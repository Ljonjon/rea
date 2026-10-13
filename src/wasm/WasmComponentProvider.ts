import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { WasmComponentPort } from "../application/wasm/WasmComponentPort.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  WASM_COMPONENT_GRAMMAR,
  wasmComponentSchema,
  type InspectWasmComponentInput,
  type WasmComponent,
} from "../domain/wasm/wasmComponent.js";
import { decodeWasmComponent } from "./WasmComponentDecoder.js";
import {
  MAX_INLINE_RESULT_BYTES,
  WasmComponentFormatFailure,
  WasmComponentLimitExceeded,
} from "./WasmComponentReader.js";

/** Bundled decoder identity; the admitted grammar is pinned separately. */
export const WASM_COMPONENT_PROVIDER_IDENTITY = {
  id: "wasm-component-binary",
  name: "REA WebAssembly component decoder",
  version: "1",
} as const;
const OPERATION = "inspect_wasm_component";
const INPUT_BYTES = 8 * 1024 * 1024;

const isAbort = (cause: unknown, signal?: AbortSignal): boolean =>
  signal?.aborted === true ||
  (cause instanceof Error && cause.name === "AbortError");

/** Decoder failures: bounded output and unadmitted or malformed encodings. */
const decoderFailure = (
  cause: WasmComponentLimitExceeded | WasmComponentFormatFailure,
  path: string,
): AnalysisError => {
  if (cause instanceof WasmComponentLimitExceeded)
    return cause.limit === "decoded-items"
      ? new AnalysisResourceConstraintError(
          OPERATION,
          "memory",
          `${cause.message} for ${path}, so the complete result would exceed the inline output budget; no partial success is returned.`,
          { maximum_decoded_entries: cause.maximum },
          { cause },
        )
      : new AnalysisResourceConstraintError(
          OPERATION,
          "transport",
          `${cause.message} for ${path}; no partial success is returned.`,
          { maximum_output_bytes: cause.maximum },
          { cause },
        );
  return cause.kind === "unsupported"
    ? new AnalysisUnsupportedTargetError(OPERATION, path, cause.message, {
        cause,
        ...(cause.message.includes("inspect_wasm_artifact")
          ? {
              remediationAction:
                "Inspect core WebAssembly modules with inspect_wasm_artifact.",
            }
          : {}),
      })
    : new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_format",
          message: `Selected artifact ${path}: ${cause.message}`,
        },
      ]);
};

const failureForPrimary = (
  cause: unknown,
  path: string,
  signal?: AbortSignal,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, cause.message, {
      cause,
    });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
    return new AnalysisCancelledError(OPERATION, { cause });
  if (isAbort(cause, signal))
    return new AnalysisCancelledError(OPERATION, { cause });
  if (
    cause instanceof WasmComponentLimitExceeded ||
    cause instanceof WasmComponentFormatFailure
  )
    return decoderFailure(cause, path);
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        OPERATION,
        "file-size",
        cause.message,
        { maximum_input_bytes: INPUT_BYTES },
        { cause },
      );
    if (cause.reason === "path")
      return new AnalysisInputError(OPERATION, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
        cause,
      });
    if (
      ["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(
        String(cause.code),
      )
    )
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${String(cause.code)}): ${path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(
    WASM_COMPONENT_PROVIDER_IDENTITY.id,
    OPERATION,
    {
      cause,
      diagnostics: {
        path,
        reason: cause instanceof Error ? cause.message : String(cause),
      },
    },
  );
};

/** Primary failure, with any retained read cleanup failure attached. */
const failureFor = (
  cause: unknown,
  path: string,
  signal?: AbortSignal,
): AnalysisError => {
  const primary = failureForPrimary(cause, path, signal);
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    WASM_COMPONENT_PROVIDER_IDENTITY.id,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { operation: OPERATION, cause },
  );
  return analysisErrorWithCleanupFailure(primary, cleanup, OPERATION);
};

const LIMITATIONS = [
  "Decoding is structural against the pinned component-model Binary.md grammar. Type correctness, name uniqueness, index bounds and canonical ABI rules are not validated, so a decoded component can still be invalid.",
  "Embedded core modules are identified by byte range and SHA-256; only their import and export sections are read. No component or module is instantiated or executed.",
  "Lift and lower relationships follow index-space origins inside one component. Outer aliases, values and instantiated nested components are not traced.",
  "Value-section payloads are retained by type and byte range only.",
];

/** Read one selected component in process, without subprocesses, temporary files or execution. */
export class WasmComponentProvider implements WasmComponentPort {
  readonly identity = WASM_COMPONENT_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();

  /** Retry release of read handles whose cleanup failed. */
  close(): Promise<void> {
    return this.#resources.close();
  }

  async inspect(
    input: InspectWasmComponentInput,
    options?: ExecutionOptions,
  ): Promise<Result<WasmComponent, AnalysisError>> {
    try {
      const snapshot = await this.#resources.run(() =>
        readStableArtifact(
          input.path,
          INPUT_BYTES,
          options?.signal,
          undefined,
          this.#resources,
        ),
      );
      options?.signal?.throwIfAborted();
      const decoded = await decodeWasmComponent(
        snapshot.bytes,
        options?.signal,
      );
      const invalidNames = decoded.components.some(
        (component) => component.names?.status === "invalid",
      );
      const report = {
        artifact: {
          path: input.path,
          sha256: snapshot.sha256,
          bytes: snapshot.bytes.length,
        },
        decoder: {
          id: WASM_COMPONENT_PROVIDER_IDENTITY.id,
          version: WASM_COMPONENT_PROVIDER_IDENTITY.version,
          grammar: WASM_COMPONENT_GRAMMAR.source,
          admitted_version: WASM_COMPONENT_GRAMMAR.version,
          admitted_layer: WASM_COMPONENT_GRAMMAR.layer,
        },
        validation: "not_performed",
        components: decoded.components,
        type_scopes: decoded.typeScopes,
        gated_features: decoded.features,
        coverage: {
          status: decoded.notDecoded.length === 0 ? "complete" : "partial",
          not_decoded: decoded.notDecoded,
        },
        limitations: [
          ...LIMITATIONS,
          ...(decoded.notDecoded.length === 0
            ? []
            : [
                "Some content was not decoded (see coverage.not_decoded). After a section that was not decoded, indices that later definitions add to its sorts are null because their positions are unknown; earlier indices stay known.",
              ]),
          ...(invalidNames
            ? [
                "A component-name section could not be decoded completely; names decoded before the failure are retained.",
              ]
            : []),
        ],
      };
      if (
        Buffer.byteLength(JSON.stringify(report), "utf8") >
        MAX_INLINE_RESULT_BYTES
      )
        throw new WasmComponentLimitExceeded(
          "output-bytes",
          MAX_INLINE_RESULT_BYTES,
        );
      const parsed = wasmComponentSchema.safeParse(report);
      if (!parsed.success)
        throw new AnalysisOutputError(
          OPERATION,
          "Component decoder produced invalid ranges or report values.",
          { cause: parsed.error },
        );
      options?.signal?.throwIfAborted();
      return ok(parsed.data);
    } catch (cause: unknown) {
      return err(failureFor(cause, input.path, options?.signal));
    }
  }
}
