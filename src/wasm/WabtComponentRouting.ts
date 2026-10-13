import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { AnalysisUnsupportedTargetError } from "../domain/analysisErrorCore.js";
import {
  isWasmComponent,
  readWasmPreamble,
} from "../domain/wasm/wasmPreamble.js";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { wabtFailure } from "./WabtFailures.js";

/** WABT decodes core modules only; components route to their own decoder. */
export const wasmComponentSelected = (
  path: string,
): AnalysisUnsupportedTargetError =>
  new AnalysisUnsupportedTargetError(
    "inspect_wasm_artifact",
    path,
    "WebAssembly component (layer 1), not a core module; WABT decodes core modules only",
    {
      remediationAction:
        "Decode WebAssembly components with inspect_wasm_component.",
    },
  );

const probeHeader = async (handle: OwnedFileHandle): Promise<boolean> => {
  try {
    const header = Buffer.alloc(8);
    const { bytesRead } = await handle.handle.read(header, 0, header.length, 0);
    return isWasmComponent(readWasmPreamble(header.subarray(0, bytesRead)));
  } catch (cause: unknown) {
    // Unreadable content is left to the authoritative stable read.
    void cause;
    return false;
  }
};

/**
 * Reject a component before any WABT configuration or command. An unreadable
 * path is left to the stable read, which reports it after tool checks. The
 * probe handle is owned by `scope`, so a failed release stays retryable.
 */
export const rejectWasmComponent = async (
  path: string,
  scope: ArtifactResourceScope,
): Promise<void> => {
  let handle: OwnedFileHandle;
  try {
    handle = new OwnedFileHandle(
      await open(
        path,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      ),
    );
  } catch (cause: unknown) {
    // The authoritative stable read classifies inaccessible selections.
    void cause;
    return;
  }
  const component = await probeHeader(handle);
  const cleanup = await scope.release({
    kind: "file-handle",
    resource: path,
    handle,
  });
  if (cleanup.kind === "failed")
    throw wabtFailure(
      ArtifactReaderFailure.withCleanup(
        cleanup.cause,
        ArtifactReaderFailure.cleanupObservation(cleanup.cause, path),
      ),
      "artifact",
      path,
    );
  if (component) throw wasmComponentSelected(path);
};
