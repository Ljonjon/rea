import { MIMEType } from "node:util";
import { createIdaDiagnosticRedactor } from "./IdaDiagnosticRedactor.js";
import { IdaDiagnosticResourceError } from "./IdaDiagnosticWriter.js";
import { ChildProcess } from "node:child_process";
import { Socket } from "node:net";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import {
  Client,
  ProtocolError,
  SdkHttpError,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import {
  DEFAULT_INHERITED_ENV_VARS,
  StdioClientTransport,
} from "@modelcontextprotocol/client/stdio";
import { z } from "zod";
import type { IdaConfiguration } from "./IdaConfiguration.js";
import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";

/** Injectable MCP boundary used by the provider and transport conformance tests. */
export interface IdaMcpConnection {
  connect(): Promise<readonly string[]>;
  call(
    name: string,
    args: Readonly<Record<string, JsonValue>>,
  ): Promise<JsonValue>;
  readResource?(uri: string): Promise<JsonValue>;
  serverInfo(): JsonValue;
  close(): Promise<void>;
  /**
   * Keep a connection retained after failed cleanup from holding the host
   * process open. A long-lived MCP server can still retry through it; a
   * one-shot CLI exits, and the upstream proxy observes end of input.
   */
  detach(): void;
}

const toolResultSchema = z.object({
  isError: z.boolean().optional(),
  structuredContent: z.record(z.string(), z.unknown()).optional(),
  content: z.array(
    z.object({ type: z.string(), text: z.string().optional() }).passthrough(),
  ),
  _meta: z
    .object({
      ida_mcp: z
        .object({
          output_truncated: z.boolean().optional(),
          download_hint: z.string().optional(),
        })
        .passthrough()
        .optional(),
    })
    .passthrough()
    .optional(),
});

const parseIdaJsonText = (text: string): JsonValue => {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new AnalysisProtocolError("IDA MCP returned malformed JSON text.");
  }
  return jsonValueSchema.parse(value);
};

/** Decode Python FastMCP's scalar wrapper without dropping structured dictionaries. */
export const decodeIdaToolResult = (
  input: unknown,
  protocol?: "native",
  redactDiagnostic: (message: string) => string = (message) => message,
): JsonValue => {
  const result = toolResultSchema.parse(input);
  const blocks = result.content.flatMap((block) =>
    block.type === "text" && block.text !== undefined ? [block.text] : [],
  );
  if (result.isError === true) {
    const reason = redactDiagnostic(blocks.join("\n"));
    throw new AnalysisProtocolError(`IDA MCP tool failed: ${reason}`, {
      diagnostics: { reason },
    });
  }
  if (result._meta?.ida_mcp?.output_truncated === true)
    throw new AnalysisProtocolError(
      redactDiagnostic(
        `IDA MCP truncated its output; the preview cannot establish a complete observation. ${result._meta.ida_mcp.download_hint ?? "Use the upstream output download workflow to retrieve the full result."}`,
      ),
    );
  // Native MCP retains the complete JSON text while structuredContent may
  // contain a shortened preview. Parse that producer-owned representation once.
  if (protocol === "native") {
    if (blocks.length !== 1)
      throw new AnalysisProtocolError(
        "Native IDA MCP omitted its complete JSON text result.",
      );
    return parseIdaJsonText(blocks[0] ?? "");
  }
  if (result.structuredContent !== undefined) {
    const value = result.structuredContent;
    return jsonValueSchema.parse(
      Object.keys(value).length === 1 && "result" in value
        ? value.result
        : value,
    );
  }
  if (blocks.length !== 1)
    throw new AnalysisProtocolError(
      "IDA MCP omitted a single structured or text result; unsupported content cannot establish an empty observation.",
    );
  const values = blocks.map((text): JsonValue => {
    try {
      return jsonValueSchema.parse(JSON.parse(text));
    } catch {
      return text;
    }
  });
  return values[0] ?? null;
};

// Retain only producer-sanitized JSON diagnostics, never a native parser cause.
class IdaHttpJsonError extends Error {
  constructor(readonly text: string) {
    super("IDA MCP returned malformed HTTP JSON.");
  }
}

type IdaDiagnosticRedactor = ReturnType<typeof createIdaDiagnosticRedactor>;

const diagnosticMediaType = (source: string): MIMEType | undefined => {
  const essence =
    /^[!#$%&'*+.^_`|~\dA-Za-z-]+\/[!#$%&'*+.^_`|~\dA-Za-z-]+/u.exec(source);
  if (essence === null) return undefined;
  const parameter =
    /[ \t]*;[ \t]*([!#$%&'*+.^_`|~\dA-Za-z-]+)=([!#$%&'*+.^_`|~\dA-Za-z-]+|"(?:[\t !#-\[\]-~]|\\[\t -~])*")/uy;
  const names = new Set<string>();
  let cursor = essence[0].length;
  while (!/^[ \t]*$/u.test(source.slice(cursor))) {
    parameter.lastIndex = cursor;
    const match = parameter.exec(source);
    if (match === null) return undefined;
    const name = match[1]!.toLowerCase();
    if (names.has(name)) return undefined;
    names.add(name);
    cursor = parameter.lastIndex;
  }
  try {
    return new MIMEType(source);
  } catch {
    return undefined;
  }
};

const httpErrorBody = (
  response: Response,
  text: string,
  redactor: IdaDiagnosticRedactor,
): string => {
  const omitted =
    "IDA MCP response body omitted: unsupported or unknown format or character encoding.";
  const contentType = response.headers.get("content-type");
  if (contentType === null) return omitted;
  const mediaType = diagnosticMediaType(contentType);
  if (mediaType === undefined) return omitted;
  const charset = mediaType.params.get("charset")?.toLowerCase();
  if (
    charset !== undefined &&
    !["utf-8", "utf8", "us-ascii", "ascii"].includes(charset)
  )
    return omitted;
  if (mediaType.subtype === "json" || mediaType.subtype.endsWith("+json"))
    return redactor.json(text);
  if (mediaType.essence === "text/plain") return redactor.text(text);
  return omitted;
};

const diagnosticFetch =
  (redactor: IdaDiagnosticRedactor): typeof fetch =>
  async (input, init) => {
    const response = await fetch(input, init);
    const readText = response.text.bind(response);
    let safeBody: string | undefined;
    if (!response.ok) {
      // Normalize before the SDK can swallow a body-consumer failure or drop
      // its format metadata. Both consumers use this one owned diagnostic.
      safeBody = httpErrorBody(response, await readText(), redactor);
      const body = safeBody;
      Object.defineProperty(response, "text", {
        value: async (): Promise<string> => body,
      });
    }
    // Successful JSON remains lazy, and SSE keeps its original body stream.
    Object.defineProperty(response, "json", {
      value: async (): Promise<unknown> => {
        const text = safeBody ?? (await readText());
        try {
          const value: unknown = JSON.parse(text);
          return value;
        } catch {
          // Parsing failure owns diagnostics even when the HTTP status succeeded.
          throw new IdaHttpJsonError(
            safeBody ?? httpErrorBody(response, text, redactor),
          );
        }
      },
    });
    return response;
  };

const retainedTransportCause = (cause: unknown, message: string): Error => {
  // Do not clone arbitrary upstream fields, stacks, data or nested causes.
  if (cause instanceof SdkHttpError)
    return new SdkHttpError(cause.code, message, {
      status: cause.data.status,
      statusText: "",
    });
  if (cause instanceof ProtocolError)
    return new ProtocolError(cause.code, message);
  return new Error(message);
};
/** Create a standard SDK connection to an existing upstream registration. */
export const createIdaMcpConnection = (
  config: IdaConfiguration,
  environment: Readonly<NodeJS.ProcessEnv>,
): IdaMcpConnection => {
  const client = new Client({ name: "rea-ida-provider", version: "1" });
  const redactor = createIdaDiagnosticRedactor(config);
  let stderr = Buffer.alloc(0);
  let stderrBytes = 0;
  const transportFailure = (cause: unknown): never => {
    if (cause instanceof IdaDiagnosticResourceError) throw cause;
    let failure: Error;
    if (cause instanceof IdaHttpJsonError)
      failure = new Error(`${cause.message} Response body: ${cause.text}`, {
        cause,
      });
    else {
      const message =
        cause instanceof Error
          ? cause.message
          : "Unknown IDA MCP transport failure";
      const body = cause instanceof SdkHttpError ? cause.data.text : undefined;
      // The fetch boundary already sanitized this body using its Content-Type.
      // Never rescan replacement markers inside that owned body.
      const safeMessage =
        typeof body === "string" && body.length > 0 && message.includes(body)
          ? message.split(body).map(redactor.text).join(body)
          : redactor.text(message);
      failure = new Error(safeMessage, {
        cause: retainedTransportCause(cause, safeMessage),
      });
    }
    if (stderrBytes === 0) throw failure;
    let start = 0;
    if (stderrBytes > stderr.length)
      while (start < stderr.length && (stderr[start]! & 0xc0) === 0x80) start++;
    throw new ProviderAdapterError("ida", "transport", {
      cause: failure,
      diagnostics: { reason: failure.message },
      capturedOutput: {
        stdout: "",
        stderr: redactor.text(stderr.subarray(start).toString("utf8")),
        truncated: stderrBytes > stderr.length - start,
        stdout_bytes: 0,
        stderr_bytes: stderrBytes,
      },
    });
  };
  const transport =
    "command" in config
      ? new StdioClientTransport({
          command: config.command,
          args: config.args,
          env: {
            // The SDK always merges ambient defaults. Its string-only environment
            // API requires empty values to suppress omitted caller-selected keys.
            ...Object.fromEntries(
              DEFAULT_INHERITED_ENV_VARS.map((key) => [key, ""]),
            ),
            ...Object.fromEntries(
              Object.entries(snapshotEnvironment(environment)).filter(
                (entry): entry is [string, string] => entry[1] !== undefined,
              ),
            ),
            IDA_MCP_MAX_WORKERS: "1",
            ...snapshotEnvironment(config.env),
          },
          stderr: "pipe",
        })
      : new StreamableHTTPClientTransport(new URL(config.url), {
          requestInit: { headers: config.headers, redirect: "error" },
          fetch: diagnosticFetch(redactor),
        });
  // Keep a bounded diagnostic tail for genuine failures; never persist ambient variables.
  if (transport instanceof StdioClientTransport)
    transport.stderr?.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.length;
      const combined = Buffer.concat([stderr, chunk]);
      stderr = Buffer.from(
        combined.subarray(Math.max(0, combined.length - 16_384)),
      );
    });
  return {
    async connect() {
      await client
        .connect(transport, { timeout: config.timeoutMs })
        .catch(transportFailure);
      const catalog = await client
        .listTools(undefined, {
          timeout: config.timeoutMs,
        })
        .catch(transportFailure);
      return catalog.tools.map(({ name }) => name);
    },
    async call(name, args) {
      return decodeIdaToolResult(
        await client
          .callTool({ name, arguments: args }, { timeout: config.timeoutMs })
          .catch(transportFailure),
        config.protocol,
        redactor.text,
      );
    },
    async readResource(uri) {
      const response = await client
        .readResource({ uri }, { timeout: config.timeoutMs })
        .catch(transportFailure);
      const resource = z
        .object({
          contents: z
            .array(
              z.object({
                uri: z.literal(uri),
                mimeType: z.literal("application/json"),
                text: z.string(),
              }),
            )
            .length(1),
        })
        .parse(response);
      return parseIdaJsonText(resource.contents[0]?.text ?? "");
    },
    serverInfo: () => jsonValueSchema.parse(client.getServerVersion() ?? null),
    close: () => client.close().catch(transportFailure),
    detach() {
      if (!(transport instanceof StdioClientTransport)) return;
      // The SDK exposes only the child's pid, not the handles it holds.
      const child: unknown = Reflect.get(transport, "_process");
      if (!(child instanceof ChildProcess)) return;
      child.unref();
      for (const stream of [child.stdin, child.stdout, child.stderr])
        if (stream instanceof Socket) stream.unref();
    },
  };
};
