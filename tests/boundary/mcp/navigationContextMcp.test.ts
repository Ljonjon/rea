import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import type { CallToolResult } from "@modelcontextprotocol/server";
import { expect, it } from "vitest";

import type {
  AnalysisProvider,
  CapabilityDescriptor,
} from "../../../src/application/AnalysisProvider.js";
import { ok } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { observed } from "../../fixtures/analysisExecution.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { parseMcpToolError } from "../../fixtures/mcpToolError.js";

const identity = { id: "fixture", name: "Fixture", version: "1" };

// A provider whose volatile selection reports the supplied observations.
const selectionProvider = (
  selection: Readonly<Record<string, unknown>>,
): AnalysisProvider => {
  const capability = (
    operation: CapabilityDescriptor["operation"],
  ): CapabilityDescriptor => ({
    provider: identity,
    operation,
    available: true,
    reason: null,
    effects: {
      mutatesArtifact: false,
      launchesProcess: false,
      mayShowUi: false,
      mayAccessNetwork: false,
      mayWriteFilesystem: false,
      changesPermissions: false,
      requiresRoot: false,
    },
    limitations: [],
  });
  return {
    identity: () => identity,
    capabilities: () =>
      (
        [
          "current_document",
          "current_address",
          "resolve_containing_procedure",
        ] as const
      ).map(capability),
    createClient: () => ({
      health: () => Promise.resolve(),
      execute: (operation: string) =>
        Promise.resolve(observed(selection[operation] ?? null)),
      close: () => Promise.resolve(ok(null)),
    }),
  };
};

const navigate = async (
  selection: Readonly<Record<string, unknown>>,
): Promise<CallToolResult> => {
  const session = createTestBinarySession(selectionProvider(selection));
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "navigation-test", version: "1" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    await client.callTool({
      name: "open_binary",
      arguments: { path: process.execPath },
    });
    return (await client.callTool({
      name: "get_navigation_context",
      arguments: {},
    })) as CallToolResult;
  } finally {
    await Promise.allSettled([client.close(), server.close(), session.close()]);
  }
};

it.each([
  {
    selection: { current_document: null, current_address: "0x401000" },
    operation: "current_document",
  },
  {
    selection: { current_document: "fixture", current_address: null },
    operation: "current_address",
  },
])(
  "delivers a typed failure when $operation is not a string",
  async ({ selection, operation }) => {
    const result = await navigate(selection);
    expect(JSON.stringify(result.content)).not.toContain(
      "Output validation error",
    );
    expect(parseMcpToolError(result).error).toMatchObject({
      code: "unreadable_output",
      details: { operation },
    });
  },
  10_000,
);
