import { expect, it, onTestFinished, vi } from "vitest";
import { createHash } from "node:crypto";
import { selectScriptCapture } from "../../../src/browser/assets/ScriptCaptureAdapters.js";
import { reconcileJavaScriptRuntimeEvidence } from "../../../src/application/javascript/JavaScriptRuntimeReconciliationService.js";
import { javascriptRuntimeReconciliationResultSchema } from "../../../src/domain/javascript/javascriptRuntimeReconciliationSchemas.js";
import {
  applicationFixture,
  analyzeFixture,
} from "../../fixtures/javascriptRuntimeReconciliation.js";
import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { createBrowserEvidence } from "../../../src/application/BrowserEvidence.js";
import { parseRuntimeCaptures } from "../../../src/domain/javascript/javascriptRuntimeReconciliationCaptureParsing.js";
import { projectRuntimeCaptures } from "../../../src/domain/javascript/javascriptRuntimeReconciliationRuntime.js";
import { parseEvidence } from "../../../src/domain/evidence.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { CdpBrowserProvider } from "../../../src/browser/CdpBrowserProvider.js";
import { inspectWebPageInputSchema } from "../../../src/domain/browserObservation.js";
import { analyzeWebBundleInputSchema } from "../../../src/domain/webBundleAnalysis.js";
import {
  startFakeCdpBrowser,
  type FakeOptions,
} from "../../fixtures/fakeCdpBrowser.js";

const source = 'postMessage("worker 🧪");';

it("retains selected worker metadata with explicit coverage limits on direct page transports", async () => {
  const { provider, input, browser } = await fixture({
    pageScopedVersionWebSocket: true,
    omitTargetWebSocket: true,
  });
  const result = await provider.inspectPage({
    ...input,
    worker_target_ids: ["shared"],
  });
  if (!result.ok) throw result.error;
  const worker = result.value.workers.find(
    ({ target_id }) => target_id === "shared",
  )!.observation!;
  expect(worker.selected_explicitly).toBe(true);
  expect(worker.scripts).toEqual([]);
  expect(worker.completeness.unavailable_sections).toEqual(
    expect.arrayContaining(["scripts", "network_requests"]),
  );
  expect(worker.limitations.join(" ")).toContain("browser-level CDP WebSocket");
  expect(
    browser.commands.some(
      ({ method, sessionId }) =>
        method === "Target.attachToTarget" ||
        method === "Target.detachFromTarget" ||
        method === "Target.setAutoAttach" ||
        sessionId !== undefined,
    ),
  ).toBe(false);
});

it.each(["explicit", "auto"] as const)(
  "rejects empty worker session IDs from %s attachments",
  async (kind) => {
    const { provider, input, browser } = await fixture({
      commandResult: (command) =>
        kind === "explicit" &&
        command.method === "Target.attachToTarget" &&
        command.params.targetId === "shared"
          ? { sessionId: "" }
          : undefined,
      commandEvents: (command, origin) =>
        kind === "auto" &&
        command.method === "Target.setAutoAttach" &&
        command.params.autoAttach === true
          ? [
              {
                method: "Target.attachedToTarget",
                sessionId: "session-1",
                params: {
                  sessionId: "",
                  targetInfo: {
                    targetId: "own",
                    type: "worker",
                    url: origin + "/same.js",
                    attached: true,
                  },
                },
              },
            ]
          : undefined,
    });
    const result = await provider.inspectPage({
      ...input,
      worker_target_ids: kind === "explicit" ? ["shared"] : [],
    });
    expect(result).toMatchObject({
      ok: false,
      error: { reason: "protocol_error" },
    });
    expect(browser.commands.some(({ sessionId }) => sessionId === "")).toBe(
      false,
    );
    await vi.waitFor(() => expect(browser.activeConnectionCount()).toBe(0));
  },
);

it.each([
  ["https://foreign.example/a.js", "disallowed_origin"],
  ["file:///worker.js", "unsupported_url"],
  ["", "unattributed_origin"],
  [undefined, "unattributed_origin"],
] as const)(
  "retains the exclusion reason for worker URL %s",
  async (url, reason) => {
    const { provider, input } = await fixture({
      commandResult: (command) =>
        command.method === "Target.getTargets"
          ? {
              targetInfos: [
                { targetId: "excluded", type: "worker", attached: false, url },
              ],
            }
          : undefined,
    });
    const result = await provider.inspectPage(input);
    if (!result.ok) throw result.error;
    expect(result.value.completeness.excluded).toContainEqual({
      section: "workers",
      reason,
      count: 1,
    });
  },
);

it("preserves worker coverage and warnings through CLI export even without worker scripts", async () => {
  const { provider, input } = await fixture({
    commandError: (command) =>
      command.method === "Debugger.enable" && command.sessionId === "worker-own"
        ? { code: -32601, message: "Debugger is unavailable" }
        : undefined,
  });
  const result = await provider.inspectPage(input);
  if (!result.ok) throw result.error;
  const own = result.value.workers.find(
    ({ target_id }) => target_id === "own",
  )!;
  const observation = own.observation!;
  expect(observation.scripts).toEqual([]);
  expect(observation.network_requests).toEqual([]);
  expect(observation.completeness.excluded).toContainEqual({
    section: "json_body_shapes",
    reason: "not_approved",
    count: null,
  });
  expect(observation.completeness.unavailable_sections).toContain("scripts");
  result.value.workers.push({
    ...own,
    target_id: "legacy",
    observation: undefined,
  });
  const root = await createTestTempDirectory("rea-worker-export-coverage-");
  const capture = join(root, "capture.json");
  await writeFile(capture, JSON.stringify(result.value));
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      "scripts/rea.mjs",
      "export-web-scripts",
      capture,
      join(root, "export"),
      "--json",
    ],
    { maxBuffer: 8 * 1024 * 1024 },
  );
  const exported = parseEvidence(JSON.parse(stdout)).normalized_result;
  const expected = [
    {
      target_id: "own",
      completeness: observation.completeness,
      limitations: observation.limitations,
    },
    { target_id: "legacy", completeness: null, limitations: [] },
  ];
  expect(exported).toMatchObject({
    worker_coverage: expect.arrayContaining(expected),
  });
  const manifest = JSON.parse(
    await readFile(join(root, "export", "manifest.json"), "utf8"),
  );
  expect(manifest).toMatchObject({
    worker_coverage: expect.arrayContaining(expected),
  });
}, 30000);

it.each([false, true])(
  "retains worker JSON-shape selection with no requests: %s",
  async (selected) => {
    const { provider, input } = await fixture();
    const result = await provider.inspectPage({
      ...input,
      include_json_body_shapes: selected,
    });
    if (!result.ok) throw result.error;
    const own = result.value.workers.find(
      ({ target_id }) => target_id === "own",
    )!.observation!;
    expect(own.network_requests).toEqual([]);
    expect(
      own.completeness.excluded.some(
        ({ section, reason }) =>
          section === "json_body_shapes" && reason === "not_approved",
      ),
    ).toBe(!selected);
  },
);

it("does not enter worker observation for page-only bundle analysis", async () => {
  const { provider, input, browser } = await fixture({
    commandError: (command) =>
      command.method === "ServiceWorker.enable" ||
      command.method === "Target.setAutoAttach"
        ? { code: -32000, message: "Workers are unavailable" }
        : undefined,
  });
  const result = await provider.analyzeBundle(
    analyzeWebBundleInputSchema.parse(input),
  );
  expect(result.ok).toBe(true);
  expect(
    browser.commands.some(
      (command) =>
        command.method.startsWith("ServiceWorker.") ||
        command.method === "Target.setAutoAttach" ||
        command.method === "Target.getTargets",
    ),
  ).toBe(false);
});

it.each(["", "https://foreign.example/changed.js"])(
  "rejects a previously retained script whose replacement leaves scope: %s",
  async (url) => {
    const { provider, input } = await fixture({
      eventsBeforeReply: ["Debugger.getScriptSource"],
      commandEvents: (command) =>
        command.method === "Debugger.getScriptSource" &&
        command.sessionId === "worker-own"
          ? [
              {
                method: "Debugger.scriptParsed",
                sessionId: "worker-own",
                params: { scriptId: "1", url, hash: "replacement" },
              },
            ]
          : undefined,
    });
    expect(await provider.inspectPage(input)).toMatchObject({
      ok: false,
      error: { reason: "target_changed" },
    });
  },
);

it("settles unfetched worker JSON responses as partial while retaining the request shape", async () => {
  const { provider, input } = await fixture({
    commandEvents: (command, origin) =>
      command.method === "Network.enable" && command.sessionId === "worker-own"
        ? [
            {
              method: "Network.requestWillBeSent",
              sessionId: "worker-own",
              params: {
                requestId: "post",
                type: "Fetch",
                request: {
                  url: origin + "/post",
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  postData: '{"selected":true}',
                },
                initiator: { type: "script" },
              },
            },
            {
              method: "Network.responseReceived",
              sessionId: "worker-own",
              params: {
                requestId: "post",
                response: {
                  url: origin + "/post",
                  status: 200,
                  mimeType: "application/json",
                  headers: {},
                },
              },
            },
            {
              method: "Network.loadingFinished",
              sessionId: "worker-own",
              params: { requestId: "post", encodedDataLength: 17 },
            },
          ]
        : undefined,
  });
  const result = await provider.inspectPage({
    ...input,
    include_json_body_shapes: true,
  });
  if (!result.ok) throw result.error;
  const observed = result.value.workers.find(
    (worker) => worker.target_id === "own",
  )!.observation!;
  expect(observed.network_requests[0]?.body_shapes).toMatchObject({
    status: "partial",
    response: null,
  });
  expect(observed.network_requests[0]?.body_shapes.request).not.toBeNull();
  expect(observed.completeness.unavailable_sections).toContain(
    "json_body_shapes",
  );
});

it("rejects a script identity change while its source read is pending", async () => {
  const { provider, input, browser } = await fixture({
    eventsBeforeReply: ["Debugger.getScriptSource"],
    commandEvents: (c, origin) =>
      c.method === "Debugger.getScriptSource" && c.sessionId === "worker-own"
        ? [
            {
              method: "Debugger.scriptParsed",
              sessionId: "worker-own",
              params: {
                scriptId: "1",
                url: origin + "/replacement.js",
                hash: "replacement",
                executionContextId: 1,
              },
            },
          ]
        : undefined,
  });
  expect(
    await provider.inspectPage({ ...input, observation_ms: 30_000 }),
  ).toMatchObject({ ok: false, error: { reason: "target_changed" } });
  await vi.waitFor(() => expect(browser.activeConnectionCount()).toBe(0));
});
async function fixture(extra: FakeOptions = {}) {
  const browser = await startFakeCdpBrowser({
    ...extra,
    commandResult(command, origin, reads) {
      const custom = extra.commandResult?.(command, origin, reads);
      if (custom !== undefined) return custom;
      if (
        command.method === "ServiceWorker.enable" ||
        command.method === "ServiceWorker.disable" ||
        command.method === "Target.setAutoAttach"
      )
        return {};
      if (command.method === "Target.getTargets")
        return {
          targetInfos: [
            {
              targetId: "own",
              type: "worker",
              url: origin + "/same.js",
              attached: false,
            },
            {
              targetId: "other",
              type: "worker",
              url: origin + "/same.js",
              attached: false,
            },
            {
              targetId: "shared",
              type: "shared_worker",
              url: origin + "/shared.js",
              attached: false,
            },
            {
              targetId: "foreign",
              type: "worker",
              url: "https://foreign.example/a.js",
              attached: false,
            },
          ],
        };
      if (
        command.method === "Target.attachToTarget" &&
        command.params.targetId === "shared"
      )
        return { sessionId: "worker-shared" };
      if (
        command.method === "Debugger.getScriptSource" &&
        command.sessionId?.startsWith("worker-")
      )
        return { scriptSource: source };
      return undefined;
    },
    commandEvents(command, origin) {
      const custom = extra.commandEvents?.(command, origin);
      if (custom !== undefined) return custom;
      if (
        command.method === "Target.setAutoAttach" &&
        command.params.autoAttach === true
      )
        return [
          {
            method: "Target.attachedToTarget",
            sessionId: "session-1",
            params: {
              sessionId: "worker-own",
              targetInfo: {
                targetId: "own",
                type: "worker",
                url: origin + "/same.js",
                attached: true,
              },
              waitingForDebugger: false,
            },
          },
        ];
      if (command.sessionId?.startsWith("worker-")) {
        if (command.method === "Runtime.enable")
          return [
            {
              method: "Runtime.executionContextCreated",
              sessionId: command.sessionId,
              params: {
                context: { id: 1, uniqueId: "worker-context", origin },
              },
            },
          ];
        if (command.method === "Debugger.enable")
          return [
            {
              method: "Debugger.scriptParsed",
              sessionId: command.sessionId,
              params: {
                scriptId: "1",
                url: origin + "/same.js",
                executionContextId: 1,
                hash: "producer",
                length: source.length,
              },
            },
          ];
        return [];
      }
      return undefined;
    },
  });
  onTestFinished(() => browser.close());
  const input = inspectWebPageInputSchema.parse({
    cdp_endpoint: browser.endpoint,
    target_id: "allowed-page",
    observation_ms: 0,
    include_script_sources: true,
  });
  return { browser, input, provider: new CdpBrowserProvider() };
}
it("uses session ancestry rather than URL equality and retains unknown ownership", async () => {
  const { provider, input } = await fixture();
  const result = await provider.inspectPage(input);
  if (!result.ok) throw result.error;
  expect(result.value.workers.map((w) => w.target_id)).toEqual([
    "other",
    "own",
    "shared",
  ]);
  expect(
    result.value.workers.find((w) => w.target_id === "other")?.observation,
  ).toMatchObject({ ownership: "unknown", scripts: [] });
  expect(
    result.value.workers.find((w) => w.target_id === "own")?.observation,
  ).toMatchObject({
    ownership: "page_related",
    page_target_id: "allowed-page",
    scripts: [
      {
        script_id: "1",
        execution_context_id: 1,
        source: { included: true, artifact: { text: source } },
      },
    ],
  });
});
it("explicitly selected shared workers remain ownership-unknown", async () => {
  const { provider, input } = await fixture();
  const result = await provider.inspectPage({
    ...input,
    worker_target_ids: ["shared"],
  });
  if (!result.ok) throw result.error;
  expect(
    result.value.workers.find((w) => w.target_id === "shared")?.observation,
  ).toMatchObject({
    ownership: "unknown",
    page_target_id: null,
    selected_explicitly: true,
    scripts: [{ source: { included: true } }],
  });
});
it.each(["foreign", "missing"])(
  "rejects an explicit target outside authorized inventory: %s",
  async (id) => {
    const { provider, input, browser } = await fixture();
    expect(
      await provider.inspectPage({ ...input, worker_target_ids: [id] }),
    ).toMatchObject({ ok: false, error: { reason: "target_not_allowed" } });
    expect(
      browser.commands.some(
        (c) => c.method === "Target.attachToTarget" && c.params.targetId === id,
      ),
    ).toBe(false);
  },
);
it.each([{}, { scriptSource: null }])(
  "rejects malformed worker source: %j",
  async (reply) => {
    const { provider, input } = await fixture({
      commandResult: (c) =>
        c.method === "Debugger.getScriptSource" && c.sessionId === "worker-own"
          ? reply
          : undefined,
    });
    expect(await provider.inspectPage(input)).toMatchObject({
      ok: false,
      error: { reason: "protocol_error" },
    });
  },
);
it("cancellation releases an in-flight source read and attached sessions", async () => {
  const { provider, input, browser } = await fixture({
    hangOnMethod: "Debugger.getScriptSource",
  });
  const controller = new AbortController();
  const pending = provider.inspectPage(input, { signal: controller.signal });
  await vi.waitFor(() =>
    expect(
      browser.commands.some(
        (c) =>
          c.method === "Debugger.getScriptSource" &&
          c.sessionId === "worker-own",
      ),
    ).toBe(true),
  );
  controller.abort();
  expect((await pending).ok).toBe(false);
  await vi.waitFor(() => expect(browser.activeConnectionCount()).toBe(0));
  expect(
    browser.commands.some(
      (c) =>
        c.method === "Target.detachFromTarget" &&
        c.params.sessionId === "worker-own",
    ),
  ).toBe(true);
  expect(
    browser.commands.some(
      (c) =>
        c.method === "Target.closeTarget" ||
        c.method === "Runtime.evaluate" ||
        c.method === "Runtime.runIfWaitingForDebugger",
    ),
  ).toBe(false);
});
it("does not request worker sources when source capture is disabled", async () => {
  const { provider, input, browser } = await fixture();
  const result = await provider.inspectPage({
    ...input,
    include_script_sources: false,
  });
  if (!result.ok) throw result.error;
  expect(
    result.value.workers.find((w) => w.target_id === "own")?.observation
      ?.scripts[0]?.source,
  ).toMatchObject({ included: false });
  expect(
    result.value.workers.find((w) => w.target_id === "own")?.observation
      ?.completeness.excluded,
  ).toContainEqual({
    section: "script_sources",
    reason: "not_approved",
    count: 1,
  });
  expect(
    browser.commands.some(
      (c) =>
        c.method === "Debugger.getScriptSource" && c.sessionId === "worker-own",
    ),
  ).toBe(false);
});

it.each([false, true, null])(
  "retains service worker client evidence before attachment (controls page: %s)",
  async (controls) => {
    const { provider, input, browser } = await fixture({
      eventsBeforeReply: ["ServiceWorker.enable", "Target.setAutoAttach"],
      commandEvents(command, origin) {
        if (command.method === "ServiceWorker.enable")
          return [
            {
              method: "ServiceWorker.workerVersionUpdated",
              sessionId: "session-1",
              params: {
                versions: [
                  {
                    targetId: "service",
                    ...(controls === null
                      ? {}
                      : {
                          controlledClients: controls
                            ? ["allowed-page"]
                            : ["another-page"],
                        }),
                    runningStatus: "running",
                    status: "activated",
                  },
                ],
              },
            },
          ];
        if (
          command.method === "Target.setAutoAttach" &&
          command.params.autoAttach === true
        )
          return [
            {
              method: "Target.attachedToTarget",
              sessionId: "session-1",
              params: {
                sessionId: "worker-service",
                targetInfo: {
                  targetId: "service",
                  type: "service_worker",
                  url: origin + "/service.js",
                  attached: true,
                },
              },
            },
          ];
        if (
          command.method === "Network.enable" &&
          command.sessionId === "worker-service"
        )
          return [
            {
              method: "ServiceWorker.workerVersionUpdated",
              sessionId: "session-1",
              params: {
                versions: [
                  {
                    targetId: "service",
                    controlledClients: [],
                    runningStatus: "running",
                    status: "activated",
                  },
                ],
              },
            },
            {
              method: "Debugger.scriptParsed",
              sessionId: "worker-service",
              params: {
                scriptId: "after-revocation",
                url: origin + "/late.js",
                executionContextId: 1,
              },
            },
          ];
        return undefined;
      },
    });
    const result = await provider.inspectPage(input);
    if (!result.ok) throw result.error;
    const observed = result.value.workers.find(
      (w) => w.target_id === "service",
    )!.observation!;
    expect(observed.ownership).toBe(
      controls ? "service_worker_client" : "unknown",
    );
    expect(observed.lifecycle[0]).toMatchObject({
      event: "version",
      controls_page: controls,
      version_status: "activated",
    });
    expect(observed.scripts).toHaveLength(controls ? 1 : 0);
    expect(
      browser.commands.some((c) => c.params.scriptId === "after-revocation"),
    ).toBe(false);
    if (controls)
      expect(observed.lifecycle.at(-1)).toMatchObject({ controls_page: false });
  },
);

it.each([undefined, "malformed", [42], []])(
  "retains ordered pre-admission transitions and distinguishes unknown clients from revocation: %j",
  async (clients) => {
    const { provider, input } = await fixture({
      eventsBeforeReply: ["ServiceWorker.enable", "Target.setAutoAttach"],
      commandEvents(command, origin) {
        if (command.method === "ServiceWorker.enable")
          return [["allowed-page"], clients].map((controlledClients) => ({
            method: "ServiceWorker.workerVersionUpdated",
            sessionId: "session-1",
            params: {
              versions: [
                { targetId: "service", controlledClients, status: "activated" },
              ],
            },
          }));
        if (
          command.method === "Target.setAutoAttach" &&
          command.params.autoAttach === true
        )
          return [
            {
              method: "Target.attachedToTarget",
              sessionId: "session-1",
              params: {
                sessionId: "worker-service",
                targetInfo: {
                  targetId: "service",
                  type: "service_worker",
                  url: origin + "/service.js",
                  attached: true,
                },
              },
            },
          ];
        if (
          command.method === "Network.enable" &&
          command.sessionId === "worker-service"
        )
          return [
            {
              method: "ServiceWorker.workerVersionUpdated",
              sessionId: "session-1",
              params: { versions: [{ targetId: "service" }] },
            },
            {
              method: "Debugger.scriptParsed",
              sessionId: "worker-service",
              params: {
                scriptId: "after-unknown",
                url: origin + "/late.js",
                executionContextId: 1,
              },
            },
          ];
        return undefined;
      },
    });
    const result = await provider.inspectPage(input);
    if (!result.ok) throw result.error;
    const observed = result.value.workers.find(
      (w) => w.target_id === "service",
    )!.observation!;
    const revoked = Array.isArray(clients) && clients.length === 0;
    expect(observed.ownership).toBe("service_worker_client");
    expect(
      observed.lifecycle.slice(0, 2).map((event) => event.controls_page),
    ).toEqual([true, revoked ? false : null]);
    expect(observed.scripts.map((script) => script.script_id)).toEqual(
      revoked ? [] : ["1", "after-unknown"],
    );
  },
);

it.each([-32_000, -32_601])(
  "retains worker identity when source retrieval becomes unavailable (%s)",
  async (code) => {
    const { provider, input } = await fixture({
      commandError: (c) =>
        c.method === "Debugger.getScriptSource" && c.sessionId === "worker-own"
          ? { code, message: "Source unavailable" }
          : undefined,
    });
    const result = await provider.inspectPage(input);
    if (!result.ok) throw result.error;
    const observed = result.value.workers.find(
      (w) => w.target_id === "own",
    )!.observation!;
    expect(observed.scripts[0]?.source.included).toBe(false);
    expect(observed.completeness.unavailable_sections).toContain(
      "script_sources",
    );
  },
);

it("rejects one session ID assigned to two workers", async () => {
  const { provider, input } = await fixture({
    commandResult: (command) =>
      command.method === "Target.attachToTarget" &&
      command.params.targetId === "shared"
        ? { sessionId: "worker-own" }
        : undefined,
  });
  const result = await provider.inspectPage({
    ...input,
    worker_target_ids: ["shared"],
  });
  expect(result).toMatchObject({
    ok: false,
    error: { reason: "protocol_error" },
  });
});

it("reconciliation retains unknown workers without asserting page containment", async () => {
  const { provider, input } = await fixture();
  const result = await provider.inspectPage(input);
  if (!result.ok) throw result.error;
  const evidence = createBrowserEvidence(
    "inspect_web_page",
    input,
    result.value,
    provider.identity(),
  );
  const projected = projectRuntimeCaptures(parseRuntimeCaptures([evidence]));
  for (const worker of projected.entities.filter(
    ({ kind }) => kind === "worker",
  )) {
    expect(
      projected.edges.some(
        ({ target_node_id }) => target_node_id === worker.node.node_id,
      ),
    ).toBe(worker.runtimeKey === "own");
    expect(worker.node.observations[0]?.properties).toMatchObject({
      ownership: worker.runtimeKey === "own" ? "page_related" : "unknown",
    });
  }
});

it("reconciles retained worker sources against static artifacts", async () => {
  const { provider, input } = await fixture();
  const captured = await provider.inspectPage(input);
  if (!captured.ok) throw captured.error;
  const evidence = createBrowserEvidence(
    "inspect_web_page",
    input,
    captured.value,
    provider.identity(),
  );
  const projection = projectRuntimeCaptures(parseRuntimeCaptures([evidence]));
  const workerScript = projection.entities.find(
    (entity) => entity.parentWorkerKey === "own",
  );
  expect(workerScript?.sourceSha256).toBe(
    createHash("sha256").update(source).digest("hex"),
  );
  const root = await applicationFixture();
  await writeFile(join(root, "worker.js"), source);
  const reconciled = reconcileJavaScriptRuntimeEvidence({
    static_layers: [
      { role: "application", analysis: await analyzeFixture(root) },
    ],
    runtime_observations: [evidence],
  });
  if (!reconciled.ok) throw reconciled.error;
  const result = javascriptRuntimeReconciliationResultSchema.parse(
    reconciled.value.normalized_result,
  );
  expect(result.reconciliations).toContainEqual(
    expect.objectContaining({
      entity_kind: "script",
      runtime_node_id: workerScript?.node.node_id,
      status: "matched",
    }),
  );
  expect(result.graph.edges).toContainEqual(
    expect.objectContaining({
      target_node_id: workerScript?.node.node_id,
      relation: "loads",
      evidence: expect.objectContaining({
        location: expect.objectContaining({
          value: expect.objectContaining({ target_key: "own" }),
        }),
      }),
    }),
  );
});

it("preserves page-script export from legacy unidentified workers", async () => {
  const { provider, input } = await fixture();
  const captured = await provider.inspectPage(input);
  if (!captured.ok) throw captured.error;
  const original = captured.value.workers[0];
  if (original === undefined) throw new Error("Expected an inventoried worker");
  const { observation: _observation, ...metadata } = original;
  const legacy = {
    ...captured.value,
    workers: [{ ...metadata, target_id: "" }],
  };
  const selected = selectScriptCapture(legacy);
  expect(selected.workerCoverage).toEqual([]);
  expect(selected.scripts).toHaveLength(legacy.scripts.items.length);
  expect(selected.limitations.join(" ")).toContain(
    "Worker identity was unavailable for 1 observations",
  );
});

it.each([undefined, null, 42])(
  "rejects missing or non-string auto-attachment sessions: %j",
  async (sessionId) => {
    const { provider, input } = await fixture({
      commandEvents: (command, origin) =>
        command.method === "Target.setAutoAttach" &&
        command.sessionId === "session-1" &&
        command.params.autoAttach === true
          ? [
              {
                method: "Target.attachedToTarget",
                sessionId: "session-1",
                params: {
                  sessionId,
                  targetInfo: {
                    targetId: "own",
                    type: "worker",
                    url: origin + "/same.js",
                    attached: true,
                  },
                },
              },
            ]
          : undefined,
    });
    const result = await provider.inspectPage(input);
    expect(result).toMatchObject({
      ok: false,
      error: { reason: "protocol_error" },
    });
  },
);

it("records and excludes empty worker script identifiers at ingestion", async () => {
  const { provider, input } = await fixture({
    commandEvents: (command, origin) =>
      command.method === "Debugger.enable" && command.sessionId === "worker-own"
        ? [
            {
              method: "Debugger.scriptParsed",
              sessionId: "worker-own",
              params: {
                scriptId: "",
                url: origin + "/same.js",
                executionContextId: 1,
              },
            },
          ]
        : undefined,
  });
  const result = await provider.inspectPage(input);
  if (!result.ok) throw result.error;
  const worker = result.value.workers.find(
    ({ target_id }) => target_id === "own",
  );
  expect(worker?.observation?.scripts).toEqual([]);
  expect(worker?.observation?.completeness.excluded).toContainEqual({
    section: "scripts",
    reason: "invalid_protocol_value",
    count: 1,
  });
});
