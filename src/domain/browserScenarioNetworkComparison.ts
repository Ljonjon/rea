import { z } from "zod";
import type { BrowserScenarioCapture } from "./browserScenarioCapture.js";
import { digestCanonicalValue } from "./canonicalDigest.js";

/** Numeric links are temporary local indices, never durable transaction identity. */
export const scenarioNetworkTransactionSchema = z.strictObject({
  events: z.array(z.unknown()),
  predecessor: z.number().int().min(-2),
  selected: z.boolean(),
});
export type ScenarioNetworkTransaction = z.infer<
  typeof scenarioNetworkTransactionSchema
>;

/** Project each transaction once, retaining ancestry as references rather than nested copies. */
export const scenarioNetworkTransactions = (
  capture: BrowserScenarioCapture,
  stepIndex: number,
): ScenarioNetworkTransaction[] => {
  const sourceSteps = new Map(
    capture.events.items.map((event) => [event.sequence, event.step_index]),
  );
  const requests = new Map(
    capture.events.items.flatMap((event) =>
      event.kind === "request" ? [[event.transaction_id, event]] : [],
    ),
  );
  const grouped = new Map<
    string,
    { events: unknown[]; predecessor: string | null; selected: boolean }
  >();
  for (const { sequence: _sequence, step_index: step, ...event } of capture
    .events.items) {
    if (!("transaction_id" in event)) continue;
    const id = event.transaction_id;
    const request = requests.get(id);
    const receiptStep =
      event.kind === "network-content"
        ? sourceSteps.get(event.source_event_sequence)
        : step;
    const selected = (request?.step_index ?? receiptStep) === stepIndex;
    let evidence: unknown;
    let predecessor: string | null;
    if (event.kind === "network-content") {
      const {
        transaction_id: _id,
        source_event_sequence: _source,
        ...content
      } = event;
      evidence = content;
      predecessor = request?.redirected_from_transaction_id ?? null;
    } else {
      const {
        transaction_id: _id,
        redirected_from_transaction_id: parent,
        ...network
      } = event;
      evidence = network;
      predecessor =
        request === undefined ? parent : request.redirected_from_transaction_id;
    }
    const previous = grouped.get(id);
    if (previous === undefined)
      grouped.set(id, { events: [evidence], predecessor, selected });
    else previous.events.push(evidence);
  }
  const indices = new Map([...grouped.keys()].map((id, index) => [id, index]));
  return [...grouped.values()].map((node) => ({
    events: node.events,
    predecessor:
      node.predecessor === null ? -1 : (indices.get(node.predecessor) ?? -2),
    selected: node.selected,
  }));
};

/** Missing or cyclic ancestry cannot support an unchanged claim. */
export const scenarioNetworkCoverageReason = (
  capture: BrowserScenarioCapture,
): string | undefined => {
  const nodes = scenarioNetworkTransactions(capture, -1);
  const finished = new Set<number>();
  for (let start = 0; start < nodes.length; start += 1) {
    const path = new Set<number>();
    let index = start;
    while (index >= 0 && !finished.has(index)) {
      if (path.has(index))
        return "Redirect ancestry contains a cycle; network transaction identity remains unknown.";
      path.add(index);
      const node = nodes[index];
      if (node === undefined)
        return "Redirect predecessor evidence is missing; network transaction identity remains unknown.";
      index = node.predecessor;
    }
    if (index === -2)
      return "Redirect predecessor evidence is missing; network transaction identity remains unknown.";
    for (const item of path) finished.add(item);
  }
  return undefined;
};

/** Hash normalized own evidence and its complete parent fingerprint in linear graph space. */
export const fingerprintScenarioNetworkTransactions = (
  nodes: readonly ScenarioNetworkTransaction[],
): string[] => {
  const own = nodes.map((node) =>
    node.events
      .map((event) => digestCanonicalValue(event, "Browser scenario"))
      .sort(),
  );
  const fingerprints = new Map<number, string>();
  for (let start = 0; start < nodes.length; start += 1) {
    const path: number[] = [];
    const positions = new Map<number, number>();
    let index = start;
    while (
      index >= 0 &&
      nodes[index] !== undefined &&
      !fingerprints.has(index)
    ) {
      const position = positions.get(index);
      if (position !== undefined) {
        // These captures are incomparable; retain an explicit cycle observation.
        for (const member of path.slice(position))
          fingerprints.set(
            member,
            digestCanonicalValue(
              { events: own[member], redirected_from: { state: "cycle" } },
              "Browser scenario",
            ),
          );
        break;
      }
      positions.set(index, path.length);
      path.push(index);
      index = nodes[index]?.predecessor ?? -2;
    }
    for (const member of path.reverse()) {
      if (fingerprints.has(member)) continue;
      const predecessor = nodes[member]?.predecessor ?? -2;
      const parent =
        predecessor === -1
          ? null
          : (fingerprints.get(predecessor) ?? { state: "missing" });
      fingerprints.set(
        member,
        digestCanonicalValue(
          { events: own[member], redirected_from: parent },
          "Browser scenario",
        ),
      );
    }
  }
  return nodes
    .flatMap((node, index) => {
      if (!node.selected) return [];
      const fingerprint = fingerprints.get(index);
      if (fingerprint === undefined)
        throw new Error("Network comparison node has no fingerprint");
      return [fingerprint];
    })
    .sort();
};
