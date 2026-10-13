import type {
  BrowserScenarioCompleteness,
  BrowserScenarioCompletenessSection,
  BrowserScenarioStep,
  BrowserStepArtifacts,
} from "./browserScenarioCaptureValues.js";
import type { BrowserScenarioCapture } from "./browserScenarioCapture.js";
import { digestCanonicalValue } from "./canonicalDigest.js";
import type {
  BrowserScenarioArtifactKind,
  BrowserScenarioEvidenceState,
} from "./browserScenarioDiffValues.js";

/** Capture-state input consumed by browser scenario artifact comparison. */
export type CaptureState<Value> =
  | { readonly state: "captured"; readonly value: Value }
  | { readonly state: "not_requested" }
  | { readonly state: "missing"; readonly reason: string }
  | {
      readonly state: "truncated";
      readonly observed: number;
      readonly retained: number;
      readonly reason: string;
    };

const includesCompletenessSection = (
  completeness: BrowserScenarioCompleteness,
  collection: "missing_sections" | "truncated_sections",
  section: BrowserScenarioCompletenessSection,
): boolean => {
  const sections: readonly BrowserScenarioCompletenessSection[] =
    completeness[collection];
  return sections.includes(section);
};

/** Project one captured artifact through its step-level completeness ledger. */
export const artifactEvidenceState = <Value>(
  artifact: BrowserScenarioArtifactKind,
  state: CaptureState<Value>,
  step: BrowserScenarioStep,
): BrowserScenarioEvidenceState => {
  if (state.state !== "captured") return state.state;
  const section = artifact === "action_state" ? "action" : artifact;
  if (
    includesCompletenessSection(
      step.completeness,
      "truncated_sections",
      section,
    )
  )
    return "truncated";
  return includesCompletenessSection(
    step.completeness,
    "missing_sections",
    section,
  )
    ? "missing"
    : "captured";
};

const EVENT_SECTIONS = [
  "events",
  "frames",
  "workers",
  "popups",
  "websockets",
] as const;

/** Project event evidence through capture- and step-level completeness. */
export const eventEvidenceState = (
  capture: BrowserScenarioCapture,
  step: BrowserScenarioStep,
): BrowserScenarioEvidenceState => {
  const listed = (collection: "missing_sections" | "truncated_sections") =>
    EVENT_SECTIONS.some(
      (section) =>
        includesCompletenessSection(
          capture.completeness,
          collection,
          section,
        ) ||
        includesCompletenessSection(step.completeness, collection, section),
    );
  if (capture.events.dropped > 0 || listed("truncated_sections"))
    return "truncated";
  return listed("missing_sections") ? "missing" : "captured";
};

/** Select stable action fields for normalized comparison. */
export const actionState = (step: BrowserScenarioStep) => ({
  action: step.action,
  status: step.status,
  before_url: step.before_url,
  after_url: step.after_url,
  error: step.error,
});

/** One step's ordered events and its network events grouped by transaction. */
export interface ScenarioStepEvents {
  readonly events: readonly unknown[];
  readonly network_transactions: readonly (readonly unknown[])[];
}

/** Select one step's events without sequence metadata; network events follow the step that sent their request. */
export const eventsFor = (
  capture: BrowserScenarioCapture,
  stepIndex: number,
): ScenarioStepEvents => {
  const sourceSteps = new Map(
    capture.events.items.map(({ sequence, step_index }) => [
      sequence,
      step_index,
    ]),
  );
  const requests = new Map(
    capture.events.items.flatMap((event) =>
      event.kind === "request" ? [[event.transaction_id, event]] : [],
    ),
  );
  // Capture-local IDs locate evidence only; the projected identity retains the
  // predecessor's complete request, outcome and selected content before normalization.
  const predecessorEvidence = new Map<string, unknown[]>();
  for (const { sequence: _sequence, step_index: _step, ...event } of capture
    .events.items) {
    if (!("transaction_id" in event)) continue;
    const id = event.transaction_id;
    let evidence: unknown;
    if (event.kind === "network-content") {
      const {
        transaction_id: _id,
        source_event_sequence: _source,
        ...content
      } = event;
      evidence = content;
    } else {
      const {
        transaction_id: _id,
        redirected_from_transaction_id: _predecessor,
        ...network
      } = event;
      evidence = network;
    }
    const previous = predecessorEvidence.get(id);
    if (previous === undefined) predecessorEvidence.set(id, [evidence]);
    else previous.push(evidence);
  }
  const events: unknown[] = [];
  const transactions = new Map<string, unknown[]>();
  const record = (transactionId: string, event: unknown) => {
    const transaction = transactions.get(transactionId);
    if (transaction === undefined) transactions.set(transactionId, [event]);
    else transaction.push(event);
  };
  for (const {
    sequence: _sequence,
    step_index: eventStepIndex,
    ...event
  } of capture.events.items) {
    if (!("transaction_id" in event)) {
      if (eventStepIndex === stepIndex) events.push(event);
      continue;
    }
    const receiptStep =
      event.kind === "network-content"
        ? sourceSteps.get(event.source_event_sequence)
        : eventStepIndex;
    if (
      (requests.get(event.transaction_id)?.step_index ?? receiptStep) !==
      stepIndex
    )
      continue;
    if (event.kind === "network-content") {
      const {
        source_event_sequence: _sourceSequence,
        transaction_id: transactionId,
        ...content
      } = event;
      record(transactionId, content);
      continue;
    }
    const {
      transaction_id: transactionId,
      redirected_from_transaction_id: predecessorId,
      ...network
    } = event;
    const predecessor =
      predecessorId === null ? null : predecessorEvidence.get(predecessorId);
    record(transactionId, {
      ...network,
      redirected_from:
        predecessor === undefined ? { state: "missing" } : predecessor,
    });
  }
  return { events, network_transactions: [...transactions.values()] };
};

const digestEach = (items: unknown): unknown =>
  Array.isArray(items)
    ? items.map((item) => digestCanonicalValue(item, "Browser scenario")).sort()
    : items;

/** Compare normalized network transactions as an unordered collection; concurrent responses arrive in any order. */
export const orderNetworkTransactions = (value: unknown): unknown =>
  typeof value === "object" &&
  value !== null &&
  "network_transactions" in value &&
  Array.isArray(value.network_transactions)
    ? {
        ...value,
        network_transactions: digestEach(
          value.network_transactions.map((transaction: unknown) =>
            digestEach(
              Array.isArray(transaction)
                ? transaction.map((event: unknown) =>
                    typeof event === "object" &&
                    event !== null &&
                    "redirected_from" in event
                      ? {
                          ...event,
                          redirected_from: digestEach(event.redirected_from),
                        }
                      : event,
                  )
                : transaction,
            ),
          ),
        ),
      }
    : value;

/** Different content selection is missing comparability, not an observed website change. */
export const networkContentCoverageReason = (
  before: BrowserScenarioCapture,
  after: BrowserScenarioCapture,
): string | undefined => {
  const left = before.scenario.network_content;
  const right = after.scenario.network_content;
  return left.request_body !== right.request_body ||
    left.response_body !== right.response_body ||
    left.header_values !== right.header_values
    ? "Network content selections differ; capture both sides with matching content selection before comparing network evidence."
    : undefined;
};

/** Different or unrecorded event-family selection is missing comparability, not an observed website change. */
export const eventFamilyCoverageReason = (
  before: BrowserScenarioCapture,
  after: BrowserScenarioCapture,
): string | undefined => {
  const left = before.scenario.event_families;
  const right = after.scenario.event_families;
  if (left === undefined || right === undefined)
    return "Event family selection is unknown in a legacy capture; capture both sides with matching event families before comparing event evidence.";
  const leftFamilies = new Set(left);
  const rightFamilies = new Set(right);
  return leftFamilies.size === rightFamilies.size &&
    [...leftFamilies].every((family) => rightFamilies.has(family))
    ? undefined
    : `Event family selections differ (${familyList(leftFamilies)} before, ${familyList(rightFamilies)} after); capture both sides with matching event families before comparing event evidence.`;
};

const familyList = (families: ReadonlySet<string>): string =>
  families.size === 0 ? "none" : [...families].sort().join(", ");

/** Wrap one value as captured comparison evidence. */
export const captured = <Value>(value: Value): CaptureState<Value> => ({
  state: "captured",
  value,
});

/** Retain stable screenshot identity without embedding image bytes. */
export const screenshotProjection = (
  screenshot: Extract<
    BrowserStepArtifacts["screenshot"],
    { state: "captured" }
  >["value"],
) => ({
  sha256: screenshot.sha256,
  bytes: screenshot.bytes,
  media_type: screenshot.media_type,
});
