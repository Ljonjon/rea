import { expect, it } from "vitest";
import { redactCapturedTransportCredentials } from "./ProviderDiagnosticRedaction.js";

it.each([true, false])(
  "redacts the current credential across older-token suffix collisions (complete=%s)",
  (complete) => {
    const previous = "a" + "b".repeat(63);
    const current = "c".repeat(63) + "a";
    const suffix = complete ? current : current.slice(0, 63);
    const tokens = complete
      ? [previous, current]
      : ["c" + "d".repeat(63), current];
    const text = `old=${tokens[0]} current=${suffix}`;
    const bytes = Buffer.byteLength(text);
    expect(
      redactCapturedTransportCredentials(
        { text, bytes, observedBytes: bytes + 1 },
        tokens,
        "[REDACTED]",
      ),
    ).toBe("old=[REDACTED] current=[REDACTED]");
  },
);
