import { describe, expect, it } from "vitest";

import type { LinuxPackageInstallFailure } from "./LinuxHopper.js";
import { HOPPER_PUBLISHER } from "./MacHopper.js";
import { setupInstallFailure } from "./SetupInstallFailure.js";

const packageFailure = (
  overrides: Partial<LinuxPackageInstallFailure> = {},
): LinuxPackageInstallFailure => ({
  command: "pkexec pacman -U --noconfirm /tmp/rea-hopper-x/hopper.arch",
  exitCode: 1,
  stdout: "",
  stderr: "",
  outputTruncated: false,
  ...overrides,
});

const remediationFor = (failure: LinuxPackageInstallFailure): string => {
  const result = setupInstallFailure(
    "authorization_or_package_manager",
    failure,
  );
  if (result.status !== "failed") throw new Error("expected a failed install");
  return result.remediation;
};

describe("setup package-manager failure reporting", () => {
  it("quotes the failing command, exit status, and output", () => {
    const remediation = remediationFor(
      packageFailure({
        stdout: "loading packages...",
        stderr:
          "error: failed to prepare transaction (conflicting dependencies)\n:: zlib-1:1.3.2-3.1 and zlib-ng-compat-2.3.3-2 are in conflict",
      }),
    );
    expect(remediation).toContain("pkexec pacman -U");
    expect(remediation).toContain("exit 1");
    expect(remediation).toContain("error: failed to prepare transaction");
    expect(remediation).toContain("zlib-ng-compat-2.3.3-2 are in conflict");
    expect(remediation).toContain("then rerun rea setup");
  });

  it("strips terminal escapes and line breaks from quoted output", () => {
    const remediation = remediationFor(
      packageFailure({
        stderr: "\u001b[31merror: unresolvable package conflicts\u001b[0m",
      }),
    );
    expect(remediation).not.toContain("\u001b");
    expect(remediation).not.toContain("\n");
    expect(remediation).toContain("error: unresolvable package conflicts");
  });

  it("keeps an stderr conflict visible after long stdout", () => {
    const remediation = remediationFor(
      packageFailure({
        stdout: "loading packages... ".repeat(100),
        stderr: "error: unresolvable package conflicts detected",
      }),
    );
    expect(remediation).toContain(
      "error: unresolvable package conflicts detected",
    );
    expect(remediation.length).toBeLessThan(800);
  });

  it("keeps the final error visible after long warnings in the same stream", () => {
    const remediation = remediationFor(
      packageFailure({
        stderr: `${"warning ".repeat(1000)}error: final conflict`,
        outputTruncated: true,
      }),
    );
    expect(remediation).toContain("error: final conflict");
    expect(remediation).toContain("(output truncated)");
    expect(remediation.length).toBeLessThan(800);
  });

  it("preserves the end of bounded output and reports truncation", () => {
    const remediation = remediationFor(
      packageFailure({
        stdout: `${"w ".repeat(199)}ZZZZZZZZ`,
        outputTruncated: true,
      }),
    );
    expect(remediation).toContain("ZZZZZZZZ");
    expect(remediation).toContain("…");
    expect(remediation).toContain("(output truncated)");
    expect(remediation.length).toBeLessThan(800);
  });

  it("bounds an excerpt that has no word boundary", () => {
    const remediation = remediationFor(
      packageFailure({ stdout: "x".repeat(1_000) }),
    );
    expect(remediation).toContain("…");
    expect(remediation.length).toBeLessThan(800);
  });

  it("reports an unavailable exit status and empty output", () => {
    const remediation = remediationFor(packageFailure({ exitCode: null }));
    expect(remediation).toContain("no exit status");
    expect(remediation).toContain("no output was captured.");
  });

  it("keeps the authorization guidance when no command output is recorded", () => {
    const result = setupInstallFailure("authorization_or_package_manager");
    expect(result).toMatchObject({
      status: "failed",
      code: "authorization_or_package_manager_failed",
    });
    if (result.status !== "failed")
      throw new Error("expected a failed install");
    expect(result.remediation).toContain(
      "Allow the system package-manager operation",
    );
  });
});

describe("macOS Hopper setup failure projection", () => {
  it("projects a publisher mismatch onto its own code and recovery", () => {
    expect(setupInstallFailure("publisher_verification_failed")).toEqual({
      status: "failed",
      code: "publisher_verification_failed",
      remediation: `The mounted Hopper application is not signed by the publisher REA pins (${HOPPER_PUBLISHER.bundleIdentifier}, Apple team ${HOPPER_PUBLISHER.teamIdentifier}); nothing was copied or launched. Install Hopper yourself and set HOPPER_LAUNCHER_PATH to its launcher, then rerun rea setup.`,
    });
  });

  it("keeps a broken bundle distinct from a publisher mismatch", () => {
    expect(setupInstallFailure("bundle")).toEqual({
      status: "failed",
      code: "bundle_invalid",
      remediation:
        "The mounted package did not contain the expected Hopper application bundle. Retry setup; if it repeats, update REA before installing.",
    });
  });
});
