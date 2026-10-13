import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmod,
  copyFile,
  readFile,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { expect, it } from "vitest";

import { assertCleanLinuxHopperRuntime } from "../../../scripts/lib/clean-linux-hopper-runtime.mjs";
import { cleanupOwnedProcessGroup } from "../../../src/process/ProcessOwnership.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const execFileAsync = promisify(execFile);

it.runIf(process.platform === "linux").each([
  ["Xvfb", "Clean Linux runner retained a Hopper demo process"],
  ["Hopper", "Clean Linux runner retained a Hopper demo process"],
  ["python3", "Cannot identify a command-less Python process"],
  ["unrelated", undefined],
] as const)(
  "observes an unreaped %s without signaling or reaping it",
  async (name, refusal) => {
    const directory = await createTestTempDirectory("rea-runtime-zombie-");
    const executable = join(directory, name);
    await copyFile("/usr/bin/true", executable);
    await chmod(executable, 0o700);
    // WNOWAIT observes exit without reaping. The parent keeps the zombie until
    // the test closes its stdin, then waitpid performs the actual cleanup.
    const parent = execFileAsync(
      "/usr/bin/python3",
      [
        "-c",
        `
import os, sys
pid = os.fork()
if pid == 0:
    os.execl(sys.argv[1], sys.argv[1])
try:
    os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
    print(pid, flush=True)
    sys.stdin.buffer.read(1)
finally:
    os.waitpid(pid, 0)
`,
        executable,
      ],
      { timeout: 10_000 },
    );
    const ready = new Promise<number>((resolve, reject) => {
      parent.child.stdout?.once("data", (data: Buffer) =>
        resolve(Number(data.toString().trim())),
      );
      parent.catch(reject);
    });
    let zombiePid: number | undefined;
    try {
      zombiePid = await ready;
      expect(Number.isSafeInteger(zombiePid)).toBe(true);
      const prefix = `/proc/${String(zombiePid)}`;
      expect(await readFile(`${prefix}/cmdline`, "utf8")).toBe("");
      expect((await readFile(`${prefix}/comm`, "utf8")).trim()).toBe(name);
      const observation = assertCleanLinuxHopperRuntime([]);
      if (refusal === undefined)
        await expect(observation).resolves.toBeUndefined();
      else await expect(observation).rejects.toThrow(refusal);
      expect(await readFile(`${prefix}/stat`, "utf8")).toContain(
        `(${name}) Z `,
      );
    } finally {
      parent.child.stdin?.end("reap");
      await parent;
      if (zombiePid !== undefined)
        await expect(
          readFile(`/proc/${String(zombiePid)}/stat`, "utf8"),
        ).rejects.toMatchObject({ code: "ENOENT" });
    }
  },
);

it.runIf(process.platform === "linux")(
  "does not treat runtime names in another process's arguments as a runtime",
  async () => {
    const observer = new URL(
      "../../../scripts/lib/clean-linux-hopper-runtime.mjs",
      import.meta.url,
    ).href;
    const code = `
      const { assertCleanLinuxHopperRuntime } = await import(${JSON.stringify(observer)});
      await assertCleanLinuxHopperRuntime([]);
      console.log('clean');
    `;
    const { stdout } = await execFileAsync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        code,
        "Xvfb",
        "/opt/hopper/bin/Hopper",
        "hopper-demo-x11.py",
      ],
      { timeout: 10_000 },
    );
    expect(stdout.trim()).toBe("clean");
  },
);

it.runIf(process.platform === "linux")(
  "distinguishes an ordinary Node script with the helper's filename",
  async () => {
    const directory = await createTestTempDirectory("rea-runtime-arguments-");
    const script = join(directory, "hopper-demo-x11.py");
    const observer = new URL(
      "../../../scripts/lib/clean-linux-hopper-runtime.mjs",
      import.meta.url,
    ).href;
    await writeFile(
      script,
      `
      import(${JSON.stringify(observer)}).then(async ({ assertCleanLinuxHopperRuntime }) => {
        await assertCleanLinuxHopperRuntime([]);
        console.log('clean');
      });
    `,
    );
    const { stdout } = await execFileAsync(process.execPath, [script], {
      timeout: 10_000,
    });
    expect(stdout.trim()).toBe("clean");
  },
);

const launchReapedOrphan = (runId: string, parentCode: string) => {
  // The short-lived Node launcher still exits before observation. A retained
  // subreaper adopts its child and waits after owned cleanup, even when the
  // container's PID 1 does not reap. It is a sibling of the verifier below.
  const reaper = execFileAsync(
    "/usr/bin/python3",
    [
      "-c",
      `
import ctypes, json, os, subprocess, sys
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(36, 1, 0, 0, 0) != 0: # PR_SET_CHILD_SUBREAPER
    raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
launcher = subprocess.run(sys.argv[1:], capture_output=True, text=True, check=True)
child = json.loads(launcher.stdout)
try:
    print(json.dumps(child), flush=True)
    sys.stdin.buffer.read(1)
finally:
    os.waitpid(child["pid"], 0)
`,
      process.execPath,
      "-e",
      parentCode,
    ],
    {
      env: { ...process.env, REA_PROCESS_RUN_ID: runId },
      timeout: 40_000,
    },
  );
  const ready = new Promise<{ pid: number; parentPid: number }>(
    (resolve, reject) => {
      reaper.child.stdout?.once("data", (data: Buffer) => {
        try {
          resolve(JSON.parse(data.toString()));
        } catch (error) {
          reject(error);
        }
      });
      reaper.then(
        () => reject(new Error("Fixture reaper exited before readiness")),
        reject,
      );
    },
  );
  return { reaper, ready };
};

const observeFromSeparateVerifier = async (
  runId: string,
  launcherPaths: string[],
) => {
  const observer = new URL(
    "../../../scripts/lib/clean-linux-hopper-runtime.mjs",
    import.meta.url,
  ).href;
  const verifierRun = new URL(
    "../../../scripts/lib/verifier-run.mjs",
    import.meta.url,
  ).href;
  const { stdout: observed } = await execFileAsync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `
const { assertCleanLinuxHopperRuntime } = await import(${JSON.stringify(observer)});
const { completeVerifierRun } = await import(${JSON.stringify(verifierRun)});
const { process_lineage } = await completeVerifierRun({
  run_id: ${JSON.stringify(runId)}, verifier_pid: process.pid, parent_pid: process.ppid,
});
let refusal;
try { await assertCleanLinuxHopperRuntime(${JSON.stringify(launcherPaths)}); }
catch (error) { refusal = error.message; }
console.log(JSON.stringify({ process_lineage, refusal }));
`,
    ],
    { timeout: 10_000 },
  );
  return JSON.parse(observed) as {
    process_lineage: {
      status: string;
      descendants: { pid: number }[];
    };
    refusal?: string;
  };
};

it.runIf(process.platform === "linux").each([
  ["Xvfb-named Node", null, true],
  ["Python helper", [], true],
  ["Python helper with -u", ["-u"], true],
  [
    "Python helper with combined/value options",
    ["-Bu", "-W", "ignore", "-X", "dev", "--check-hash-based-pycs", "always"],
    true,
  ],
  ["Python helper after --", ["--"], true],
  [
    "Python -c script argument",
    ["-c", "import time; print('ready', flush=True); time.sleep(30)"],
    false,
  ],
  ["Python -m script argument", ["-m", "unrelated"], false],
  ["alternate launcher", null, true],
] as const)(
  "classifies a reparented %s without signaling it",
  async (mode, pythonOptions, retained) => {
    const runId = randomUUID();
    const childCode =
      "process.title = 'Xvfb'; setInterval(() => {}, 1000); process.send('ready');";
    const directory = await createTestTempDirectory("rea-clean-runtime-test-");
    const launcher = join(directory, "Hopper");
    const alternate = join(directory, "Hopper-alternate");
    const helper = join(directory, "hopper-demo-x11.py");
    const alternateMode = mode === "alternate launcher";
    const pythonMode = pythonOptions !== null;
    if (alternateMode) {
      await copyFile("/usr/bin/sleep", launcher);
      await chmod(launcher, 0o700);
      await symlink(launcher, alternate);
    }
    if (pythonMode) {
      await writeFile(
        helper,
        "import time\nprint('ready', flush=True)\ntime.sleep(30)\n",
      );
      await copyFile(helper, join(directory, "unrelated.py"));
    }
    // The fixture must be the cause of a refusal; a retained host runtime
    // would otherwise mask a broken classification or executable-identity check.
    await assertCleanLinuxHopperRuntime(alternateMode ? [launcher] : []);
    const command = alternateMode
      ? alternate
      : pythonMode
        ? "/usr/bin/python3"
        : process.execPath;
    const arguments_ = alternateMode
      ? ["30"]
      : pythonMode
        ? [...pythonOptions, helper]
        : ["-e", childCode];
    const stdio = alternateMode
      ? "ignore"
      : pythonMode
        ? ["ignore", "pipe", "ignore"]
        : ["ignore", "ignore", "ignore", "ipc"];
    const parentCode = `
      const { spawn } = require('node:child_process');
      const child = spawn(${JSON.stringify(command)}, ${JSON.stringify(arguments_)}, {
        detached: true, stdio: ${JSON.stringify(stdio)}, cwd: ${JSON.stringify(directory)}
      });
      child.once('error', () => process.exit(1));
      const ready = () => {
        process.stdout.write(JSON.stringify({ pid: child.pid, parentPid: process.pid }));
        if (child.connected) child.disconnect();
        child.stdout?.destroy();
        child.unref();
      };
      ${pythonMode ? "child.stdout.once('data', ready);" : `child.once(${JSON.stringify(alternateMode ? "spawn" : "message")}, ready);`}
    `;
    const { reaper, ready } = launchReapedOrphan(runId, parentCode);
    let orphanPid: number | undefined;
    try {
      const { pid, parentPid } = await ready;
      orphanPid = pid;
      const { stdout: coordinates } = await execFileAsync("ps", [
        "-p",
        String(pid),
        "-o",
        "ppid=,pgid=",
      ]);
      const [currentParent, group] = coordinates
        .trim()
        .split(/\s+/u)
        .map(Number);
      expect(currentParent).not.toBe(parentPid);
      expect(currentParent).toBe(reaper.child.pid);
      expect(group).toBe(pid);

      if (alternateMode) {
        const commandLine = await readFile(
          `/proc/${String(pid)}/cmdline`,
          "utf8",
        );
        expect(commandLine.split("\0")[0]).toBe(alternate);
        await unlink(alternate);
      }
      if (pythonMode) {
        const commandLine = await readFile(
          `/proc/${String(pid)}/cmdline`,
          "utf8",
        );
        expect(
          commandLine.split("\0").slice(0, pythonOptions.length + 2),
        ).toEqual([command, ...pythonOptions, helper]);
      }
      const { process_lineage: lineage, refusal } =
        await observeFromSeparateVerifier(
          runId,
          alternateMode ? [launcher] : [],
        );
      expect(lineage.status).toBe("verified");
      expect(lineage.descendants.some((p) => p.pid === pid)).toBe(false);
      if (retained)
        expect(refusal).toBe(
          "Clean Linux runner retained a Hopper demo process",
        );
      else expect(refusal).toBeUndefined();
      // Observation must not terminate the fixture, even though it resembles Xvfb.
      const { stdout: alive } = await execFileAsync("ps", [
        "-p",
        String(pid),
        "-o",
        "stat=",
      ]);
      expect(alive.trim()).not.toMatch(/^Z/u);
    } finally {
      try {
        if (orphanPid !== undefined) {
          const cleanup = await cleanupOwnedProcessGroup({
            runId,
            leaderPid: orphanPid,
            processGroupId: orphanPid,
          });
          expect(cleanup.cleaned, JSON.stringify(cleanup)).toBe(true);
        }
      } finally {
        reaper.child.stdin?.end("reap");
        await reaper;
        if (orphanPid !== undefined)
          await expect(
            readFile(`/proc/${String(orphanPid)}/stat`, "utf8"),
          ).rejects.toMatchObject({ code: "ENOENT" });
      }
    }
  },
);
