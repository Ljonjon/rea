import { createHash } from "node:crypto";
import { extname, join } from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";

import type { JsonValue } from "../domain/jsonValue.js";
import { AnalysisArtifactChangedError } from "../domain/analysisErrorCore.js";
import { withGhidraFileCopy } from "./GhidraFileCopy.js";
import type { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { windowsPrivateRuntime } from "../windows/WindowsPrivateRuntime.js";

/** Immutable target copy admitted to one ephemeral Ghidra import. */
export interface GhidraTargetSnapshot {
  readonly path: string;
  readonly sha256: string;
  readonly admission?: JsonValue;
}

/** Copy one target and require its bytes to match the parsed target identity. */
export const createGhidraTargetSnapshot = async (
  sourcePath: string,
  runtimeRoot: string,
  expectedSha256: string,
  options: {
    readonly signal?: AbortSignal;
    readonly platform?: NodeJS.Platform;
    readonly fileOwners?: Set<OwnedFileHandle>;
  } = {},
): Promise<GhidraTargetSnapshot> => {
  if (!/^[a-f0-9]{64}$/u.test(expectedSha256))
    throw new TypeError("Ghidra target SHA-256 commitment is invalid");
  const suffix = safeExtension(sourcePath);
  const snapshotPath = join(
    runtimeRoot,
    `target-${expectedSha256.slice(0, 12)}${suffix}`,
  );
  if ((options.platform ?? process.platform) === "win32") {
    const observed = await windowsPrivateRuntime(runtimeRoot).snapshot(
      sourcePath,
      `target-${expectedSha256.slice(0, 12)}${suffix}`,
      options.signal,
    );
    if (observed.sha256 !== expectedSha256)
      throw new AnalysisArtifactChangedError(
        "open_binary",
        sourcePath,
        `Ghidra target snapshot digest mismatch: expected ${expectedSha256}, observed ${observed.sha256}`,
      );
    return {
      path: snapshotPath,
      sha256: observed.sha256,
      admission: { source: observed.source, snapshot: observed.snapshot },
    };
  }
  return withGhidraFileCopy(
    sourcePath,
    snapshotPath,
    async (source, destination) => {
      const hash = createHash("sha256");
      const digest = new Transform({
        transform(chunk: unknown, _encoding, done) {
          if (!Buffer.isBuffer(chunk)) {
            done(new TypeError("Ghidra snapshot stream must contain bytes"));
            return;
          }
          hash.update(chunk);
          done(null, chunk);
        },
      });
      await pipeline(
        source.createReadStream({ autoClose: false }),
        digest,
        destination.createWriteStream({ autoClose: false }),
        options.signal === undefined ? {} : { signal: options.signal },
      );
      const observedSha256 = hash.digest("hex");
      if (observedSha256 !== expectedSha256)
        throw new AnalysisArtifactChangedError(
          "open_binary",
          sourcePath,
          `Ghidra target snapshot digest mismatch: expected ${expectedSha256}, observed ${observedSha256}`,
        );
      return { path: snapshotPath, sha256: observedSha256 };
    },
    options.fileOwners,
  );
};

const safeExtension = (path: string): string => {
  const extension = extname(path);
  return /^\.[A-Za-z0-9]{1,12}$/u.test(extension) ? extension : ".bin";
};
