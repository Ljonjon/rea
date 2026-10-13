import { open, rm, type FileHandle } from "node:fs/promises";
import { OwnedFileHandle } from "../filesystem/OwnedFileHandle.js";
import { err, ok, type Result } from "../domain/result.js";
import { AnalysisArtifactChangedError } from "../domain/analysisErrorCore.js";
import { openGhidraSource } from "./GhidraSourceFile.js";

/** Failed copy cleanup retains exact descriptor owners and the original outcome. */
export class GhidraFileCopyCleanupFailure<
  Value = unknown,
> extends AggregateError {
  constructor(
    readonly owners: readonly {
      readonly path: string;
      readonly owner: OwnedFileHandle;
    }[],
    readonly outcome: Result<Value, unknown>,
    failures: readonly unknown[],
  ) {
    super(
      outcome.ok ? failures : [outcome.error, ...failures],
      "Ghidra source-copy descriptor cleanup remains incomplete",
      outcome.ok ? {} : { cause: outcome.error },
    );
    this.name = "GhidraFileCopyCleanupFailure";
  }

  get primaryCause(): unknown {
    return this.outcome.ok ? this : this.outcome.error;
  }
}

/** Both immutable snapshot copies share one explicit descriptor lifetime. */
export const withGhidraFileCopy = async <Value>(
  sourcePath: string,
  destinationPath: string,
  copy: (source: FileHandle, destination: FileHandle) => Promise<Value>,
  retainedOwners: Set<OwnedFileHandle> = new Set(),
): Promise<Value> => {
  const owners: { path: string; owner: OwnedFileHandle }[] = [];
  const own = (path: string, handle: FileHandle) => {
    const owner = new OwnedFileHandle(handle);
    owners.push({ path, owner });
    retainedOwners.add(owner);
    return handle;
  };
  let outcome: Result<Value, unknown>;
  let destinationOwned = false;
  try {
    const source = own(sourcePath, await openGhidraSource(sourcePath));
    if (!(await source.stat()).isFile())
      throw new AnalysisArtifactChangedError(
        "open_binary",
        sourcePath,
        "The admitted Ghidra source is no longer a regular file",
      );
    const destination = own(
      destinationPath,
      await open(destinationPath, "wx", 0o600),
    );
    destinationOwned = true;
    await destination.chmod(0o600);
    outcome = ok(await copy(source, destination));
  } catch (cause: unknown) {
    outcome = err(cause);
  }
  const cleanup = await Promise.allSettled(
    owners.map(async ({ owner }) => {
      await owner.close();
      retainedOwners.delete(owner);
    }),
  );
  const failures = cleanup.flatMap((result) =>
    result.status === "rejected" ? [result.reason as unknown] : [],
  );
  if (failures.length !== 0)
    throw new GhidraFileCopyCleanupFailure(
      owners.filter(({ owner }) => retainedOwners.has(owner)),
      outcome,
      failures,
    );
  if (!outcome.ok) {
    if (destinationOwned)
      await rm(destinationPath, { force: true }).catch(() => undefined);
    throw outcome.error;
  }
  return outcome.value;
};
