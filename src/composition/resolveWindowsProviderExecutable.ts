import { stat } from "node:fs/promises";
import { waitForAbortable, ABORTED } from "../process/AbortablePromise.js";
import { ProviderStartupDeadline } from "../process/ProviderDeadline.js";
import {
  AnalysisCancelledError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { resolve, win32 } from "node:path";

/** Resolve Windows bare command names against the captured child environment. */
export const resolveWindowsProviderExecutable = async (
  executable: string,
  environment: Readonly<NodeJS.ProcessEnv>,
  options: { readonly signal?: AbortSignal; readonly timeoutMs?: number } = {},
): Promise<string> => {
  const root = win32.parse(executable).root;
  if (win32.isAbsolute(executable) && root.length > 1) return executable;
  if (root !== "" || executable.includes("/") || executable.includes("\\"))
    return resolve(executable);

  const pathValue = environment.PATH ?? environment.Path ?? environment.path;
  if (pathValue === undefined) return executable;
  const pathEntries = pathValue.split(";");
  const explicitExtension = win32.extname(executable).toLowerCase();
  if (explicitExtension !== "" && ![".com", ".exe"].includes(explicitExtension))
    return executable;
  const extensions =
    explicitExtension !== ""
      ? [""]
      : (environment.PATHEXT ?? environment.PathExt ?? ".COM;.EXE")
          .split(";")
          .filter((extension) =>
            [".com", ".exe"].includes(extension.toLowerCase()),
          );

  const deadline = new ProviderStartupDeadline(
    options.timeoutMs ?? 120_000,
    options.signal,
  );
  try {
    for (const entry of pathEntries) {
      if (entry.length === 0) continue;
      for (const extension of extensions) {
        const candidate = resolve(entry, `${executable}${extension}`);
        // The captured PATH is Windows-formatted even when this resolver is unit-tested elsewhere.
        try {
          const info = await waitForAbortable(stat(candidate), deadline.signal);
          if (info === ABORTED) {
            if (deadline.interruption === "timeout")
              throw new AnalysisTimeoutError(
                "resolve_provider_executable",
                options.timeoutMs ?? 120_000,
              );
            throw new AnalysisCancelledError("resolve_provider_executable");
          }
          if (info.isFile()) return candidate;
        } catch (cause) {
          if (
            cause instanceof AnalysisCancelledError ||
            cause instanceof AnalysisTimeoutError
          )
            throw cause;
          // An inaccessible PATH entry is equivalent to a missing candidate.
        }
      }
    }
    return executable;
  } finally {
    deadline.dispose();
  }
};
