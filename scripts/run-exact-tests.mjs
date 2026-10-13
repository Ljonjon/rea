import { resolve } from "node:path";

import { createVitest, parseCLI } from "vitest/node";

// CLI file filters are substring matches. Select discovered specifications by
// identity instead, retaining each project's include/exclude and runner settings.
const { filter, options } = parseCLI(["vitest", ...process.argv.slice(2)]);
const selected = new Set(filter.map((path) => resolve(path)));
const vitest = await createVitest({ ...options, watch: false });
try {
  await vitest.standalone();
  const specifications = (await vitest.globTestSpecifications()).filter(
    (specification) => selected.has(resolve(specification.moduleId)),
  );
  const discovered = new Set(
    specifications.map((specification) => resolve(specification.moduleId)),
  );
  const missing = filter.filter((path) => !discovered.has(resolve(path)));
  if (missing.length > 0 || selected.size === 0)
    throw new Error(
      `Selected test files were not discovered: ${missing.join(", ")}`,
    );
  await vitest.runTestSpecifications(specifications);
} finally {
  await vitest.close();
}
