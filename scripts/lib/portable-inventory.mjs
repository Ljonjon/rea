import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { open, readdir } from "node:fs/promises";
import { join } from "node:path";

/** Hash one opened file with bounded buffers; reject size mismatches before reads. */
export async function hashPortableFile(path, expectedSize) {
  const file = await open(path, "r");
  try {
    const metadata = await file.stat();
    if (!metadata.isFile())
      throw new Error(
        `Portable inventory contains a non-regular file: ${path}`,
      );
    if (expectedSize !== undefined && metadata.size !== expectedSize)
      throw new Error(
        `Portable file size mismatch: ${path}; expected ${expectedSize}, observed ${metadata.size}`,
      );
    const hash = createHash("sha256");
    let size = 0;
    for await (const chunk of file.createReadStream({
      autoClose: false,
      highWaterMark: 64 * 1024,
    })) {
      size += chunk.length;
      if (size > metadata.size)
        throw new Error(`Portable file size changed while hashing: ${path}`);
      hash.update(chunk);
    }
    if (size !== metadata.size)
      throw new Error(`Portable file size changed while hashing: ${path}`);
    return { size, sha256: hash.digest("hex") };
  } finally {
    await file.close();
  }
}

/** Require exact files and their parent directories before running the artifact. */
export async function verifyPortableInventory(directory, files) {
  const actual = [];
  const parents = new Set();
  for (const { path } of files) {
    const parts = path.split("/");
    for (let length = 1; length < parts.length; length++)
      parents.add(parts.slice(0, length).join("/"));
  }
  async function visit(current, prefix = "") {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const path = prefix + entry.name;
      if (entry.isDirectory()) {
        // Even an empty package directory can shadow a hoisted Node dependency.
        if (!parents.has(path))
          throw new Error(
            `Portable inventory contains an unlisted directory: ${path}`,
          );
        await visit(join(current, entry.name), `${path}/`);
      } else if (!entry.isFile())
        throw new Error(
          `Portable inventory contains a non-regular entry: ${path}`,
        );
      else if (path !== "portable.json") actual.push(path);
    }
  }
  await visit(directory);
  assert.deepEqual(
    files.map((file) => file.path).sort(),
    actual.sort(),
    "Portable inventory must match the exact regular-file set",
  );
}
