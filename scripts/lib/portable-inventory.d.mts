export function verifyPortableInventory(
  directory: string,
  files: readonly { readonly path: string }[],
): Promise<void>;
export function hashPortableFile(
  path: string,
  expectedSize?: number,
): Promise<{ size: number; sha256: string }>;
