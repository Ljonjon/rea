/**
 * Validate optional source-map content against its source inventory.
 *
 * ECMA-426 DecodeSourceMapSources reads a content entry only when the source
 * index is within `sourcesContent`, so trailing missing slots decode as null
 * content instead of invalidating the map. Extra entries beyond the source
 * inventory and non-string/non-null entries are still rejected.
 */
export const hasValidSourceMapContents = (
  sourceCount: number,
  contents: unknown,
): boolean =>
  contents === undefined ||
  contents === null ||
  (Array.isArray(contents) &&
    contents.length <= sourceCount &&
    contents.every(
      (content: unknown) => content === null || typeof content === "string",
    ));
