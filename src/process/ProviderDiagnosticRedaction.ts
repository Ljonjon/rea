import type { ProviderProcessSnapshot } from "./ProviderProcess.js";

type CapturedStream = Pick<
  ProviderProcessSnapshot["stdout"],
  "text" | "bytes" | "observedBytes"
>;

/** Redact explicit transport credentials from complete and budget-cut output. */
export const redactCapturedTransportCredential = (
  stream: CapturedStream,
  token: string | undefined,
  replacement: string,
): string =>
  redactCapturedTransportCredentials(
    stream,
    token === undefined ? [] : [token],
    replacement,
  );

/** Resolve the longest cut suffix against the original stream before any replacements. */
export const redactCapturedTransportCredentials = (
  stream: CapturedStream,
  tokens: Iterable<string>,
  replacement: string,
): string => {
  const credentials = [...tokens]
    .filter((token) => token.length > 0)
    .sort((left, right) => right.length - left.length);
  const { text } = stream;
  let suffixLength = 0;
  if (stream.observedBytes > stream.bytes)
    for (const token of credentials)
      for (
        let length = Math.min(text.length, token.length);
        length > suffixLength;
        length--
      )
        if (text.endsWith(token.slice(0, length))) {
          suffixLength = length;
          break;
        }
  let redacted =
    suffixLength === 0 ? text : text.slice(0, text.length - suffixLength);
  for (const token of credentials)
    redacted = redacted.replaceAll(token, replacement);
  return suffixLength === 0 ? redacted : redacted + replacement;
};
