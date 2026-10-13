export interface OpenAiModelFixtureRequest {
  readonly path: string;
  readonly tools: readonly string[];
  readonly stream: unknown;
  readonly messageRoles: readonly unknown[];
}

export interface OpenAiModelFixtureProbe {
  readonly method: string | undefined;
  readonly path: string | undefined;
  readonly body: unknown;
  readonly status: 404;
}

export interface OpenAiModelFixtureToolCall {
  readonly id?: string;
  readonly type?: "function";
  readonly function: { readonly name: string; readonly arguments: string };
}

/** Assistant message the fixture returns as a completion or streams as deltas. */
export interface OpenAiModelFixtureMessage {
  readonly role?: "assistant";
  readonly content?: string | null;
  readonly tool_calls?: readonly OpenAiModelFixtureToolCall[];
}

export interface OpenAiModelFixture {
  readonly baseUrl: string;
  readonly requests: readonly OpenAiModelFixtureRequest[];
  readonly probes: readonly OpenAiModelFixtureProbe[];
  readonly failure: string | undefined;
  close(): Promise<void>;
}

export function createOpenAiModelFixture(options: {
  readonly directory: string;
  readonly prefix: string;
  readonly onRequest: (request: {
    readonly body: Record<string, unknown>;
    readonly tools: readonly Record<string, unknown>[];
    readonly requestIndex: number;
  }) => OpenAiModelFixtureMessage | Promise<OpenAiModelFixtureMessage>;
}): Promise<OpenAiModelFixture>;
