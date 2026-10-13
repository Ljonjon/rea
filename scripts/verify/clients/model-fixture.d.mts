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
  }) => unknown;
}): Promise<OpenAiModelFixture>;
