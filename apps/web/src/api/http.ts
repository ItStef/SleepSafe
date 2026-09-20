export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export type RefreshResult = 'ok' | 'rejected' | 'unavailable';

export interface ResponseSchema<T> {
  parse(data: unknown): T;
}

export interface RequestOptions<T> {
  body?: unknown;
  auth?: boolean;
  schema?: ResponseSchema<T>;
}

export interface HttpClientOptions {
  fetchImpl?: typeof fetch;
  onSessionExpired?: () => void;
}

function errorFrom(data: unknown): { code: string; message: string } {
  if (typeof data === 'object' && data !== null && 'error' in data) {
    const error = (data as { error: unknown }).error;
    if (typeof error === 'object' && error !== null) {
      const { code, message } = error as { code?: unknown; message?: unknown };
      if (typeof code === 'string') {
        return { code, message: typeof message === 'string' ? message : code };
      }
    }
  }
  return { code: 'UNKNOWN', message: 'Unexpected error response' };
}

export class HttpClient {
  private accessToken: string | null = null;
  private refreshing: Promise<RefreshResult> | null = null;
  private readonly fetchImpl: typeof fetch;
  onSessionExpired: (() => void) | undefined;

  constructor(options: HttpClientOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? ((input, init) => globalThis.fetch(input, init));
    this.onSessionExpired = options.onSessionExpired;
  }

  setAccessToken(token: string | null): void {
    this.accessToken = token;
  }

  async request<T = void>(
    method: string,
    path: string,
    options: RequestOptions<T> = {},
  ): Promise<T> {
    const auth = options.auth ?? true;
    let response = await this.send(method, path, options.body, auth);

    if (response.status === 401 && auth && this.accessToken !== null) {
      const result = await this.refreshSession();
      if (result === 'ok') {
        response = await this.send(method, path, options.body, auth);
      } else if (result === 'unavailable') {
        throw new ApiError(0, 'NETWORK', 'Network error');
      }
    }
    return this.parse(response, options.schema);
  }

  refreshSession(): Promise<RefreshResult> {
    this.refreshing ??= this.doRefresh().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private async doRefresh(): Promise<RefreshResult> {
    let response: Response;
    try {
      response = await this.send('POST', '/auth/refresh', undefined, false);
    } catch {
      return 'unavailable';
    }
    if (response.ok) {
      try {
        const data = (await response.json()) as { accessToken?: unknown };
        if (typeof data.accessToken !== 'string') {
          return 'unavailable';
        }
        this.accessToken = data.accessToken;
        return 'ok';
      } catch {
        return 'unavailable';
      }
    }
    if (response.status === 401 || response.status === 403) {
      this.accessToken = null;
      this.onSessionExpired?.();
      return 'rejected';
    }
    return 'unavailable';
  }

  private async send(
    method: string,
    path: string,
    body: unknown,
    auth: boolean,
  ): Promise<Response> {
    const headers: Record<string, string> = {};
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
    }
    if (auth && this.accessToken !== null) {
      headers['authorization'] = `Bearer ${this.accessToken}`;
    }
    try {
      return await this.fetchImpl(path, {
        method,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        credentials: 'same-origin',
        cache: 'no-store',
      });
    } catch {
      throw new ApiError(0, 'NETWORK', 'Network error');
    }
  }

  private async parse<T>(response: Response, schema: ResponseSchema<T> | undefined): Promise<T> {
    if (response.status === 204) {
      return undefined as T;
    }
    const text = await response.text();
    let data: unknown;
    try {
      data = text === '' ? undefined : JSON.parse(text);
    } catch {
      data = undefined;
    }
    if (!response.ok) {
      const { code, message } = errorFrom(data);
      throw new ApiError(response.status, code, message);
    }
    if (!schema) {
      return data as T;
    }
    try {
      return schema.parse(data);
    } catch {
      throw new ApiError(response.status, 'BAD_RESPONSE', 'Malformed response');
    }
  }
}
