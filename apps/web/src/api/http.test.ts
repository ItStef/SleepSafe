import { describe, expect, it, vi } from 'vitest';
import { ApiError, HttpClient } from './http';

interface Recorded {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | undefined;
  credentials: string | undefined;
  cache: string | undefined;
}

type Reply = Response | Error;

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

function fakeFetch(...replies: (Reply | ((request: Recorded) => Reply))[]) {
  const requests: Recorded[] = [];
  const impl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request: Recorded = {
      url: String(input),
      method: init?.method ?? 'GET',
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body as string | undefined,
      credentials: init?.credentials,
      cache: init?.cache,
    };
    requests.push(request);
    const next = replies.shift();
    if (next === undefined) throw new Error(`Unexpected request to ${request.url}`);
    const reply = typeof next === 'function' ? next(request) : next;
    if (reply instanceof Error) throw reply;
    return reply;
  });
  return { impl: impl as unknown as typeof fetch, requests };
}

const ok = (accessToken: string) => json(200, { accessToken, expiresIn: 900 });
const unauthorized = () =>
  json(401, { error: { code: 'UNAUTHENTICATED', message: 'Invalid or expired token' } });

describe('HttpClient', () => {
  it('salje JSON, bez keširanja i sa kolacicima samo istog izvora', async () => {
    const { impl, requests } = fakeFetch(json(200, { x: 1 }));
    const http = new HttpClient({ fetchImpl: impl });
    const result = await http.request<{ x: number }>('POST', '/auth/prelogin', {
      auth: false,
      body: { email: 'a@example.com' },
    });
    expect(result).toEqual({ x: 1 });
    expect(requests[0]).toMatchObject({
      url: '/auth/prelogin',
      method: 'POST',
      body: JSON.stringify({ email: 'a@example.com' }),
      credentials: 'same-origin',
      cache: 'no-store',
    });
    expect(requests[0]?.headers['content-type']).toBe('application/json');
  });

  it('pristupni token salje samo kad zahtev to trazi', async () => {
    const { impl, requests } = fakeFetch(json(200, {}), json(200, {}), json(200, {}));
    const http = new HttpClient({ fetchImpl: impl });
    http.setAccessToken('tajni-token');
    await http.request('GET', '/auth/me');
    await http.request('POST', '/auth/login', { auth: false, body: {} });
    http.setAccessToken(null);
    await http.request('GET', '/auth/me');

    expect(requests[0]?.headers['authorization']).toBe('Bearer tajni-token');
    expect(requests[1]?.headers['authorization']).toBeUndefined();
    expect(requests[2]?.headers['authorization']).toBeUndefined();
  });

  it('GET nema telo ni content-type', async () => {
    const { impl, requests } = fakeFetch(json(200, {}));
    await new HttpClient({ fetchImpl: impl }).request('GET', '/auth/me');
    expect(requests[0]?.body).toBeUndefined();
    expect(requests[0]?.headers['content-type']).toBeUndefined();
  });

  it('odgovor 204 vraca undefined', async () => {
    const { impl } = fakeFetch(new Response(null, { status: 204 }));
    const result = await new HttpClient({ fetchImpl: impl }).request('POST', '/auth/logout');
    expect(result).toBeUndefined();
  });

  it('greska servera postaje ApiError sa kodom', async () => {
    const { impl } = fakeFetch(
      json(401, { error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' } }),
    );
    const http = new HttpClient({ fetchImpl: impl });
    await expect(
      http.request('POST', '/auth/login', { auth: false, body: {} }),
    ).rejects.toMatchObject({
      name: 'ApiError',
      status: 401,
      code: 'INVALID_CREDENTIALS',
    });
  });

  it('odgovor koji nije JSON daje UNKNOWN, a pad mreze daje NETWORK', async () => {
    const { impl } = fakeFetch(
      new Response('<html>Bad gateway</html>', { status: 502 }),
      new TypeError('Failed to fetch'),
    );
    const http = new HttpClient({ fetchImpl: impl });
    await expect(http.request('GET', '/health', { auth: false })).rejects.toMatchObject({
      status: 502,
      code: 'UNKNOWN',
    });
    await expect(http.request('GET', '/health', { auth: false })).rejects.toMatchObject({
      status: 0,
      code: 'NETWORK',
    });
  });

  it('odgovor koji ne odgovara sema ugovoru se odbacuje (BAD_RESPONSE)', async () => {
    const { impl } = fakeFetch(json(200, { neocekivano: true }));
    const schema = {
      parse: (data: unknown) => {
        if (typeof data === 'object' && data !== null && 'accessToken' in data) return data;
        throw new Error('bad');
      },
    };
    await expect(
      new HttpClient({ fetchImpl: impl }).request('GET', '/x', { auth: false, schema }),
    ).rejects.toMatchObject({ code: 'BAD_RESPONSE' });
  });

  describe('obnavljanje pristupnog tokena', () => {
    it('istekao token: obnovi ga jednom i ponovi zahtev sa novim', async () => {
      const { impl, requests } = fakeFetch(
        unauthorized(),
        ok('novi-token'),
        json(200, { ime: 'x' }),
      );
      const http = new HttpClient({ fetchImpl: impl });
      http.setAccessToken('stari-token');

      const result = await http.request<{ ime: string }>('GET', '/auth/me');
      expect(result).toEqual({ ime: 'x' });
      expect(requests.map((r) => r.url)).toEqual(['/auth/me', '/auth/refresh', '/auth/me']);
      expect(requests[0]?.headers['authorization']).toBe('Bearer stari-token');
      expect(requests[1]?.headers['authorization']).toBeUndefined();
      expect(requests[2]?.headers['authorization']).toBe('Bearer novi-token');
    });

    it('vise istovremenih zahteva deli JEDNO obnavljanje', async () => {
      const refreshCalls: string[] = [];
      // Server prihvata samo aktuelni token; klijent krece sa zastarelim.
      let token = 'aktuelni';
      const impl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const headers = (init?.headers ?? {}) as Record<string, string>;
        if (url === '/auth/refresh') {
          refreshCalls.push(url);
          await new Promise((resolve) => setTimeout(resolve, 20));
          token = 'obnovljeni';
          return ok('obnovljeni');
        }
        return headers['authorization'] === `Bearer ${token}` ? json(200, { url }) : unauthorized();
      }) as unknown as typeof fetch;

      const http = new HttpClient({ fetchImpl: impl });
      http.setAccessToken('stari');
      const results = await Promise.all([
        http.request('GET', '/a'),
        http.request('GET', '/b'),
        http.request('GET', '/c'),
      ]);
      expect(results).toEqual([{ url: '/a' }, { url: '/b' }, { url: '/c' }]);
      expect(refreshCalls).toHaveLength(1);
    });

    it('odbijeno obnavljanje: odjavljuje korisnika, brise token i vraca originalnu gresku', async () => {
      const { impl, requests } = fakeFetch(unauthorized(), unauthorized(), json(200, {}));
      const onSessionExpired = vi.fn();
      const http = new HttpClient({ fetchImpl: impl, onSessionExpired });
      http.setAccessToken('stari');

      await expect(http.request('GET', '/auth/me')).rejects.toMatchObject({
        status: 401,
        code: 'UNAUTHENTICATED',
      });
      expect(onSessionExpired).toHaveBeenCalledTimes(1);

      await http.request('GET', '/auth/me');
      expect(requests[2]?.headers['authorization']).toBeUndefined();
    });

    it('server nedostupan pri obnavljanju: NETWORK, bez odjave', async () => {
      const { impl } = fakeFetch(unauthorized(), new Response('greska', { status: 500 }));
      const onSessionExpired = vi.fn();
      const http = new HttpClient({ fetchImpl: impl, onSessionExpired });
      http.setAccessToken('stari');

      await expect(http.request('GET', '/auth/me')).rejects.toMatchObject({ code: 'NETWORK' });
      expect(onSessionExpired).not.toHaveBeenCalled();
    });

    it('ponavlja zahtev samo jednom: druga 401 posle obnavljanja je greska, bez petlje', async () => {
      const { impl, requests } = fakeFetch(unauthorized(), ok('novi'), unauthorized());
      const http = new HttpClient({ fetchImpl: impl });
      http.setAccessToken('stari');
      await expect(http.request('GET', '/auth/me')).rejects.toBeInstanceOf(ApiError);
      expect(requests).toHaveLength(3);
    });

    it('401 bez pristupnog tokena (npr. pogresna lozinka) ne pokrece obnavljanje', async () => {
      const { impl, requests } = fakeFetch(
        json(401, { error: { code: 'INVALID_CREDENTIALS', message: 'x' } }),
      );
      const http = new HttpClient({ fetchImpl: impl });
      await expect(
        http.request('POST', '/auth/login', { auth: false, body: {} }),
      ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
      expect(requests).toHaveLength(1);
    });

    it('refreshSession() sam postavlja token koji se koristi u sledecim zahtevima', async () => {
      const { impl, requests } = fakeFetch(ok('iz-kolacica'), json(200, {}));
      const http = new HttpClient({ fetchImpl: impl });
      expect(await http.refreshSession()).toBe('ok');
      await http.request('GET', '/auth/me');
      expect(requests[1]?.headers['authorization']).toBe('Bearer iz-kolacica');
    });

    it('refreshSession() razlikuje odbijeno (401) od nedostupnog servera', async () => {
      const { impl } = fakeFetch(unauthorized(), new TypeError('offline'));
      const http = new HttpClient({ fetchImpl: impl });
      expect(await http.refreshSession()).toBe('rejected');
      expect(await http.refreshSession()).toBe('unavailable');
    });
  });
});
