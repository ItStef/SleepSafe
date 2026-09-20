import {
  decryptItem,
  deriveKeys,
  encryptItem,
  fromBase64Url,
  unwrapVaultKey,
} from '@sleepsafe/crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { signAccessToken } from '../security';
import { REFRESH_REUSE_GRACE_MS } from '../sessions';
import {
  APP_ORIGIN,
  REFRESH_COOKIE,
  type TestEnv,
  bearer,
  createTestEnv,
  logIn,
  refreshWith,
  registerVerified,
} from './support';

const PASSWORD = 'moja tajna lozinka';
const DAY = 24 * 60 * 60 * 1000;

describe.skipIf(!process.env['DATABASE_URL'])('sesije: me, refresh i logout', () => {
  let env: TestEnv;
  let registration: Awaited<ReturnType<typeof registerVerified>>;

  beforeAll(async () => {
    env = await createTestEnv();
    registration = await registerVerified(env, env.newEmail(), PASSWORD);
  });

  afterAll(async () => {
    await env.close();
  });

  const me = (accessToken?: string) =>
    env.app.inject({
      method: 'GET',
      url: '/auth/me',
      headers: accessToken === undefined ? {} : bearer(accessToken),
    });

  const logout = (refreshToken?: string, origin: string | null = APP_ORIGIN) =>
    env.app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: origin === null ? {} : { origin },
      ...(refreshToken === undefined ? {} : { cookies: { [REFRESH_COOKIE]: refreshToken } }),
    });

  const unauthenticated = {
    error: { code: 'UNAUTHENTICATED', message: 'Invalid or expired token' },
  };

  describe('GET /auth/me', () => {
    it('cela tacka kraj-do-kraja: prijava, otkljucavanje vaulta i desifrovanje stavke', async () => {
      const { accessToken } = await logIn(env, registration);
      const response = await me(accessToken);
      expect(response.statusCode).toBe(200);

      const profile = response.json();
      expect(Object.keys(profile).sort()).toEqual([
        'email',
        'id',
        'kdfIterations',
        'kdfMemoryKiB',
        'kdfParallelism',
        'kdfSalt',
        'wrappedVaultKey',
      ]);
      expect(profile.email).toBe(registration.body.email);

      const { kek } = await deriveKeys(PASSWORD, fromBase64Url(profile.kdfSalt), {
        memoryKiB: profile.kdfMemoryKiB,
        iterations: profile.kdfIterations,
        parallelism: profile.kdfParallelism,
      });
      const vaultKey = await unwrapVaultKey(profile.wrappedVaultKey, kek);

      const context = { userId: profile.id, itemId: 'stavka-1' };
      const stored = await encryptItem(vaultKey, { site: 'primer.rs', password: 'tajna' }, context);
      expect(await decryptItem(vaultKey, stored, context)).toEqual({
        site: 'primer.rs',
        password: 'tajna',
      });
    });

    it('nikad ne vraca heš Auth kljuca ni tajne servera', async () => {
      const { accessToken } = await logIn(env, registration);
      const text = (await me(accessToken)).body;
      const user = await env.prisma.user.findUniqueOrThrow({
        where: { email: registration.body.email },
      });
      expect(text).not.toContain(user.authHash);
      expect(text).not.toContain(registration.body.authKey);
    });

    it('bez tokena, sa pogresnim oblikom ili sa tudjim potpisom daje ISTU 401 gresku', async () => {
      const { accessToken } = await logIn(env, registration);
      const forged = await signAccessToken(
        { userId: 'x', sessionId: 'y' },
        'z'.repeat(40),
        900,
        new Date(),
      );
      const requests = [
        me(),
        env.app.inject({ method: 'GET', url: '/auth/me', headers: { authorization: 'Bearer' } }),
        env.app.inject({
          method: 'GET',
          url: '/auth/me',
          headers: { authorization: `Basic ${accessToken}` },
        }),
        env.app.inject({
          method: 'GET',
          url: '/auth/me',
          headers: { authorization: `bearer ${accessToken}` },
        }),
        me('nije.jwt'),
        me(forged),
        me(`${accessToken}x`),
      ];
      for (const response of await Promise.all(requests)) {
        expect(response.statusCode).toBe(401);
        expect(response.json()).toEqual(unauthenticated);
      }
    });

    it('istekao pristupni token se odbija', async () => {
      const { accessToken } = await logIn(env, registration);
      expect((await me(accessToken)).statusCode).toBe(200);
      env.advance((env.config.ACCESS_TOKEN_TTL_SECONDS + 1) * 1000);
      const response = await me(accessToken);
      expect(response.statusCode).toBe(401);
      expect(response.json()).toEqual(unauthenticated);
    });

    it('ispravan token sa ponistenom ili isteklom sesijom se odbija', async () => {
      const revoked = await logIn(env, registration);
      await env.prisma.session.updateMany({
        where: { user: { email: registration.body.email } },
        data: { revokedAt: new Date() },
      });
      expect((await me(revoked.accessToken)).statusCode).toBe(401);

      const expired = await logIn(env, registration);
      await env.prisma.session.updateMany({
        where: { user: { email: registration.body.email }, revokedAt: null },
        data: { expiresAt: new Date(Date.now() - 1000) },
      });
      expect((await me(expired.accessToken)).statusCode).toBe(401);
    });

    it('odgovori se ne kesiraju', async () => {
      const { accessToken } = await logIn(env, registration);
      expect((await me(accessToken)).headers['cache-control']).toBe('no-store');
      expect((await me()).headers['cache-control']).toBe('no-store');
    });
  });

  describe('POST /auth/refresh', () => {
    it('menja refresh token novim i vraca radni pristupni token', async () => {
      const { refreshToken } = await logIn(env, registration);
      const response = await refreshWith(env, refreshToken);
      expect(response.statusCode).toBe(200);

      const body = response.json<{ accessToken: string; expiresIn: number }>();
      expect(Object.keys(body).sort()).toEqual(['accessToken', 'expiresIn']);
      const cookie = response.cookies.find((item) => item.name === REFRESH_COOKIE);
      expect(cookie?.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(cookie?.value).not.toBe(refreshToken);
      expect(cookie).toMatchObject({ httpOnly: true, sameSite: 'Strict', path: '/auth' });

      expect((await me(body.accessToken)).statusCode).toBe(200);
      env.advance(60_000);
      expect((await refreshWith(env, cookie?.value ?? '')).statusCode).toBe(200);
    });

    it('produzava sesiju od trenutka obnavljanja', async () => {
      const { refreshToken } = await logIn(env, registration);
      env.advance(2 * DAY);
      const response = await refreshWith(env, refreshToken);
      expect(response.statusCode).toBe(200);
      const newToken = response.cookies.find((item) => item.name === REFRESH_COOKIE)?.value ?? '';
      const [session] = await env.prisma.session.findMany({
        where: { user: { email: registration.body.email } },
        orderBy: { lastUsedAt: 'desc' },
        take: 1,
      });
      expect(newToken).not.toBe('');
      if (!session) throw new Error('no session');
      expect(session.expiresAt.getTime() - session.lastUsedAt.getTime()).toBe(
        env.config.SESSION_TTL_DAYS * DAY,
      );
      expect(session.lastUsedAt.getTime() - session.createdAt.getTime()).toBeGreaterThanOrEqual(
        2 * DAY - 1000,
      );
    });

    it('ponovna upotreba starog tokena posle roka ponistava sesiju i brise kolacic', async () => {
      const { accessToken, refreshToken } = await logIn(env, registration);
      const first = await refreshWith(env, refreshToken);
      const stolenSideToken = first.cookies.find((item) => item.name === REFRESH_COOKIE)?.value;

      env.advance(REFRESH_REUSE_GRACE_MS + 1000);
      const replay = await refreshWith(env, refreshToken);
      expect(replay.statusCode).toBe(401);
      expect(replay.json()).toEqual({
        error: { code: 'UNAUTHENTICATED', message: 'Invalid or expired session' },
      });
      const cleared = replay.cookies.find((item) => item.name === REFRESH_COOKIE);
      expect(cleared?.value).toBe('');

      expect((await refreshWith(env, stolenSideToken ?? '')).statusCode).toBe(401);
      expect((await me(accessToken)).statusCode).toBe(401);
    });

    it('ponovna upotreba unutar roka je bezopasna: 401, ali sesija i kolacic ostaju', async () => {
      const { accessToken, refreshToken } = await logIn(env, registration);
      const first = await refreshWith(env, refreshToken);
      const newToken = first.cookies.find((item) => item.name === REFRESH_COOKIE)?.value ?? '';

      env.advance(REFRESH_REUSE_GRACE_MS - 2000);
      const replay = await refreshWith(env, refreshToken);
      expect(replay.statusCode).toBe(401);
      expect(replay.cookies.find((item) => item.name === REFRESH_COOKIE)).toBeUndefined();
      expect((await me(accessToken)).statusCode).toBe(200);
      expect((await refreshWith(env, newToken)).statusCode).toBe(200);
    });

    it('dva istovremena zahteva: uspeva jedan, a sesija ostaje ziva', async () => {
      const { accessToken, refreshToken } = await logIn(env, registration);
      const responses = await Promise.all([
        refreshWith(env, refreshToken),
        refreshWith(env, refreshToken),
        refreshWith(env, refreshToken),
      ]);
      expect(responses.map((response) => response.statusCode).sort()).toEqual([200, 401, 401]);
      expect((await me(accessToken)).statusCode).toBe(200);
    });

    it('odbija zahtev bez Origin zaglavlja ili sa tudjim poreklom (CSRF zastita)', async () => {
      const { refreshToken } = await logIn(env, registration);
      for (const origin of [null, 'https://evil.example', 'http://localhost:5174', 'null']) {
        const response = await refreshWith(env, refreshToken, origin);
        expect(response.statusCode).toBe(403);
        expect(response.json().error.code).toBe('FORBIDDEN');
      }
      expect((await refreshWith(env, refreshToken)).statusCode).toBe(200);
    });

    it('odbija zahtev bez kolacica, sa pokvarenim ili nepoznatim tokenom', async () => {
      const noCookie = await env.app.inject({
        method: 'POST',
        url: '/auth/refresh',
        headers: { origin: APP_ORIGIN },
      });
      expect(noCookie.statusCode).toBe(401);

      for (const token of ['x', '', 'A'.repeat(42), `${'A'.repeat(42)}+`, 'A'.repeat(43)]) {
        const response = await refreshWith(env, token);
        expect(response.statusCode).toBe(401);
        expect(response.json().error.code).toBe('UNAUTHENTICATED');
      }
    });

    it('token iz tela ili zaglavlja se ne prihvata, samo kolacic', async () => {
      const { refreshToken } = await logIn(env, registration);
      const response = await env.app.inject({
        method: 'POST',
        url: '/auth/refresh',
        headers: { origin: APP_ORIGIN, authorization: `Bearer ${refreshToken}` },
        payload: { refreshToken },
      });
      expect(response.statusCode).toBe(401);
    });
  });

  describe('POST /auth/logout', () => {
    it('ponistava sesiju na serveru i brise kolacic', async () => {
      const { accessToken, refreshToken } = await logIn(env, registration);
      const response = await logout(refreshToken);
      expect(response.statusCode).toBe(204);
      expect(response.body).toBe('');
      expect(response.cookies.find((item) => item.name === REFRESH_COOKIE)?.value).toBe('');

      expect((await me(accessToken)).statusCode).toBe(401);
      expect((await refreshWith(env, refreshToken)).statusCode).toBe(401);
    });

    it('je idempotentna i uspeva i bez kolacica', async () => {
      const { refreshToken } = await logIn(env, registration);
      expect((await logout(refreshToken)).statusCode).toBe(204);
      expect((await logout(refreshToken)).statusCode).toBe(204);
      expect((await logout()).statusCode).toBe(204);
      expect((await logout('A'.repeat(43))).statusCode).toBe(204);
    });

    it('odbija zahtev sa tudjim ili bez porekla i ne ponistava sesiju', async () => {
      const { accessToken, refreshToken } = await logIn(env, registration);
      for (const origin of [null, 'https://evil.example']) {
        expect((await logout(refreshToken, origin)).statusCode).toBe(403);
      }
      expect((await me(accessToken)).statusCode).toBe(200);
    });

    it('odjava jednog uredjaja ne dira drugi', async () => {
      const laptop = await logIn(env, registration);
      const phone = await logIn(env, registration);
      await logout(laptop.refreshToken);
      expect((await me(laptop.accessToken)).statusCode).toBe(401);
      expect((await me(phone.accessToken)).statusCode).toBe(200);
      expect((await refreshWith(env, phone.refreshToken)).statusCode).toBe(200);
    });
  });
});
