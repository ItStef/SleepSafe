import { DEFAULT_KDF_PARAMS } from '@sleepsafe/crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { OTP_TTL_MINUTES } from '../challenges';
import { type TestEnv, codeFrom, createTestEnv, prepareRegistration } from './support';

describe.skipIf(!process.env['DATABASE_URL'])('registracija i potvrda emaila', () => {
  let env: TestEnv;

  beforeAll(async () => {
    env = await createTestEnv();
  });

  afterAll(async () => {
    await env.close();
  });

  const post = (url: string, payload: object) => env.app.inject({ method: 'POST', url, payload });

  async function register(email: string, password = 'moja tajna lozinka') {
    const registration = await prepareRegistration(email, password);
    const response = await post('/auth/register', registration.body);
    return { ...registration, response };
  }

  describe('prelogin', () => {
    it('nepostojeci email dobija stalnu laznu so i podrazumevane parametre', async () => {
      const email = env.newEmail();
      const first = await post('/auth/prelogin', { email });
      const second = await post('/auth/prelogin', { email });
      expect(first.statusCode).toBe(200);
      expect(first.json()).toEqual(second.json());
      expect(first.json()).toMatchObject({
        kdfMemoryKiB: DEFAULT_KDF_PARAMS.memoryKiB,
        kdfIterations: DEFAULT_KDF_PARAMS.iterations,
        kdfParallelism: DEFAULT_KDF_PARAMS.parallelism,
      });
      expect(first.json<{ kdfSalt: string }>().kdfSalt).toMatch(/^[A-Za-z0-9_-]{22}$/);
    });

    it('razlicit email dobija razlicitu laznu so', async () => {
      const a = await post('/auth/prelogin', { email: env.newEmail() });
      const b = await post('/auth/prelogin', { email: env.newEmail() });
      expect(a.json<{ kdfSalt: string }>().kdfSalt).not.toBe(b.json<{ kdfSalt: string }>().kdfSalt);
    });

    it('email se normalizuje (velika slova i razmaci ne prave drugi nalog)', async () => {
      const email = env.newEmail();
      const a = await post('/auth/prelogin', { email });
      const b = await post('/auth/prelogin', { email: `  ${email.toUpperCase()}  ` });
      expect(b.json()).toEqual(a.json());
    });

    it('nepotvrdjen nalog i dalje dobija laznu so; potvrdjen dobija pravu', async () => {
      const email = env.newEmail();
      const before = await post('/auth/prelogin', { email });
      const { body, response } = await register(email);
      const { challengeId } = response.json<{ challengeId: string }>();

      const pending = await post('/auth/prelogin', { email });
      expect(pending.json()).toEqual(before.json());

      await post('/auth/verify-email', { challengeId, code: codeFrom(env.mailer.last) });
      const verified = await post('/auth/prelogin', { email });
      expect(verified.json()).toEqual({
        kdfSalt: body.kdfSalt,
        kdfMemoryKiB: body.kdfMemoryKiB,
        kdfIterations: body.kdfIterations,
        kdfParallelism: body.kdfParallelism,
      });
    });

    it('odbija neispravan zahtev', async () => {
      const response = await post('/auth/prelogin', { email: 'nije-email' });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({
        error: { code: 'VALIDATION_ERROR', message: 'Invalid request' },
      });
    });
  });

  describe('register', () => {
    it('vraca 202 sa izazovom i salje kod na email', async () => {
      const email = env.newEmail();
      const { response } = await register(email);
      expect(response.statusCode).toBe(202);
      expect(Object.keys(response.json())).toEqual(['challengeId']);

      expect(env.mailer.last?.to).toBe(email);
      expect(env.mailer.last?.subject).toBe('SleepSafe: potvrda email adrese');
      expect(codeFrom(env.mailer.last)).toMatch(/^\d{6}$/);
    });

    it('server cuva samo heš Auth kljuca, so, parametre i umotani kljuc, nista drugo', async () => {
      const email = env.newEmail();
      const { body } = await register(email, 'lozinka koju server ne sme da vidi');

      const user = await env.prisma.user.findUniqueOrThrow({ where: { email } });
      expect(user.emailVerifiedAt).toBeNull();
      expect(user.authHash).not.toBe(body.authKey);
      expect(user.authHash).toHaveLength(43);
      expect(user.kdfSalt).toBe(body.kdfSalt);
      expect(user.wrappedVaultKey).toEqual(body.wrappedVaultKey);

      const everything = JSON.stringify(user);
      expect(everything).not.toContain(body.authKey);
      expect(everything).not.toContain('lozinka koju server ne sme da vidi');

      const challenges = await env.prisma.otpChallenge.findMany({ where: { userId: user.id } });
      expect(challenges).toHaveLength(1);
      expect(JSON.stringify(challenges)).not.toContain(codeFrom(env.mailer.last));
    });

    it('vec potvrdjen email dobija isti oblik odgovora, bez emaila i bez izmene naloga', async () => {
      const email = env.newEmail();
      const first = await register(email);
      await post('/auth/verify-email', {
        challengeId: first.response.json<{ challengeId: string }>().challengeId,
        code: codeFrom(env.mailer.last),
      });
      const before = await env.prisma.user.findUniqueOrThrow({ where: { email } });
      const mailsBefore = env.mailer.sent.length;

      const second = await register(email, 'napadacka lozinka');
      expect(second.response.statusCode).toBe(202);
      expect(Object.keys(second.response.json())).toEqual(['challengeId']);
      expect(env.mailer.sent).toHaveLength(mailsBefore);

      const after = await env.prisma.user.findUniqueOrThrow({ where: { email } });
      expect(after.authHash).toBe(before.authHash);
      expect(after.kdfSalt).toBe(before.kdfSalt);
      expect(after.wrappedVaultKey).toEqual(before.wrappedVaultKey);
    });

    it('lazni izazov za postojeci nalog se ne moze resiti', async () => {
      const email = env.newEmail();
      const first = await register(email);
      await post('/auth/verify-email', {
        challengeId: first.response.json<{ challengeId: string }>().challengeId,
        code: codeFrom(env.mailer.last),
      });
      const second = await register(email);
      const wrong = await post('/auth/verify-email', {
        challengeId: second.response.json<{ challengeId: string }>().challengeId,
        code: '123456',
      });
      expect(wrong.statusCode).toBe(400);
      expect(wrong.json()).toEqual({
        error: { code: 'INVALID_CODE', message: 'Invalid or expired code' },
      });
    });

    it('nepotvrdjena registracija se prepisuje: stari kod prestaje da vazi, novi radi', async () => {
      const email = env.newEmail();
      const first = await register(email, 'prva lozinka');
      const firstCode = codeFrom(env.mailer.last);
      const second = await register(email, 'druga lozinka');
      const secondCode = codeFrom(env.mailer.last);

      const stale = await post('/auth/verify-email', {
        challengeId: first.response.json<{ challengeId: string }>().challengeId,
        code: firstCode,
      });
      expect(stale.statusCode).toBe(400);

      const fresh = await post('/auth/verify-email', {
        challengeId: second.response.json<{ challengeId: string }>().challengeId,
        code: secondCode,
      });
      expect(fresh.statusCode).toBe(204);

      const user = await env.prisma.user.findUniqueOrThrow({ where: { email } });
      expect(user.kdfSalt).toBe(second.body.kdfSalt);
    });

    it('odbija slabe KDF parametre i nista ne upisuje u bazu', async () => {
      const email = env.newEmail();
      const { body } = await prepareRegistration(email, 'lozinka');
      for (const weak of [
        { kdfMemoryKiB: 1024 },
        { kdfIterations: 1 },
        { kdfMemoryKiB: 4 * 1024 * 1024 },
        { kdfParallelism: 64 },
      ]) {
        const response = await post('/auth/register', { ...body, ...weak });
        expect(response.statusCode).toBe(400);
        expect(response.json().error.code).toBe('VALIDATION_ERROR');
      }
      expect(await env.prisma.user.count({ where: { email } })).toBe(0);
    });

    it('odbija neispravna i dodatna polja', async () => {
      const email = env.newEmail();
      const { body } = await prepareRegistration(email, 'lozinka');
      const bad: object[] = [
        { ...body, email: 'nije-email' },
        { ...body, authKey: 'kratak' },
        { ...body, password: 'tajna' },
        { ...body, wrappedVaultKey: { ...body.wrappedVaultKey, ct: 'x' } },
        { email },
        [],
      ];
      for (const payload of bad) {
        const response = await post('/auth/register', payload);
        expect(response.statusCode).toBe(400);
      }
      expect(await env.prisma.user.count({ where: { email } })).toBe(0);
    });

    it('odbija telo koje nije JSON ili ga uopste nema', async () => {
      const plainText = await env.app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { 'content-type': 'text/plain' },
        payload: 'lozinka=tajna',
      });
      expect(plainText.statusCode).toBe(400);
      expect(plainText.json().error.code).toBe('VALIDATION_ERROR');

      const form = await env.app.inject({
        method: 'POST',
        url: '/auth/register',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: 'lozinka=tajna',
      });
      expect(form.statusCode).toBe(415);
      expect(form.json().error.code).toBe('BAD_REQUEST');

      const empty = await env.app.inject({ method: 'POST', url: '/auth/register' });
      expect(empty.statusCode).toBe(400);
    });

    it('istovremena registracija istog emaila ne pravi dva naloga ni gresku 500', async () => {
      const email = env.newEmail();
      const [a, b] = await Promise.all([
        prepareRegistration(email, 'prva'),
        prepareRegistration(email, 'druga'),
      ]);
      const responses = await Promise.all([
        post('/auth/register', a.body),
        post('/auth/register', b.body),
      ]);
      for (const response of responses) {
        expect(response.statusCode).toBe(202);
      }
      expect(await env.prisma.user.count({ where: { email } })).toBe(1);
    });
  });

  describe('verify-email', () => {
    it('ispravan kod potvrdjuje email i vraca 204 bez tela', async () => {
      const email = env.newEmail();
      const { response } = await register(email);
      const verify = await post('/auth/verify-email', {
        challengeId: response.json<{ challengeId: string }>().challengeId,
        code: codeFrom(env.mailer.last),
      });
      expect(verify.statusCode).toBe(204);
      expect(verify.body).toBe('');
      const user = await env.prisma.user.findUniqueOrThrow({ where: { email } });
      expect(user.emailVerifiedAt).not.toBeNull();
    });

    it('pogresan kod daje opstu gresku i ne potvrdjuje email', async () => {
      const email = env.newEmail();
      const { response } = await register(email);
      const code = codeFrom(env.mailer.last);
      const verify = await post('/auth/verify-email', {
        challengeId: response.json<{ challengeId: string }>().challengeId,
        code: code === '000000' ? '000001' : '000000',
      });
      expect(verify.statusCode).toBe(400);
      expect(verify.json()).toEqual({
        error: { code: 'INVALID_CODE', message: 'Invalid or expired code' },
      });
      const user = await env.prisma.user.findUniqueOrThrow({ where: { email } });
      expect(user.emailVerifiedAt).toBeNull();
    });

    it('istekao kod se odbija', async () => {
      const email = env.newEmail();
      const { response } = await register(email);
      const code = codeFrom(env.mailer.last);
      env.advance((OTP_TTL_MINUTES + 1) * 60_000);
      const verify = await post('/auth/verify-email', {
        challengeId: response.json<{ challengeId: string }>().challengeId,
        code,
      });
      expect(verify.statusCode).toBe(400);
      const user = await env.prisma.user.findUniqueOrThrow({ where: { email } });
      expect(user.emailVerifiedAt).toBeNull();
    });

    it('kod se ne moze iskoristiti dvaput', async () => {
      const email = env.newEmail();
      const { response } = await register(email);
      const payload = {
        challengeId: response.json<{ challengeId: string }>().challengeId,
        code: codeFrom(env.mailer.last),
      };
      expect((await post('/auth/verify-email', payload)).statusCode).toBe(204);
      expect((await post('/auth/verify-email', payload)).statusCode).toBe(400);
    });

    it('odbija neispravan zahtev', async () => {
      for (const payload of [
        { challengeId: 'nije-uuid', code: '123456' },
        { challengeId: '3f2b8c1e-7a44-4d0b-9a55-1c2d3e4f5a6b', code: '12' },
        {},
      ]) {
        const response = await post('/auth/verify-email', payload);
        expect(response.statusCode).toBe(400);
        expect(response.json().error.code).toBe('VALIDATION_ERROR');
      }
    });
  });

  describe('ogranicenje broja zahteva', () => {
    it('rute prijave imaju strozi limit po IP adresi', async () => {
      const limited = await createTestEnv({ AUTH_RATE_LIMIT_PER_MINUTE: '3' });
      try {
        const send = () =>
          limited.app.inject({
            method: 'POST',
            url: '/auth/prelogin',
            payload: { email: 'a@example.com' },
          });
        for (let i = 0; i < 3; i++) {
          expect((await send()).statusCode).toBe(200);
        }
        const blocked = await send();
        expect(blocked.statusCode).toBe(429);
        expect(blocked.json().error.code).toBe('RATE_LIMITED');
      } finally {
        await limited.close();
      }
    });
  });
});
