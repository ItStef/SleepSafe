import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { OTP_MAX_ATTEMPTS, OTP_TTL_MINUTES } from '../challenges';
import { hashRefreshToken, verifyAccessToken } from '../security';
import {
  REFRESH_COOKIE,
  type TestEnv,
  codeFrom,
  createTestEnv,
  prepareRegistration,
  registerVerified,
} from './support';

const PASSWORD = 'moja tajna lozinka';

describe.skipIf(!process.env['DATABASE_URL'])('prijava: Auth kljuc, pa kod iz emaila', () => {
  let env: TestEnv;
  let email: string;
  let registration: Awaited<ReturnType<typeof registerVerified>>;

  beforeAll(async () => {
    env = await createTestEnv();
    email = env.newEmail();
    registration = await registerVerified(env, email, PASSWORD);
  });

  afterAll(async () => {
    await env.close();
  });

  const post = (url: string, payload: object, headers: Record<string, string> = {}) =>
    env.app.inject({ method: 'POST', url, payload, headers });

  const login = (payload: object = { email, authKey: registration.body.authKey }) =>
    post('/auth/login', payload);

  const wrongLogin = async () => {
    const other = await prepareRegistration(email, 'pogresna lozinka');
    return login({ email, authKey: other.body.authKey });
  };

  const invalidCredentials = {
    error: { code: 'INVALID_CREDENTIALS', message: 'Invalid email or password' },
  };

  describe('POST /auth/login', () => {
    it('tacan Auth kljuc vraca 202 sa izazovom i salje kod na email', async () => {
      const mailsBefore = env.mailer.sent.length;
      const response = await login();
      expect(response.statusCode).toBe(202);
      expect(Object.keys(response.json())).toEqual(['challengeId']);

      expect(env.mailer.sent).toHaveLength(mailsBefore + 1);
      expect(env.mailer.last?.to).toBe(email);
      expect(env.mailer.last?.subject).toBe('SleepSafe: kod za prijavu');
      expect(codeFrom(env.mailer.last)).toMatch(/^\d{6}$/);
    });

    it('u bazi se cuva samo heš koda, i to za namenu LOGIN', async () => {
      const response = await login();
      const { challengeId } = response.json<{ challengeId: string }>();
      const row = await env.prisma.otpChallenge.findUniqueOrThrow({ where: { id: challengeId } });
      expect(row.purpose).toBe('LOGIN');
      expect(JSON.stringify(row)).not.toContain(codeFrom(env.mailer.last));
    });

    it('pogresan Auth kljuc, nepostojeci i nepotvrdjen nalog dobijaju ISTI odgovor, bez emaila', async () => {
      const mailsBefore = env.mailer.sent.length;

      const wrong = await wrongLogin();

      const ghost = await prepareRegistration(env.newEmail(), PASSWORD);
      const missing = await login({ email: ghost.body.email, authKey: ghost.body.authKey });

      const pendingEmail = env.newEmail();
      const pending = await prepareRegistration(pendingEmail, PASSWORD);
      await post('/auth/register', pending.body);
      const mailsAfterRegister = env.mailer.sent.length;
      const unverified = await login({ email: pendingEmail, authKey: pending.body.authKey });

      for (const response of [wrong, missing, unverified]) {
        expect(response.statusCode).toBe(401);
        expect(response.json()).toEqual(invalidCredentials);
      }
      // Ni jedan neuspeh ne salje kod (registracija je poslala samo svoj).
      expect(mailsAfterRegister).toBe(mailsBefore + 1);
      expect(env.mailer.sent).toHaveLength(mailsAfterRegister);
    });

    it('odbija neispravan zahtev', async () => {
      const bad: object[] = [
        {},
        { email },
        { authKey: registration.body.authKey },
        { email: 'nije-email', authKey: registration.body.authKey },
        { email, authKey: 'kratak' },
        { email, authKey: registration.body.authKey, password: PASSWORD },
      ];
      for (const payload of bad) {
        const response = await login(payload);
        expect(response.statusCode).toBe(400);
        expect(response.json().error.code).toBe('VALIDATION_ERROR');
      }
    });

    it('email se normalizuje (velika slova i razmaci)', async () => {
      const response = await login({
        email: `  ${email.toUpperCase()} `,
        authKey: registration.body.authKey,
      });
      expect(response.statusCode).toBe(202);
    });

    it('novi pokusaj prijave ponistava prethodni izazov', async () => {
      const first = await login();
      const firstCode = codeFrom(env.mailer.last);
      const second = await login();
      const secondCode = codeFrom(env.mailer.last);

      const stale = await post('/auth/verify-otp', {
        challengeId: first.json<{ challengeId: string }>().challengeId,
        code: firstCode,
      });
      expect(stale.statusCode).toBe(400);

      const fresh = await post('/auth/verify-otp', {
        challengeId: second.json<{ challengeId: string }>().challengeId,
        code: secondCode,
      });
      expect(fresh.statusCode).toBe(200);
    });
  });

  describe('POST /auth/verify-otp', () => {
    async function startLogin() {
      const response = await login();
      return {
        challengeId: response.json<{ challengeId: string }>().challengeId,
        code: codeFrom(env.mailer.last),
      };
    }

    it('tacan kod otvara sesiju: token u telu, refresh token samo u kolacicu', async () => {
      const { challengeId, code } = await startLogin();
      const response = await post(
        '/auth/verify-otp',
        { challengeId, code },
        { 'user-agent': 'TestBrowser/1.0' },
      );
      expect(response.statusCode).toBe(200);

      const body = response.json<{ accessToken: string; expiresIn: number }>();
      expect(Object.keys(body).sort()).toEqual(['accessToken', 'expiresIn']);
      expect(body.expiresIn).toBe(900);

      const cookie = response.cookies.find((item) => item.name === REFRESH_COOKIE);
      expect(cookie).toBeDefined();
      expect(cookie?.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(JSON.stringify(body)).not.toContain(cookie?.value ?? 'x');

      const session = await env.prisma.session.findUniqueOrThrow({
        where: {
          refreshTokenHash: hashRefreshToken(cookie?.value ?? '', env.config.SERVER_PEPPER),
        },
      });
      expect(session.userAgent).toBe('TestBrowser/1.0');
      expect(session.revokedAt).toBeNull();

      const claims = await verifyAccessToken(body.accessToken, env.config.JWT_SECRET);
      expect(claims).toEqual({ userId: session.userId, sessionId: session.id });
    });

    it('kolacic je httpOnly, SameSite=Strict, ogranicen na /auth, sa rokom sesije', async () => {
      const { challengeId, code } = await startLogin();
      const response = await post('/auth/verify-otp', { challengeId, code });
      const cookie = response.cookies.find((item) => item.name === REFRESH_COOKIE);
      expect(cookie).toMatchObject({
        httpOnly: true,
        sameSite: 'Strict',
        path: '/auth',
        maxAge: env.config.SESSION_TTL_DAYS * 24 * 60 * 60,
      });
      expect(cookie?.secure).toBeFalsy();
    });

    it('u produkciji kolacic je i Secure', async () => {
      const production = await createTestEnv({
        NODE_ENV: 'production',
        SMTP_TLS: 'starttls',
        LOG_LEVEL: 'silent',
      });
      try {
        const account = await registerVerified(production, production.newEmail(), PASSWORD);
        const started = await production.app.inject({
          method: 'POST',
          url: '/auth/login',
          payload: { email: account.body.email, authKey: account.body.authKey },
        });
        const response = await production.app.inject({
          method: 'POST',
          url: '/auth/verify-otp',
          payload: {
            challengeId: started.json<{ challengeId: string }>().challengeId,
            code: codeFrom(production.mailer.last),
          },
        });
        const cookie = response.cookies.find((item) => item.name === REFRESH_COOKIE);
        expect(cookie?.secure).toBe(true);
        expect(cookie?.httpOnly).toBe(true);
      } finally {
        await production.close();
      }
    });

    it('pogresan kod daje opstu gresku, bez kolacica i bez sesije', async () => {
      const { challengeId, code } = await startLogin();
      const ownSessions = () => env.prisma.session.count({ where: { user: { email } } });
      const sessionsBefore = await ownSessions();
      const response = await post('/auth/verify-otp', {
        challengeId,
        code: code === '000000' ? '000001' : '000000',
      });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({
        error: { code: 'INVALID_CODE', message: 'Invalid or expired code' },
      });
      expect(response.cookies).toHaveLength(0);
      expect(await ownSessions()).toBe(sessionsBefore);
    });

    it(`posle ${OTP_MAX_ATTEMPTS} pogresnih pokusaja izazov je zakljucan i za tacan kod`, async () => {
      const { challengeId, code } = await startLogin();
      const wrong = code === '000000' ? '000001' : '000000';
      for (let i = 0; i < OTP_MAX_ATTEMPTS; i++) {
        await post('/auth/verify-otp', { challengeId, code: wrong });
      }
      const response = await post('/auth/verify-otp', { challengeId, code });
      expect(response.statusCode).toBe(400);
    });

    it('istekao kod se odbija', async () => {
      const { challengeId, code } = await startLogin();
      env.advance((OTP_TTL_MINUTES + 1) * 60_000);
      const response = await post('/auth/verify-otp', { challengeId, code });
      expect(response.statusCode).toBe(400);
    });

    it('kod se ne moze iskoristiti dvaput', async () => {
      const payload = await startLogin();
      expect((await post('/auth/verify-otp', payload)).statusCode).toBe(200);
      expect((await post('/auth/verify-otp', payload)).statusCode).toBe(400);
    });

    it('kod za potvrdu emaila ne moze da otvori sesiju', async () => {
      const fresh = await prepareRegistration(env.newEmail(), PASSWORD);
      const registered = await post('/auth/register', fresh.body);
      const response = await post('/auth/verify-otp', {
        challengeId: registered.json<{ challengeId: string }>().challengeId,
        code: codeFrom(env.mailer.last),
      });
      expect(response.statusCode).toBe(400);
      expect(response.cookies).toHaveLength(0);
    });

    it('odbija neispravan zahtev', async () => {
      const response = await post('/auth/verify-otp', { challengeId: 'nije-uuid', code: '12' });
      expect(response.statusCode).toBe(400);
      expect(response.json().error.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('ogranicenje neuspelih prijava po emailu', () => {
    let limited: TestEnv;
    let account: Awaited<ReturnType<typeof registerVerified>>;

    beforeAll(async () => {
      limited = await createTestEnv({ LOGIN_MAX_FAILURES: '3', LOGIN_LOCKOUT_MINUTES: '15' });
      account = await registerVerified(limited, limited.newEmail(), PASSWORD);
    });

    afterAll(async () => {
      await limited.close();
    });

    const attempt = (address: string, authKey: string) =>
      limited.app.inject({
        method: 'POST',
        url: '/auth/login',
        payload: { email: address, authKey },
      });

    it('posle 3 pogresna pokusaja blokira i tacan kljuc, a posle isteka ponovo radi', async () => {
      const bad = (await prepareRegistration(account.body.email, 'pogresno')).body.authKey;
      for (let i = 0; i < 3; i++) {
        expect((await attempt(account.body.email, bad)).statusCode).toBe(401);
      }

      const blocked = await attempt(account.body.email, account.body.authKey);
      expect(blocked.statusCode).toBe(429);
      expect(blocked.json()).toEqual({
        error: {
          code: 'TOO_MANY_ATTEMPTS',
          message: 'Too many failed attempts, try again later',
        },
      });

      limited.advance(14 * 60_000);
      expect((await attempt(account.body.email, account.body.authKey)).statusCode).toBe(429);
      limited.advance(2 * 60_000);
      expect((await attempt(account.body.email, account.body.authKey)).statusCode).toBe(202);
    });

    it('blokada vazi i za nepostojece emailove, pa se ne vidi ko ima nalog', async () => {
      const ghost = await prepareRegistration(limited.newEmail(), PASSWORD);
      for (let i = 0; i < 3; i++) {
        expect((await attempt(ghost.body.email, ghost.body.authKey)).statusCode).toBe(401);
      }
      expect((await attempt(ghost.body.email, ghost.body.authKey)).statusCode).toBe(429);
    });

    it('blokada jednog emaila ne pogadja druge naloge', async () => {
      const other = await registerVerified(limited, limited.newEmail(), PASSWORD);
      const victim = await prepareRegistration(limited.newEmail(), 'x');
      for (let i = 0; i < 4; i++) {
        await attempt(victim.body.email, victim.body.authKey);
      }
      expect((await attempt(victim.body.email, victim.body.authKey)).statusCode).toBe(429);
      expect((await attempt(other.body.email, other.body.authKey)).statusCode).toBe(202);
    });
  });
});
