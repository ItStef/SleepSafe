import { randomUUID } from 'node:crypto';
import {
  decryptItem,
  deriveKeys,
  encryptItem,
  fromBase64Url,
  unwrapVaultKey,
} from '@sleepsafe/crypto';
import type { SessionInfo, SyncItem } from '@sleepsafe/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  CLIENT_KDF,
  type TestEnv,
  bearer,
  createTestEnv,
  logIn,
  prepareNewPassword,
  registerVerified,
} from './support';

const PASSWORD = 'moja tajna lozinka';
const NEW_PASSWORD = 'potpuno nova lozinka';

type Registration = Awaited<ReturnType<typeof registerVerified>>;
type Account = Registration & { userId: string; accessToken: string; refreshToken: string };

describe.skipIf(!process.env['DATABASE_URL'])('nalog: lozinka, sesije, brisanje', () => {
  let env: TestEnv;

  async function newAccount(target: TestEnv = env): Promise<Account> {
    const registration = await registerVerified(target, target.newEmail(), PASSWORD);
    const tokens = await logIn(target, registration);
    const user = await target.prisma.user.findUniqueOrThrow({
      where: { email: registration.body.email },
    });
    return { ...registration, userId: user.id, ...tokens };
  }

  async function anotherDevice(account: Registration, target: TestEnv = env) {
    return logIn(target, account);
  }

  beforeAll(async () => {
    env = await createTestEnv();
  });

  afterAll(async () => {
    await env.close();
  });

  const call = (
    token: string | null,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    url: string,
    payload?: object,
    target: TestEnv = env,
    headers: Record<string, string> = {},
  ) =>
    target.app.inject({
      method,
      url,
      headers: { ...(token ? bearer(token) : {}), ...headers },
      ...(payload === undefined ? {} : { payload }),
    });

  const me = (token: string) => call(token, 'GET', '/auth/me');

  const invalidPassword = { error: { code: 'INVALID_PASSWORD', message: 'Invalid password' } };

  async function tryLogin(target: TestEnv, email: string, authKey: string) {
    return target.app.inject({ method: 'POST', url: '/auth/login', payload: { email, authKey } });
  }

  describe('POST /auth/change-password', () => {
    it('cela tacka: menja lozinku, a vault i dalje radi i sa novom lozinkom', async () => {
      const account = await newAccount();
      const itemId = randomUUID();
      const secret = { site: 'banka.example', password: 'lozinka-iz-vaulta' };
      const sealed = await encryptItem(account.vaultKey, secret, {
        userId: account.userId,
        itemId,
      });
      await call(account.accessToken, 'PUT', `/vault/items/${itemId}`, {
        envelope: sealed,
        baseRevision: null,
      });
      const other = await anotherDevice(account);
      const mailsBefore = env.mailer.sent.length;

      const { payload, next } = await prepareNewPassword(account, NEW_PASSWORD);
      const response = await call(account.accessToken, 'POST', '/auth/change-password', payload);
      expect(response.statusCode).toBe(204);
      expect(response.body).toBe('');

      expect(env.mailer.sent).toHaveLength(mailsBefore + 1);
      expect(env.mailer.last?.to).toBe(account.body.email);
      expect(env.mailer.last?.subject).toBe('SleepSafe: master lozinka je promenjena');

      const oldLogin = await tryLogin(env, account.body.email, account.body.authKey);
      expect(oldLogin.statusCode).toBe(401);
      const fresh = await logIn(env, next);

      expect((await me(other.accessToken)).statusCode).toBe(401);
      expect((await me(account.accessToken)).statusCode).toBe(200);

      const profile = (await me(fresh.accessToken)).json();
      expect(profile.kdfSalt).toBe(payload.kdfSalt);
      expect(profile.wrappedVaultKey).toEqual(payload.wrappedVaultKey);
      const { kek } = await deriveKeys(NEW_PASSWORD, fromBase64Url(profile.kdfSalt), {
        memoryKiB: profile.kdfMemoryKiB,
        iterations: profile.kdfIterations,
        parallelism: profile.kdfParallelism,
      });
      const vaultKey = await unwrapVaultKey(profile.wrappedVaultKey, kek);
      const item = (
        await call(fresh.accessToken, 'GET', `/vault/items/${itemId}`)
      ).json<SyncItem>();
      if (!item.envelope) throw new Error('missing envelope');
      expect(await decryptItem(vaultKey, item.envelope, { userId: profile.id, itemId })).toEqual(
        secret,
      );
    });

    it('server cuva samo novi heš, nikad novi Auth kljuc ni lozinku', async () => {
      const account = await newAccount();
      const { payload } = await prepareNewPassword(account, NEW_PASSWORD);
      await call(account.accessToken, 'POST', '/auth/change-password', payload);

      const user = await env.prisma.user.findUniqueOrThrow({ where: { id: account.userId } });
      const stored = JSON.stringify(user);
      expect(stored).not.toContain(payload.newAuthKey);
      expect(stored).not.toContain(NEW_PASSWORD);
      expect(stored).not.toContain(account.body.authKey);
      expect(user.authHash).toHaveLength(43);
    });

    it('pogresna trenutna lozinka: 403, nista se ne menja, nikog ne odjavljuje, bez emaila', async () => {
      const account = await newAccount();
      const other = await anotherDevice(account);
      const before = await env.prisma.user.findUniqueOrThrow({ where: { id: account.userId } });
      const mails = env.mailer.sent.length;

      const wrong = await prepareNewPassword(
        { ...account, body: { ...account.body, authKey: 'x'.repeat(43) } },
        NEW_PASSWORD,
      );
      const response = await call(account.accessToken, 'POST', '/auth/change-password', {
        ...wrong.payload,
        currentAuthKey: 'x'.repeat(43),
      });
      expect(response.statusCode).toBe(403);
      expect(response.json()).toEqual(invalidPassword);

      const after = await env.prisma.user.findUniqueOrThrow({ where: { id: account.userId } });
      expect(after.authHash).toBe(before.authHash);
      expect(after.wrappedVaultKey).toEqual(before.wrappedVaultKey);
      expect((await me(other.accessToken)).statusCode).toBe(200);
      expect(env.mailer.sent).toHaveLength(mails);
    });

    it('sama ukradena sesija ne moze da promeni lozinku, a neuspesi se broje kao pri prijavi', async () => {
      const limited = await createTestEnv({ LOGIN_MAX_FAILURES: '3' });
      try {
        const account = await newAccount(limited);
        const { payload } = await prepareNewPassword(account, NEW_PASSWORD);
        const wrongPayload = { ...payload, currentAuthKey: 'y'.repeat(43) };

        for (let i = 0; i < 3; i++) {
          const response = await call(
            account.accessToken,
            'POST',
            '/auth/change-password',
            wrongPayload,
            limited,
          );
          expect(response.statusCode).toBe(403);
        }
        const blocked = await call(
          account.accessToken,
          'POST',
          '/auth/change-password',
          payload,
          limited,
        );
        expect(blocked.statusCode).toBe(429);
        expect(blocked.json().error.code).toBe('TOO_MANY_ATTEMPTS');
        const login = await tryLogin(limited, account.body.email, account.body.authKey);
        expect(login.statusCode).toBe(429);
      } finally {
        await limited.close();
      }
    });

    it('trazi prijavu (401 bez tokena i sa ponistenom sesijom)', async () => {
      const account = await newAccount();
      const { payload } = await prepareNewPassword(account, NEW_PASSWORD);
      expect((await call(null, 'POST', '/auth/change-password', payload)).statusCode).toBe(401);

      await env.prisma.session.updateMany({
        where: { userId: account.userId },
        data: { revokedAt: new Date() },
      });
      const response = await call(account.accessToken, 'POST', '/auth/change-password', payload);
      expect(response.statusCode).toBe(401);
      const user = await env.prisma.user.findUniqueOrThrow({ where: { id: account.userId } });
      expect(user.kdfSalt).toBe(account.body.kdfSalt);
    });

    it('odbija slabe KDF parametre, dodatna i nedostajuca polja, i nista ne menja', async () => {
      const account = await newAccount();
      const { payload } = await prepareNewPassword(account, NEW_PASSWORD);
      const bad: object[] = [
        { ...payload, kdfMemoryKiB: 1024 },
        { ...payload, kdfIterations: 1 },
        { ...payload, kdfParallelism: 64 },
        { ...payload, password: NEW_PASSWORD },
        { ...payload, newAuthKey: 'kratak' },
        { ...payload, wrappedVaultKey: { ...payload.wrappedVaultKey, ct: 'x' } },
        { currentAuthKey: payload.currentAuthKey },
        {},
      ];
      for (const body of bad) {
        const response = await call(account.accessToken, 'POST', '/auth/change-password', body);
        expect(response.statusCode).toBe(400);
        expect(response.json().error.code).toBe('VALIDATION_ERROR');
      }
      const user = await env.prisma.user.findUniqueOrThrow({ where: { id: account.userId } });
      expect(user.kdfSalt).toBe(account.body.kdfSalt);
      expect(user.kdfMemoryKiB).toBe(CLIENT_KDF.memoryKiB);
    });

    it('kod za prijavu poslat pre promene lozinke vise ne vazi', async () => {
      const account = await newAccount();
      const started = await tryLogin(env, account.body.email, account.body.authKey);
      const challengeId = started.json<{ challengeId: string }>().challengeId;
      const code = /\b(\d{6})\b/.exec(env.mailer.last?.text ?? '')?.[1] ?? '';

      const { payload } = await prepareNewPassword(account, NEW_PASSWORD);
      expect(
        (await call(account.accessToken, 'POST', '/auth/change-password', payload)).statusCode,
      ).toBe(204);

      const verify = await env.app.inject({
        method: 'POST',
        url: '/auth/verify-otp',
        payload: { challengeId, code },
      });
      expect(verify.statusCode).toBe(400);
    });

    it('trka: dva zahteva prodju proveru lozinke pre upisa, a uspeva tacno jedan', async () => {
      const account = await newAccount();
      const attempts = [
        await prepareNewPassword(account, 'prva nova lozinka'),
        await prepareNewPassword(account, 'druga nova lozinka'),
      ];

      const prisma = env.prisma as unknown as {
        $transaction: (...args: unknown[]) => Promise<unknown>;
      };
      const original = prisma.$transaction;
      let arrived = 0;
      let open!: () => void;
      const gate = new Promise<void>((resolve) => (open = resolve));
      prisma.$transaction = async (...args) => {
        arrived += 1;
        if (arrived === 2) open();
        await gate;
        return original.apply(env.prisma, args);
      };

      let responses;
      try {
        responses = await Promise.all(
          attempts.map((attempt) =>
            call(account.accessToken, 'POST', '/auth/change-password', attempt.payload),
          ),
        );
      } finally {
        prisma.$transaction = original;
      }
      expect(responses.map((r) => r.statusCode).sort()).toEqual([204, 403]);

      const winnerIndex = responses.findIndex((r) => r.statusCode === 204);
      const winner = attempts[winnerIndex];
      const loser = attempts[1 - winnerIndex];
      if (!winner || !loser) throw new Error('missing attempt');

      const user = await env.prisma.user.findUniqueOrThrow({ where: { id: account.userId } });
      expect(user.kdfSalt).toBe(winner.payload.kdfSalt);
      expect((await logIn(env, winner.next)).accessToken).toBeTruthy();
      expect((await tryLogin(env, account.body.email, loser.payload.newAuthKey)).statusCode).toBe(
        401,
      );
    });
  });

  describe('sesije', () => {
    const list = async (token: string) =>
      (await call(token, 'GET', '/auth/sessions')).json<{ sessions: SessionInfo[] }>().sessions;

    it('prikazuje aktivne sesije i oznacava trenutnu', async () => {
      const account = await newAccount();
      const phone = await anotherDevice(account);

      const fromLaptop = await list(account.accessToken);
      expect(fromLaptop).toHaveLength(2);
      expect(fromLaptop.filter((s) => s.current)).toHaveLength(1);

      const fromPhone = await list(phone.accessToken);
      const currentOnLaptop = fromLaptop.find((s) => s.current)?.id;
      const currentOnPhone = fromPhone.find((s) => s.current)?.id;
      expect(currentOnLaptop).not.toBe(currentOnPhone);

      for (const session of fromLaptop) {
        expect(Object.keys(session).sort()).toEqual([
          'createdAt',
          'current',
          'id',
          'lastUsedAt',
          'userAgent',
        ]);
      }
    });

    it('ne prikazuje ponistene ni istekle sesije, ni tudje', async () => {
      const account = await newAccount();
      const revoked = await anotherDevice(account);
      const expired = await anotherDevice(account);
      const stranger = await newAccount();

      const all = await env.prisma.session.findMany({
        where: { userId: account.userId },
        orderBy: { createdAt: 'asc' },
      });
      await env.prisma.session.update({
        where: { id: all[1]?.id ?? '' },
        data: { revokedAt: new Date() },
      });
      await env.prisma.session.update({
        where: { id: all[2]?.id ?? '' },
        data: { expiresAt: new Date(0) },
      });

      const visible = await list(account.accessToken);
      expect(visible).toHaveLength(1);
      expect(visible[0]?.current).toBe(true);
      expect((await me(revoked.accessToken)).statusCode).toBe(401);
      expect((await me(expired.accessToken)).statusCode).toBe(401);

      const strangerIds = (await list(stranger.accessToken)).map((s) => s.id);
      expect(visible.some((s) => strangerIds.includes(s.id))).toBe(false);
    });

    it('cuva User-Agent uredjaja', async () => {
      const account = await newAccount();
      const started = await tryLogin(env, account.body.email, account.body.authKey);
      const code = /\b(\d{6})\b/.exec(env.mailer.last?.text ?? '')?.[1] ?? '';
      await env.app.inject({
        method: 'POST',
        url: '/auth/verify-otp',
        headers: { 'user-agent': 'Firefox/999 (Test OS)' },
        payload: { challengeId: started.json<{ challengeId: string }>().challengeId, code },
      });
      const sessions = await list(account.accessToken);
      expect(sessions.map((s) => s.userAgent)).toContain('Firefox/999 (Test OS)');
    });

    it('ponistavanje odjavljuje taj uredjaj odmah, a ostale ne dira', async () => {
      const account = await newAccount();
      const phone = await anotherDevice(account);
      const phoneSession = (await list(phone.accessToken)).find((s) => s.current);

      const response = await call(
        account.accessToken,
        'DELETE',
        `/auth/sessions/${phoneSession?.id}`,
      );
      expect(response.statusCode).toBe(204);
      expect((await me(phone.accessToken)).statusCode).toBe(401);
      expect((await me(account.accessToken)).statusCode).toBe(200);
    });

    it('tudja i nepostojeca sesija: isti odgovor (204), a tudja ostaje netaknuta', async () => {
      const account = await newAccount();
      const stranger = await newAccount();
      const strangerSession = (await list(stranger.accessToken))[0];

      const foreign = await call(
        account.accessToken,
        'DELETE',
        `/auth/sessions/${strangerSession?.id}`,
      );
      const missing = await call(account.accessToken, 'DELETE', `/auth/sessions/${randomUUID()}`);
      expect(foreign.statusCode).toBe(204);
      expect(missing.statusCode).toBe(204);
      expect((await me(stranger.accessToken)).statusCode).toBe(200);

      const invalid = await call(account.accessToken, 'DELETE', '/auth/sessions/nije-uuid');
      expect(invalid.statusCode).toBe(400);
    });

    it('moze da ponisti i sopstvenu trenutnu sesiju', async () => {
      const account = await newAccount();
      const current = (await list(account.accessToken)).find((s) => s.current);
      await call(account.accessToken, 'DELETE', `/auth/sessions/${current?.id}`);
      expect((await me(account.accessToken)).statusCode).toBe(401);
    });

    it('odjava svih ostalih ostavlja samo trenutnu sesiju', async () => {
      const account = await newAccount();
      const phone = await anotherDevice(account);
      const tablet = await anotherDevice(account);
      const stranger = await newAccount();

      const response = await call(account.accessToken, 'POST', '/auth/sessions/revoke-others');
      expect(response.statusCode).toBe(204);

      expect((await me(account.accessToken)).statusCode).toBe(200);
      expect((await me(phone.accessToken)).statusCode).toBe(401);
      expect((await me(tablet.accessToken)).statusCode).toBe(401);
      expect(await list(account.accessToken)).toHaveLength(1);
      expect((await me(stranger.accessToken)).statusCode).toBe(200);
    });

    it('sve rute za sesije traze prijavu', async () => {
      const responses = [
        await call(null, 'GET', '/auth/sessions'),
        await call(null, 'DELETE', `/auth/sessions/${randomUUID()}`),
        await call(null, 'POST', '/auth/sessions/revoke-others'),
      ];
      for (const response of responses) {
        expect(response.statusCode).toBe(401);
      }
    });
  });

  describe('POST /auth/delete-account', () => {
    it('pogresna lozinka: 403 i nalog ostaje', async () => {
      const account = await newAccount();
      const response = await call(account.accessToken, 'POST', '/auth/delete-account', {
        authKey: 'z'.repeat(43),
      });
      expect(response.statusCode).toBe(403);
      expect(response.json()).toEqual(invalidPassword);
      expect(await env.prisma.user.count({ where: { id: account.userId } })).toBe(1);
      expect((await me(account.accessToken)).statusCode).toBe(200);
    });

    it('trajno brise nalog, stavke, sesije i kodove, a tudje podatke ne dira', async () => {
      const account = await newAccount();
      const stranger = await newAccount();
      const itemId = randomUUID();
      const envelope = await encryptItem(
        account.vaultKey,
        { x: 1 },
        { userId: account.userId, itemId },
      );
      await call(account.accessToken, 'PUT', `/vault/items/${itemId}`, {
        envelope,
        baseRevision: null,
      });
      const strangerItem = randomUUID();
      await call(stranger.accessToken, 'PUT', `/vault/items/${strangerItem}`, {
        envelope: await encryptItem(
          stranger.vaultKey,
          { y: 2 },
          { userId: stranger.userId, itemId: strangerItem },
        ),
        baseRevision: null,
      });
      await tryLogin(env, account.body.email, account.body.authKey);
      const mails = env.mailer.sent.length;

      const response = await call(account.accessToken, 'POST', '/auth/delete-account', {
        authKey: account.body.authKey,
      });
      expect(response.statusCode).toBe(204);

      const where = { userId: account.userId };
      expect(await env.prisma.user.count({ where: { id: account.userId } })).toBe(0);
      expect(await env.prisma.vaultItem.count({ where })).toBe(0);
      expect(await env.prisma.session.count({ where })).toBe(0);
      expect(await env.prisma.otpChallenge.count({ where })).toBe(0);

      expect(env.mailer.sent).toHaveLength(mails + 1);
      expect(env.mailer.last?.to).toBe(account.body.email);
      expect(env.mailer.last?.subject).toBe('SleepSafe: nalog je obrisan');

      expect((await me(account.accessToken)).statusCode).toBe(401);
      const login = await tryLogin(env, account.body.email, account.body.authKey);
      expect(login.statusCode).toBe(401);
      expect(login.json().error.code).toBe('INVALID_CREDENTIALS');

      expect((await me(stranger.accessToken)).statusCode).toBe(200);
      expect(
        (await call(stranger.accessToken, 'GET', `/vault/items/${strangerItem}`)).statusCode,
      ).toBe(200);
    });

    it('isti email se moze ponovo registrovati, ali stari podaci ne postoje', async () => {
      const account = await newAccount();
      const itemId = randomUUID();
      await call(account.accessToken, 'PUT', `/vault/items/${itemId}`, {
        envelope: await encryptItem(account.vaultKey, {}, { userId: account.userId, itemId }),
        baseRevision: null,
      });
      await call(account.accessToken, 'POST', '/auth/delete-account', {
        authKey: account.body.authKey,
      });

      const again = await registerVerified(env, account.body.email, PASSWORD);
      const tokens = await logIn(env, again);
      const profile = (await me(tokens.accessToken)).json();
      expect(profile.id).not.toBe(account.userId);
      const list = await call(tokens.accessToken, 'GET', '/vault/items');
      expect(list.json().items).toEqual([]);
    });

    it('drugi poziv sa istim tokenom ne uspeva (sesija je obrisana)', async () => {
      const account = await newAccount();
      const body = { authKey: account.body.authKey };
      expect(
        (await call(account.accessToken, 'POST', '/auth/delete-account', body)).statusCode,
      ).toBe(204);
      expect(
        (await call(account.accessToken, 'POST', '/auth/delete-account', body)).statusCode,
      ).toBe(401);
    });

    it('trazi prijavu, ispravan zahtev i deli brojac neuspeha sa prijavom', async () => {
      expect(
        (await call(null, 'POST', '/auth/delete-account', { authKey: 'A'.repeat(43) })).statusCode,
      ).toBe(401);

      const limited = await createTestEnv({ LOGIN_MAX_FAILURES: '2' });
      try {
        const account = await newAccount(limited);
        for (const payload of [{}, { authKey: 'kratak' }, { authKey: 'A'.repeat(43), x: 1 }]) {
          const response = await call(
            account.accessToken,
            'POST',
            '/auth/delete-account',
            payload,
            limited,
          );
          expect(response.statusCode).toBe(400);
        }
        for (let i = 0; i < 2; i++) {
          await call(
            account.accessToken,
            'POST',
            '/auth/delete-account',
            { authKey: 'q'.repeat(43) },
            limited,
          );
        }
        const blocked = await call(
          account.accessToken,
          'POST',
          '/auth/delete-account',
          { authKey: account.body.authKey },
          limited,
        );
        expect(blocked.statusCode).toBe(429);
        expect(await limited.prisma.user.count({ where: { id: account.userId } })).toBe(1);
      } finally {
        await limited.close();
      }
    });
  });
});
