import { randomUUID } from 'node:crypto';
import {
  type RecoveryKeys,
  createVault,
  decryptItem,
  deriveKeys,
  deriveRecoveryKeys,
  encryptItem,
  formatRecoveryCode,
  generateRecoveryCodes,
  generateSalt,
  recoveryAuthToString,
  rewrapVaultKey,
  toBase64Url,
  unwrapVaultKey,
  wrapVaultKey,
} from '@sleepsafe/crypto';
import type { RecoveryBundle, RecoveryVerifyResponse, SyncItem } from '@sleepsafe/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  CLIENT_KDF,
  type TestEnv,
  bearer,
  codeFrom,
  createTestEnv,
  fakeRecoveryBundle,
  logIn,
} from './support';

const PASSWORD = 'moja tajna lozinka';
const NEW_PASSWORD = 'potpuno nova lozinka';

describe.skipIf(!process.env['DATABASE_URL'])('oporavak naloga kodovima', () => {
  let env: TestEnv;
  let vaultKey: CryptoKey; // izvoziv, isti u svim nalozima ovog testa
  let codes: string[];
  let keys: RecoveryKeys[];
  let bundle: RecoveryBundle;
  let recoverySalt: Uint8Array;

  // Jednom za ceo fajl: 20 pravih izvodjenja. Server ne moze da razlikuje isti skup u drugom nalogu.
  beforeAll(async () => {
    env = await createTestEnv();
    const master = await deriveKeys('pomocna', generateSalt(), CLIENT_KDF);
    const created = await createVault(master.kek);
    vaultKey = await unwrapVaultKey(created.wrappedVaultKey, master.kek, { extractable: true });

    codes = generateRecoveryCodes(20);
    recoverySalt = generateSalt();
    keys = [];
    for (const code of codes) keys.push(await deriveRecoveryKeys(code, recoverySalt, CLIENT_KDF));
    bundle = {
      kdfSalt: toBase64Url(recoverySalt),
      kdfMemoryKiB: CLIENT_KDF.memoryKiB,
      kdfIterations: CLIENT_KDF.iterations,
      kdfParallelism: CLIENT_KDF.parallelism,
      codes: await Promise.all(
        keys.map(async (key) => ({
          authKey: recoveryAuthToString(key.authKey),
          wrappedVaultKey: (await wrapVaultKey(vaultKey, key.kek)) as never,
        })),
      ),
    };
  });

  afterAll(async () => {
    await env.close();
  });

  const post = (url: string, payload: unknown, token?: string, target: TestEnv = env) =>
    target.app.inject({
      method: 'POST',
      url,
      payload: payload as object,
      ...(token ? { headers: bearer(token) } : {}),
    });
  const get = (url: string, token: string) =>
    env.app.inject({ method: 'GET', url, headers: bearer(token) });

  async function registerBody(email: string, password: string, recovery: unknown = bundle) {
    const recoveryBody = recovery as RecoveryBundle;
    const salt = generateSalt();
    const { authKey, kek } = await deriveKeys(password, salt, CLIENT_KDF);
    const wrappedVaultKey = await wrapVaultKey(vaultKey, kek);
    return {
      body: {
        email,
        authKey: toBase64Url(authKey),
        kdfSalt: toBase64Url(salt),
        kdfMemoryKiB: CLIENT_KDF.memoryKiB,
        kdfIterations: CLIENT_KDF.iterations,
        kdfParallelism: CLIENT_KDF.parallelism,
        wrappedVaultKey,
        recovery: recoveryBody,
      },
      kek,
    };
  }

  async function newAccount(target: TestEnv = env, password = PASSWORD) {
    const email = target.newEmail();
    const registration = await registerBody(email, password);
    const response = await post('/auth/register', registration.body, undefined, target);
    const { challengeId } = response.json<{ challengeId: string }>();
    await post(
      '/auth/verify-email',
      { challengeId, code: codeFrom(target.mailer.last) },
      undefined,
      target,
    );
    const user = await target.prisma.user.findUniqueOrThrow({ where: { email } });
    return { email, password, userId: user.id, ...registration };
  }

  // Ceo tok kao klijent: start, kod iz emaila, verify, otvaranje omotaca, nova lozinka.
  async function recover(
    account: { email: string },
    index: number,
    target: TestEnv = env,
    newPassword = NEW_PASSWORD,
  ) {
    const start = await post('/auth/recovery/start', { email: account.email }, undefined, target);
    const started = start.json<{ challengeId: string }>();
    const verify = await post(
      '/auth/recovery/verify',
      { challengeId: started.challengeId, code: codeFrom(target.mailer.last) },
      undefined,
      target,
    );
    const verified = verify.json<RecoveryVerifyResponse>();

    const mine = keys[index];
    if (!mine) throw new Error('missing key');
    let matched:
      | { id: string; wrappedVaultKey: RecoveryVerifyResponse['codes'][number]['wrappedVaultKey'] }
      | undefined;
    for (const candidate of verified.codes) {
      try {
        await unwrapVaultKey(candidate.wrappedVaultKey, mine.kek);
        matched = candidate;
        break;
      } catch {
        // taj omotac pripada drugom kodu
      }
    }
    if (!matched) throw new Error('no blob for this code');

    const salt = generateSalt();
    const next = await deriveKeys(newPassword, salt, CLIENT_KDF);
    const wrappedVaultKey = await rewrapVaultKey(matched.wrappedVaultKey, mine.kek, next.kek);
    const payload = {
      resetId: verified.resetId,
      resetToken: verified.resetToken,
      codeId: matched.id,
      recoveryAuth: recoveryAuthToString(mine.authKey),
      newAuthKey: toBase64Url(next.authKey),
      kdfSalt: toBase64Url(salt),
      kdfMemoryKiB: CLIENT_KDF.memoryKiB,
      kdfIterations: CLIENT_KDF.iterations,
      kdfParallelism: CLIENT_KDF.parallelism,
      wrappedVaultKey,
    };
    return { verified, payload, next, started };
  }

  const loginWith = (email: string, authKey: string, target: TestEnv = env) =>
    post('/auth/login', { email, authKey }, undefined, target);

  describe('registracija sa kodovima', () => {
    it('cuva 20 kodova samo kao HMAC, nikad sam dokaz ni omotac u otvorenom obliku', async () => {
      const account = await newAccount();
      const rows = await env.prisma.recoveryCode.findMany({ where: { userId: account.userId } });
      expect(rows).toHaveLength(20);
      expect(rows.every((row) => row.usedAt === null)).toBe(true);

      const stored = JSON.stringify(rows.map((row) => row.codeHash));
      for (const code of bundle.codes) expect(stored).not.toContain(code.authKey);
      for (const row of rows) expect(row.codeHash).toHaveLength(43);

      const user = await env.prisma.user.findUniqueOrThrow({ where: { id: account.userId } });
      expect(user.recoverySalt).toBe(bundle.kdfSalt);
      expect(user.recoveryKdfMemoryKiB).toBe(CLIENT_KDF.memoryKiB);
    });

    it('bez kodova, sa pogresnim brojem, duplikatima ili slabim parametrima: 400 i nista se ne upisuje', async () => {
      const email = env.newEmail();
      const cases: unknown[] = [
        undefined,
        { ...bundle, codes: bundle.codes.slice(0, 19) },
        { ...bundle, codes: [...bundle.codes.slice(0, 19), bundle.codes[0]] },
        { ...bundle, kdfMemoryKiB: 1024 },
        { ...bundle, kdfIterations: 1 },
        { ...bundle, extra: 1 },
      ];
      for (const recovery of cases) {
        const { body } = await registerBody(email, PASSWORD, recovery);
        const payload = recovery === undefined ? { ...body, recovery: undefined } : body;
        const response = await post('/auth/register', payload);
        expect(response.statusCode).toBe(400);
      }
      expect(await env.prisma.user.count({ where: { email } })).toBe(0);
    });

    it('ponovna registracija nepotvrdjenog naloga zamenjuje skup, ne dupla ga', async () => {
      const email = env.newEmail();
      const first = await registerBody(email, PASSWORD);
      await post('/auth/register', first.body);
      const second = await registerBody(email, PASSWORD, fakeRecoveryBundle());
      expect((await post('/auth/register', second.body)).statusCode).toBe(202);

      const user = await env.prisma.user.findUniqueOrThrow({ where: { email } });
      const rows = await env.prisma.recoveryCode.findMany({ where: { userId: user.id } });
      expect(rows).toHaveLength(20);
      expect(user.recoverySalt).toBe(second.body.recovery.kdfSalt);
    });

    it('greska pri upisu kodova ne ostavlja nalog bez njih (sve ili nista)', async () => {
      const email = env.newEmail();
      const { body } = await registerBody(email, PASSWORD);
      const client = env.prisma as unknown as {
        $transaction: (...args: unknown[]) => Promise<unknown>;
      };
      const original = client.$transaction;
      // Unutar transakcije upis kodova pada, posle upisa naloga.
      client.$transaction = (work: unknown, ...rest: unknown[]) =>
        typeof work !== 'function'
          ? original.call(env.prisma, work, ...rest)
          : original.call(
              env.prisma,
              (tx: object) =>
                (work as (t: object) => Promise<unknown>)(
                  new Proxy(tx, {
                    get(target, property, receiver) {
                      if (property === 'recoveryCode') {
                        return {
                          deleteMany: async () => ({ count: 0 }),
                          createMany: async () => {
                            throw new Error('disk pun');
                          },
                        };
                      }
                      return Reflect.get(target, property, receiver);
                    },
                  }),
                ),
              ...rest,
            );
      try {
        expect((await post('/auth/register', body)).statusCode).toBe(500);
      } finally {
        client.$transaction = original;
      }
      expect(await env.prisma.user.count({ where: { email } })).toBe(0);
    });
  });

  describe('POST /auth/recovery/start', () => {
    it('za pravi nalog: 202, kod stize na email, a odgovor nosi njegove parametre', async () => {
      const account = await newAccount();
      const mails = env.mailer.sent.length;
      const response = await post('/auth/recovery/start', { email: account.email });
      expect(response.statusCode).toBe(202);
      const body = response.json();
      expect(body).toMatchObject({
        kdfSalt: bundle.kdfSalt,
        kdfMemoryKiB: bundle.kdfMemoryKiB,
        kdfIterations: bundle.kdfIterations,
        kdfParallelism: bundle.kdfParallelism,
      });
      expect(env.mailer.sent).toHaveLength(mails + 1);
      expect(env.mailer.last?.to).toBe(account.email);
      expect(env.mailer.last?.subject).toBe('SleepSafe: kod za oporavak naloga');
      expect(codeFrom(env.mailer.last)).toMatch(/^\d{6}$/);
    });

    it('nepostojeci, nepotvrdjen i nalog bez kodova: isti oblik odgovora, bez emaila', async () => {
      const unverified = env.newEmail();
      await post('/auth/register', (await registerBody(unverified, PASSWORD)).body);
      const noCodes = await newAccount();
      await env.prisma.recoveryCode.deleteMany({ where: { userId: noCodes.userId } });

      const mails = env.mailer.sent.length;
      const shape = (r: { json: () => Record<string, unknown> }) => Object.keys(r.json()).sort();
      const real = await post('/auth/recovery/start', { email: (await newAccount()).email });
      const responses = [
        await post('/auth/recovery/start', { email: env.newEmail() }),
        await post('/auth/recovery/start', { email: unverified }),
        await post('/auth/recovery/start', { email: noCodes.email }),
      ];
      const mailsAfterReal = mails + 2; // jedan za newAccount (verifikacija) i jedan za pravi start
      for (const response of responses) {
        expect(response.statusCode).toBe(202);
        expect(shape(response)).toEqual(shape(real));
      }
      expect(env.mailer.sent).toHaveLength(mailsAfterReal);
    });

    it('lazna so je stalna za istu adresu, a razlicita za razlicite', async () => {
      const a = env.newEmail();
      const b = env.newEmail();
      const first = (await post('/auth/recovery/start', { email: a })).json<{ kdfSalt: string }>();
      const again = (await post('/auth/recovery/start', { email: a })).json<{ kdfSalt: string }>();
      const other = (await post('/auth/recovery/start', { email: b })).json<{ kdfSalt: string }>();
      expect(first.kdfSalt).toBe(again.kdfSalt);
      expect(first.kdfSalt).not.toBe(other.kdfSalt);
    });

    it('kad su svi kodovi iskorisceni, nalog izgleda kao da ih nema', async () => {
      const account = await newAccount();
      await env.prisma.recoveryCode.updateMany({
        where: { userId: account.userId },
        data: { usedAt: new Date() },
      });
      const mails = env.mailer.sent.length;
      expect((await post('/auth/recovery/start', { email: account.email })).statusCode).toBe(202);
      expect(env.mailer.sent).toHaveLength(mails);
    });

    it('odbija neispravnu adresu i dodatna polja, a blokirana adresa dobija 429', async () => {
      expect((await post('/auth/recovery/start', { email: 'nije-email' })).statusCode).toBe(400);
      expect(
        (await post('/auth/recovery/start', { email: 'a@example.com', x: 1 })).statusCode,
      ).toBe(400);

      const limited = await createTestEnv({ LOGIN_MAX_FAILURES: '2' });
      try {
        const email = limited.newEmail();
        for (let i = 0; i < 2; i++) {
          await post('/auth/login', { email, authKey: 'x'.repeat(43) }, undefined, limited);
        }
        const blocked = await post('/auth/recovery/start', { email }, undefined, limited);
        expect(blocked.statusCode).toBe(429);
      } finally {
        await limited.close();
      }
    });
  });

  describe('POST /auth/recovery/verify', () => {
    it('tacan kod daje token i omotace samo neiskoriscenih kodova', async () => {
      const account = await newAccount();
      const used = await env.prisma.recoveryCode.findFirstOrThrow({
        where: { userId: account.userId },
      });
      await env.prisma.recoveryCode.update({
        where: { id: used.id },
        data: { usedAt: new Date() },
      });

      const start = await post('/auth/recovery/start', { email: account.email });
      const verify = await post('/auth/recovery/verify', {
        challengeId: start.json<{ challengeId: string }>().challengeId,
        code: codeFrom(env.mailer.last),
      });
      expect(verify.statusCode).toBe(200);
      const body = verify.json<RecoveryVerifyResponse>();
      expect(body.codes).toHaveLength(19);
      expect(body.codes.some((code) => code.id === used.id)).toBe(false);
      expect(body.resetToken).toHaveLength(43);
    });

    it('pogresan i ponovljen kod, nepoznat challenge i kod za drugu namenu se odbijaju', async () => {
      const account = await newAccount();
      const start = await post('/auth/recovery/start', { email: account.email });
      const { challengeId } = start.json<{ challengeId: string }>();
      const code = codeFrom(env.mailer.last);
      const wrong = code === '000000' ? '111111' : '000000';

      expect((await post('/auth/recovery/verify', { challengeId, code: wrong })).statusCode).toBe(
        400,
      );
      expect((await post('/auth/recovery/verify', { challengeId, code })).statusCode).toBe(200);
      expect((await post('/auth/recovery/verify', { challengeId, code })).statusCode).toBe(400);
      expect(
        (await post('/auth/recovery/verify', { challengeId: randomUUID(), code })).statusCode,
      ).toBe(400);

      // Kod za prijavu ne moze da otvori oporavak.
      const login = await loginWith(account.email, account.body.authKey);
      const loginChallenge = login.json<{ challengeId: string }>().challengeId;
      const loginCode = codeFrom(env.mailer.last);
      expect(
        (await post('/auth/recovery/verify', { challengeId: loginChallenge, code: loginCode }))
          .statusCode,
      ).toBe(400);
    });

    it('posle 5 pogresnih pokusaja kod vise ne radi ni sa tacnim unosom', async () => {
      const account = await newAccount();
      const start = await post('/auth/recovery/start', { email: account.email });
      const { challengeId } = start.json<{ challengeId: string }>();
      const code = codeFrom(env.mailer.last);
      const wrong = code === '000000' ? '111111' : '000000';
      for (let i = 0; i < 5; i++) await post('/auth/recovery/verify', { challengeId, code: wrong });
      expect((await post('/auth/recovery/verify', { challengeId, code })).statusCode).toBe(400);
    });

    it('istekao kod (11 minuta) se odbija', async () => {
      const short = await createTestEnv();
      try {
        const account = await newAccount(short);
        const start = await post(
          '/auth/recovery/start',
          { email: account.email },
          undefined,
          short,
        );
        const code = codeFrom(short.mailer.last);
        short.advance(11 * 60_000);
        const verify = await post(
          '/auth/recovery/verify',
          { challengeId: start.json<{ challengeId: string }>().challengeId, code },
          undefined,
          short,
        );
        expect(verify.statusCode).toBe(400);
      } finally {
        await short.close();
      }
    });
  });

  describe('POST /auth/recovery/reset', () => {
    it('cela tacka: nova lozinka radi, stara ne, sesije su odjavljene, a stavke se i dalje otvaraju', async () => {
      const account = await newAccount();
      const first = await logIn(env, account);
      const itemId = randomUUID();
      const secret = { site: 'banka.example', password: 'lozinka-iz-vaulta' };
      await env.app.inject({
        method: 'PUT',
        url: `/vault/items/${itemId}`,
        headers: bearer(first.accessToken),
        payload: {
          envelope: await encryptItem(vaultKey, secret, { userId: account.userId, itemId }),
          baseRevision: null,
        },
      });
      const mails = env.mailer.sent.length;

      const flow = await recover(account, 3);
      const response = await post('/auth/recovery/reset', flow.payload);
      expect(response.statusCode).toBe(204);

      // Sve sesije su odjavljene, stara lozinka ne radi, nova radi.
      expect((await get('/auth/me', first.accessToken)).statusCode).toBe(401);
      expect((await loginWith(account.email, account.body.authKey)).statusCode).toBe(401);
      const newLogin = await loginWith(account.email, toBase64Url(flow.next.authKey));
      expect(newLogin.statusCode).toBe(202);

      // Vault Key je isti: stavka stara lozinka -> nova lozinka i dalje se desifruje.
      const session = await logIn(env, {
        body: { email: account.email, authKey: toBase64Url(flow.next.authKey) },
      });
      const profile = (await get('/auth/me', session.accessToken)).json();
      const reopened = await unwrapVaultKey(profile.wrappedVaultKey, flow.next.kek);
      const item = (await get(`/vault/items/${itemId}`, session.accessToken)).json<SyncItem>();
      if (!item.envelope) throw new Error('missing envelope');
      expect(await decryptItem(reopened, item.envelope, { userId: profile.id, itemId })).toEqual(
        secret,
      );

      // Obavestenje, iskorisceni kod je potrosen, ostalih 19 vazi.
      const notice = env.mailer.sent.find(
        (mail, i) => i >= mails && mail.subject.includes('resetovana'),
      );
      expect(notice?.to).toBe(account.email);
      const status = (await get('/auth/recovery-codes', session.accessToken)).json();
      expect(status).toMatchObject({ total: 20, remaining: 19 });
    });

    it('server cuva samo hes novog Auth kljuca, nikad lozinku ni dokaz koda', async () => {
      const account = await newAccount();
      const flow = await recover(account, 0);
      await post('/auth/recovery/reset', flow.payload);
      const user = await env.prisma.user.findUniqueOrThrow({ where: { id: account.userId } });
      const rows = await env.prisma.recoveryCode.findMany({ where: { userId: account.userId } });
      const stored = JSON.stringify({ user, rows });
      expect(stored).not.toContain(flow.payload.newAuthKey);
      expect(stored).not.toContain(flow.payload.recoveryAuth);
      expect(stored).not.toContain(NEW_PASSWORD);
      for (const code of codes) expect(stored).not.toContain(formatRecoveryCode(code));
    });

    it('iskoriscen kod ne moze ponovo, a ostali kodovi i dalje rade', async () => {
      const account = await newAccount();
      const first = await recover(account, 5);
      expect((await post('/auth/recovery/reset', first.payload)).statusCode).toBe(204);

      // Isti kod, novi krug: server ga vise ne nudi (19 omotaca), pa ga ni klijent ne nalazi.
      const start = await post('/auth/recovery/start', { email: account.email });
      const verify = await post('/auth/recovery/verify', {
        challengeId: start.json<{ challengeId: string }>().challengeId,
        code: codeFrom(env.mailer.last),
      });
      expect(verify.json<RecoveryVerifyResponse>().codes).toHaveLength(19);
      const forced = {
        ...first.payload,
        resetId: verify.json().resetId,
        resetToken: verify.json().resetToken,
      };
      expect((await post('/auth/recovery/reset', forced)).statusCode).toBe(400);

      // Drugi kod radi.
      const second = await recover(account, 6);
      expect((await post('/auth/recovery/reset', second.payload)).statusCode).toBe(204);
    });

    it('pogresan dokaz koda: 400, kod ostaje neiskoriscen, nista se ne menja', async () => {
      const account = await newAccount();
      const flow = await recover(account, 1);
      const before = await env.prisma.user.findUniqueOrThrow({ where: { id: account.userId } });
      const bad = { ...flow.payload, recoveryAuth: toBase64Url(new Uint8Array(32).fill(7)) };
      const response = await post('/auth/recovery/reset', bad);
      expect(response.statusCode).toBe(400);
      expect(response.json().error.code).toBe('INVALID_RECOVERY');

      const after = await env.prisma.user.findUniqueOrThrow({ where: { id: account.userId } });
      expect(after.authHash).toBe(before.authHash);
      expect(
        await env.prisma.recoveryCode.count({ where: { userId: account.userId, usedAt: null } }),
      ).toBe(20);
      // Pravi dokaz i dalje prolazi (jedan neuspeh je potrosio jedan od 5 pokusaja tokena).
      expect((await post('/auth/recovery/reset', flow.payload)).statusCode).toBe(204);
    });

    it('token se ne moze pogadjati: posle 5 pokusaja ne radi ni sa tacnim dokazom', async () => {
      const account = await newAccount();
      const flow = await recover(account, 2);
      const bad = { ...flow.payload, recoveryAuth: toBase64Url(new Uint8Array(32).fill(9)) };
      for (let i = 0; i < 5; i++)
        expect((await post('/auth/recovery/reset', bad)).statusCode).toBe(400);
      expect((await post('/auth/recovery/reset', flow.payload)).statusCode).toBe(400);
      expect(
        await env.prisma.recoveryCode.count({ where: { userId: account.userId, usedAt: null } }),
      ).toBe(20);
    });

    it('pogresan token, token drugog naloga i kod drugog naloga se odbijaju', async () => {
      const a = await newAccount();
      const b = await newAccount();
      const flowA = await recover(a, 0);
      const flowB = await recover(b, 0);

      const wrongToken = { ...flowA.payload, resetToken: 'x'.repeat(43) };
      expect((await post('/auth/recovery/reset', wrongToken)).statusCode).toBe(400);

      // Token naloga A + kod naloga B (isti dokaz, ali kod pripada B).
      const crossed = { ...flowA.payload, codeId: flowB.payload.codeId };
      expect((await post('/auth/recovery/reset', crossed)).statusCode).toBe(400);
      expect(
        (await post('/auth/recovery/reset', { ...flowA.payload, resetId: randomUUID() }))
          .statusCode,
      ).toBe(400);

      // B nije diran.
      const userB = await env.prisma.user.findUniqueOrThrow({ where: { id: b.userId } });
      expect(userB.kdfSalt).toBe(b.body.kdfSalt);
    });

    it('token je jednokratan i istice posle 10 minuta', async () => {
      const account = await newAccount();
      const flow = await recover(account, 4);
      expect((await post('/auth/recovery/reset', flow.payload)).statusCode).toBe(204);
      expect((await post('/auth/recovery/reset', flow.payload)).statusCode).toBe(400);

      const short = await createTestEnv();
      try {
        const other = await newAccount(short);
        const late = await recover(other, 4, short);
        short.advance(11 * 60_000);
        expect(
          (await post('/auth/recovery/reset', late.payload, undefined, short)).statusCode,
        ).toBe(400);
      } finally {
        await short.close();
      }
    });

    it('novi zahtev za oporavak ponistava raniji token', async () => {
      const account = await newAccount();
      const older = await recover(account, 10);
      const newer = await recover(account, 10);
      expect((await post('/auth/recovery/reset', older.payload)).statusCode).toBe(400);
      expect((await post('/auth/recovery/reset', newer.payload)).statusCode).toBe(204);
    });

    it('kod za prijavu poslat pre promene lozinke vise ne vazi', async () => {
      const account = await newAccount();
      const login = await loginWith(account.email, account.body.authKey);
      const challengeId = login.json<{ challengeId: string }>().challengeId;
      const code = codeFrom(env.mailer.last);

      const flow = await recover(account, 11);
      expect((await post('/auth/recovery/reset', flow.payload)).statusCode).toBe(204);
      expect((await post('/auth/verify-otp', { challengeId, code })).statusCode).toBe(400);
    });

    it('trka: isti token sa dva razlicita koda, uspeva tacno jedan (token vazi za jednu promenu)', async () => {
      const account = await newAccount();
      const first = await recover(account, 13);
      const otherKey = keys[14];
      if (!otherKey) throw new Error('missing key');
      let otherId = '';
      for (const candidate of first.verified.codes) {
        try {
          await unwrapVaultKey(candidate.wrappedVaultKey, otherKey.kek);
          otherId = candidate.id;
          break;
        } catch {
          // omotac drugog koda
        }
      }
      const second = {
        ...first.payload,
        codeId: otherId,
        recoveryAuth: recoveryAuthToString(otherKey.authKey),
        newAuthKey: toBase64Url(new Uint8Array(32).fill(6)),
      };

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
        responses = await Promise.all([
          post('/auth/recovery/reset', first.payload),
          post('/auth/recovery/reset', second),
        ]);
      } finally {
        prisma.$transaction = original;
      }
      expect(responses.map((r) => r.statusCode).sort()).toEqual([204, 400]);
      expect(
        await env.prisma.recoveryCode.count({
          where: { userId: account.userId, usedAt: { not: null } },
        }),
      ).toBe(1);
    });

    it('trka: dva razlicita tokena za isti kod, uspeva tacno jedan', async () => {
      const account = await newAccount();
      const first = await recover(account, 12);
      // Drugi krug bi ponistio prvi token, pa se drugi token pravi rucno, nezavisno od prvog.
      const secondId = randomUUID();
      const { generateResetToken, hashResetToken } = await import('../security');
      const secondToken = generateResetToken();
      await env.prisma.otpChallenge.create({
        data: {
          id: secondId,
          userId: account.userId,
          purpose: 'RECOVERY_RESET',
          codeHash: hashResetToken(secondToken, secondId, 'p'.repeat(32)),
          expiresAt: new Date(Date.now() + 600_000),
        },
      });
      const second = {
        ...first.payload,
        resetId: secondId,
        resetToken: secondToken,
        newAuthKey: toBase64Url(new Uint8Array(32).fill(5)),
      };

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
        responses = await Promise.all([
          post('/auth/recovery/reset', first.payload),
          post('/auth/recovery/reset', second),
        ]);
      } finally {
        prisma.$transaction = original;
      }
      expect(responses.map((r) => r.statusCode).sort()).toEqual([204, 400]);
    });

    it('odbija slabe parametre, dodatna polja i nedostajuca polja, a token ostaje upotrebljiv', async () => {
      const account = await newAccount();
      const flow = await recover(account, 8);
      const bad: object[] = [
        { ...flow.payload, kdfMemoryKiB: 1024 },
        { ...flow.payload, kdfIterations: 1 },
        { ...flow.payload, password: NEW_PASSWORD },
        { ...flow.payload, recoveryAuth: undefined },
        {},
      ];
      for (const payload of bad) {
        expect((await post('/auth/recovery/reset', payload)).statusCode).toBe(400);
      }
      expect((await post('/auth/recovery/reset', flow.payload)).statusCode).toBe(204);
    });

    it('neuspesi se broje kao pri prijavi: posle ogranicenja ni tacan zahtev ne prolazi', async () => {
      const limited = await createTestEnv({ LOGIN_MAX_FAILURES: '3' });
      try {
        const account = await newAccount(limited);
        const flow = await recover(account, 0, limited);
        const bad = { ...flow.payload, recoveryAuth: toBase64Url(new Uint8Array(32).fill(3)) };
        for (let i = 0; i < 3; i++) {
          expect((await post('/auth/recovery/reset', bad, undefined, limited)).statusCode).toBe(
            400,
          );
        }
        const blocked = await post('/auth/recovery/reset', flow.payload, undefined, limited);
        expect(blocked.statusCode).toBe(429);
        expect(blocked.json().error.code).toBe('TOO_MANY_ATTEMPTS');
      } finally {
        await limited.close();
      }
    });

    it('trka: dva zahteva sa istim tokenom, uspeva tacno jedan', async () => {
      const account = await newAccount();
      const flow = await recover(account, 7);
      const second = await deriveKeys('druga nova lozinka', generateSalt(), CLIENT_KDF);
      const otherPayload = {
        ...flow.payload,
        newAuthKey: toBase64Url(second.authKey),
        wrappedVaultKey: await wrapVaultKey(vaultKey, second.kek),
      };

      // Oba prodju sve provere pre upisa, pa samo uslovi u transakciji odlucuju ko pobedjuje.
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
        responses = await Promise.all([
          post('/auth/recovery/reset', flow.payload),
          post('/auth/recovery/reset', otherPayload),
        ]);
      } finally {
        prisma.$transaction = original;
      }
      expect(responses.map((r) => r.statusCode).sort()).toEqual([204, 400]);
      expect(
        await env.prisma.recoveryCode.count({
          where: { userId: account.userId, usedAt: { not: null } },
        }),
      ).toBe(1);
    });
  });

  describe('kodovi za prijavljenog korisnika', () => {
    it('status trazi prijavu i prikazuje ukupno, preostalo i vreme', async () => {
      const account = await newAccount();
      expect(
        (await env.app.inject({ method: 'GET', url: '/auth/recovery-codes' })).statusCode,
      ).toBe(401);
      const session = await logIn(env, account);
      const status = (await get('/auth/recovery-codes', session.accessToken)).json();
      expect(status).toMatchObject({ total: 20, remaining: 20 });
      expect(typeof status.createdAt).toBe('string');
    });

    it('novi skup zamenjuje stari, trazi lozinku i salje obavestenje', async () => {
      const account = await newAccount();
      const session = await logIn(env, account);
      const before = await env.prisma.recoveryCode.findMany({ where: { userId: account.userId } });
      const fresh = fakeRecoveryBundle();
      const mails = env.mailer.sent.length;

      const response = await post(
        '/auth/recovery-codes',
        { currentAuthKey: account.body.authKey, recovery: fresh },
        session.accessToken,
      );
      expect(response.statusCode).toBe(204);
      const after = await env.prisma.recoveryCode.findMany({ where: { userId: account.userId } });
      expect(after).toHaveLength(20);
      const oldHashes = new Set(before.map((row) => row.codeHash));
      expect(after.some((row) => oldHashes.has(row.codeHash))).toBe(false);
      const user = await env.prisma.user.findUniqueOrThrow({ where: { id: account.userId } });
      expect(user.recoverySalt).toBe(fresh.kdfSalt);
      expect(env.mailer.sent).toHaveLength(mails + 1);
      expect(env.mailer.last?.subject).toBe('SleepSafe: napravljeni su novi kodovi za oporavak');
    });

    it('pogresna lozinka: 403 i skup ostaje; bez prijave 401; los zahtev 400', async () => {
      const account = await newAccount();
      const session = await logIn(env, account);
      const before = await env.prisma.recoveryCode.findMany({ where: { userId: account.userId } });

      const wrong = await post(
        '/auth/recovery-codes',
        { currentAuthKey: 'x'.repeat(43), recovery: fakeRecoveryBundle() },
        session.accessToken,
      );
      expect(wrong.statusCode).toBe(403);
      expect(wrong.json().error.code).toBe('INVALID_PASSWORD');
      expect(await env.prisma.recoveryCode.findMany({ where: { userId: account.userId } })).toEqual(
        before,
      );

      expect(
        (
          await post('/auth/recovery-codes', {
            currentAuthKey: account.body.authKey,
            recovery: fakeRecoveryBundle(),
          })
        ).statusCode,
      ).toBe(401);
      const weak = { ...fakeRecoveryBundle(), kdfMemoryKiB: 1024 };
      expect(
        (
          await post(
            '/auth/recovery-codes',
            { currentAuthKey: account.body.authKey, recovery: weak },
            session.accessToken,
          )
        ).statusCode,
      ).toBe(400);
    });

    it('brisanje naloga brise i kodove', async () => {
      const account = await newAccount();
      const session = await logIn(env, account);
      await post('/auth/delete-account', { authKey: account.body.authKey }, session.accessToken);
      expect(await env.prisma.recoveryCode.count({ where: { userId: account.userId } })).toBe(0);
    });
  });
});
