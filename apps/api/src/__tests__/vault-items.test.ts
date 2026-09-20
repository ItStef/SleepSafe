import { randomUUID } from 'node:crypto';
import {
  decryptItem,
  deriveKeys,
  encryptItem,
  fromBase64Url,
  unwrapVaultKey,
} from '@sleepsafe/crypto';
import { MAX_ITEM_CIPHERTEXT_CHARS, type SyncItem } from '@sleepsafe/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type TestEnv, bearer, createTestEnv, logIn, registerVerified } from './support';

const PASSWORD = 'moja tajna lozinka';

type Account = Awaited<ReturnType<typeof registerVerified>> & {
  userId: string;
  accessToken: string;
};

describe.skipIf(!process.env['DATABASE_URL'])('vault: stavke i sinhronizacija', () => {
  let env: TestEnv;
  let alice: Account;
  let bob: Account;

  async function newAccount(target: TestEnv): Promise<Account> {
    const registration = await registerVerified(target, target.newEmail(), PASSWORD);
    const { accessToken } = await logIn(target, registration);
    const user = await target.prisma.user.findUniqueOrThrow({
      where: { email: registration.body.email },
    });
    return { ...registration, userId: user.id, accessToken };
  }

  beforeAll(async () => {
    env = await createTestEnv();
    alice = await newAccount(env);
    bob = await newAccount(env);
  });

  afterAll(async () => {
    await env.close();
  });

  async function seal(account: Account, itemId: string, data: unknown) {
    return encryptItem(account.vaultKey, data, { userId: account.userId, itemId });
  }

  const request = (
    account: Account | null,
    method: 'GET' | 'PUT' | 'DELETE',
    url: string,
    payload?: object,
    target: TestEnv = env,
  ) =>
    target.app.inject({
      method,
      url,
      headers: account ? bearer(account.accessToken) : {},
      ...(payload === undefined ? {} : { payload }),
    });

  async function create(account: Account, data: unknown = { site: 'primer.rs' }, target = env) {
    const id = randomUUID();
    const envelope = await seal(account, id, data);
    const response = await request(
      account,
      'PUT',
      `/vault/items/${id}`,
      { envelope, baseRevision: null },
      target,
    );
    return { id, envelope, response, revision: response.json<{ revision: number }>().revision };
  }

  const list = async (account: Account, query = '') => {
    const response = await request(account, 'GET', `/vault/items${query}`);
    return response.json<{ items: SyncItem[]; cursor: number; hasMore: boolean }>();
  };

  const conflictBody = { error: { code: 'CONFLICT', message: 'Item was modified elsewhere' } };
  const notFoundBody = { error: { code: 'NOT_FOUND', message: 'Not found' } };

  describe('autentikacija', () => {
    it('sve rute traze prijavu', async () => {
      const id = randomUUID();
      const envelope = await seal(alice, id, { a: 1 });
      const responses = [
        await request(null, 'GET', '/vault/items'),
        await request(null, 'GET', `/vault/items/${id}`),
        await request(null, 'PUT', `/vault/items/${id}`, { envelope, baseRevision: null }),
        await request(null, 'DELETE', `/vault/items/${id}`),
      ];
      for (const response of responses) {
        expect(response.statusCode).toBe(401);
        expect(response.json().error.code).toBe('UNAUTHENTICATED');
      }
    });

    it('token ponistene sesije ne otvara vault', async () => {
      const account = await newAccount(env);
      await env.prisma.session.updateMany({
        where: { userId: account.userId },
        data: { revokedAt: new Date() },
      });
      expect((await request(account, 'GET', '/vault/items')).statusCode).toBe(401);
    });
  });

  describe('pravljenje i citanje', () => {
    it('nova stavka: 201 sa ID-jem i revizijom, a u bazi je samo sifrat', async () => {
      const { id, envelope, response } = await create(alice, {
        site: 'tajni-sajt.example',
        password: 'super-tajna-lozinka',
      });
      expect(response.statusCode).toBe(201);
      expect(response.json()).toEqual({ id, revision: expect.any(Number) });

      const row = await env.prisma.vaultItem.findUniqueOrThrow({
        where: { userId_id: { userId: alice.userId, id } },
      });
      expect(row.envelope).toEqual(envelope);
      const stored = JSON.stringify(row);
      expect(stored).not.toContain('tajni-sajt.example');
      expect(stored).not.toContain('super-tajna-lozinka');
    });

    it('revizije rastu za 1 uz svaku izmenu, nezavisno po korisnicima', async () => {
      const fresh = await newAccount(env);
      const first = await create(fresh);
      const second = await create(fresh);
      expect(first.revision).toBe(1);
      expect(second.revision).toBe(2);

      const other = await newAccount(env);
      expect((await create(other)).revision).toBe(1);
    });

    it('GET stavke vraca sifrat, reviziju i vreme izmene', async () => {
      const { id, envelope, revision } = await create(alice);
      const response = await request(alice, 'GET', `/vault/items/${id}`);
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        id,
        revision,
        deleted: false,
        envelope,
        updatedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
      });
    });

    it('nepostojeca stavka je 404, a neispravan ID je 400', async () => {
      const missing = await request(alice, 'GET', `/vault/items/${randomUUID()}`);
      expect(missing.statusCode).toBe(404);
      expect(missing.json()).toEqual(notFoundBody);
      expect((await request(alice, 'GET', '/vault/items/nije-uuid')).statusCode).toBe(400);
    });

    it('stavka sa istim ID-jem se ne moze napraviti dvaput', async () => {
      const { id, envelope } = await create(alice);
      const again = await request(alice, 'PUT', `/vault/items/${id}`, {
        envelope,
        baseRevision: null,
      });
      expect(again.statusCode).toBe(409);
      expect(again.json()).toEqual(conflictBody);
    });
  });

  describe('izmena i konflikti', () => {
    it('izmena sa tacnom revizijom uspeva i podize reviziju', async () => {
      const { id, revision } = await create(alice, { v: 1 });
      const updated = await seal(alice, id, { v: 2 });
      const response = await request(alice, 'PUT', `/vault/items/${id}`, {
        envelope: updated,
        baseRevision: revision,
      });
      expect(response.statusCode).toBe(200);
      expect(response.json().revision).toBeGreaterThan(revision);

      const read = await request(alice, 'GET', `/vault/items/${id}`);
      expect(read.json().envelope).toEqual(updated);
    });

    it('izmena zastarele verzije se odbija (409) i ne menja stavku', async () => {
      const { id, revision } = await create(alice, { v: 1 });
      const winner = await seal(alice, id, { v: 'uredjaj-A' });
      await request(alice, 'PUT', `/vault/items/${id}`, {
        envelope: winner,
        baseRevision: revision,
      });

      const loser = await seal(alice, id, { v: 'uredjaj-B' });
      const response = await request(alice, 'PUT', `/vault/items/${id}`, {
        envelope: loser,
        baseRevision: revision,
      });
      expect(response.statusCode).toBe(409);
      expect(response.json()).toEqual(conflictBody);
      expect((await request(alice, 'GET', `/vault/items/${id}`)).json().envelope).toEqual(winner);
    });

    it('izmena nepostojece stavke je 404', async () => {
      const id = randomUUID();
      const envelope = await seal(alice, id, {});
      const response = await request(alice, 'PUT', `/vault/items/${id}`, {
        envelope,
        baseRevision: 5,
      });
      expect(response.statusCode).toBe(404);
    });

    it('od dve istovremene izmene iste verzije uspeva tacno jedna', async () => {
      const { id, revision } = await create(alice);
      const bodies = await Promise.all(
        ['A', 'B', 'C'].map(async (tag) => ({
          envelope: await seal(alice, id, { tag }),
          baseRevision: revision,
        })),
      );
      const responses = await Promise.all(
        bodies.map((payload) => request(alice, 'PUT', `/vault/items/${id}`, payload)),
      );
      expect(responses.map((r) => r.statusCode).sort()).toEqual([200, 409, 409]);
    });

    it('istovremeno pravljenje istog ID-ja: uspeva tacno jedno', async () => {
      const id = randomUUID();
      const envelope = await seal(alice, id, { x: 1 });
      const responses = await Promise.all(
        Array.from({ length: 5 }, () =>
          request(alice, 'PUT', `/vault/items/${id}`, { envelope, baseRevision: null }),
        ),
      );
      expect(responses.filter((r) => r.statusCode === 201)).toHaveLength(1);
      expect(responses.filter((r) => r.statusCode === 409)).toHaveLength(4);
    });

    it('istovremena pravljenja razlicitih stavki dobijaju razlicite, uzastopne revizije', async () => {
      const fresh = await newAccount(env);
      const results = await Promise.all(Array.from({ length: 15 }, () => create(fresh)));
      expect(results.every((r) => r.response.statusCode === 201)).toBe(true);
      const revisions = results.map((r) => r.revision).sort((a, b) => a - b);
      expect(revisions).toEqual(Array.from({ length: 15 }, (_, i) => i + 1));
    });
  });

  describe('brisanje', () => {
    it('brise sifrat i ostavlja trag brisanja', async () => {
      const { id, revision } = await create(alice);
      const response = await request(alice, 'DELETE', `/vault/items/${id}`);
      expect(response.statusCode).toBe(204);
      expect(response.body).toBe('');

      expect((await request(alice, 'GET', `/vault/items/${id}`)).statusCode).toBe(404);

      const row = await env.prisma.vaultItem.findUniqueOrThrow({
        where: { userId_id: { userId: alice.userId, id } },
      });
      expect(row.envelope).toBeNull();
      expect(row.deletedAt).not.toBeNull();
      expect(row.revision).toBeGreaterThan(revision);
    });

    it('trag brisanja stize ostalim uredjajima kroz sinhronizaciju', async () => {
      const fresh = await newAccount(env);
      const { id, revision } = await create(fresh);
      await request(fresh, 'DELETE', `/vault/items/${id}`);

      const { items } = await list(fresh, `?since=${revision}`);
      expect(items).toEqual([
        {
          id,
          revision: revision + 1,
          deleted: true,
          envelope: null,
          updatedAt: expect.any(String),
        },
      ]);
    });

    it('ponovljeno brisanje i brisanje nepostojece stavke uspevaju bez izmena', async () => {
      const fresh = await newAccount(env);
      const { id } = await create(fresh);
      await request(fresh, 'DELETE', `/vault/items/${id}`);
      const before = await list(fresh, '?since=0');

      expect((await request(fresh, 'DELETE', `/vault/items/${id}`)).statusCode).toBe(204);
      expect((await request(fresh, 'DELETE', `/vault/items/${randomUUID()}`)).statusCode).toBe(204);
      const after = await list(fresh, '?since=1');
      expect(after.cursor).toBe(2);
      expect(after.items).toHaveLength(1);
      expect(before.items).toHaveLength(0);
    });

    it('obrisana stavka se ne oziva: ni izmenom ni ponovnim pravljenjem sa istim ID-jem', async () => {
      const { id, envelope, revision } = await create(alice);
      await request(alice, 'DELETE', `/vault/items/${id}`);

      const update = await request(alice, 'PUT', `/vault/items/${id}`, {
        envelope,
        baseRevision: revision,
      });
      expect(update.statusCode).toBe(409);
      const recreate = await request(alice, 'PUT', `/vault/items/${id}`, {
        envelope,
        baseRevision: null,
      });
      expect(recreate.statusCode).toBe(409);
    });
  });

  describe('sinhronizacija (GET /vault/items)', () => {
    it('since=0 vraca aktivne stavke redom nastanka, bez tragova brisanja', async () => {
      const fresh = await newAccount(env);
      const a = await create(fresh);
      const b = await create(fresh);
      const c = await create(fresh);
      await request(fresh, 'DELETE', `/vault/items/${b.id}`);

      const result = await list(fresh);
      expect(result.items.map((item) => item.id)).toEqual([a.id, c.id]);
      expect(result.items.every((item) => !item.deleted && item.envelope !== null)).toBe(true);
      expect(result.hasMore).toBe(false);
    });

    it('since=N vraca samo izmene posle N, ukljucujuci brisanja i izmene starih stavki', async () => {
      const fresh = await newAccount(env);
      const a = await create(fresh, { n: 'a' });
      const b = await create(fresh, { n: 'b' });
      const cursor = (await list(fresh)).cursor;
      expect(cursor).toBe(2);

      const newEnvelope = await seal(fresh, a.id, { n: 'a2' });
      await request(fresh, 'PUT', `/vault/items/${a.id}`, {
        envelope: newEnvelope,
        baseRevision: a.revision,
      });
      await request(fresh, 'DELETE', `/vault/items/${b.id}`);

      const result = await list(fresh, `?since=${cursor}`);
      expect(result.items.map((item) => [item.id, item.deleted])).toEqual([
        [a.id, false],
        [b.id, true],
      ]);
      expect(result.cursor).toBe(4);
      const nothing = await list(fresh, `?since=${result.cursor}`);
      expect(nothing).toEqual({ items: [], cursor: 4, hasMore: false });
    });

    it('preuzimanje po stranicama daje sve stavke tacno jednom', async () => {
      const fresh = await newAccount(env);
      const ids: string[] = [];
      for (let i = 0; i < 5; i++) {
        ids.push((await create(fresh)).id);
      }

      const collected: string[] = [];
      let cursor = 0;
      let pages = 0;
      for (;;) {
        const page = await list(fresh, `?since=${cursor}&limit=2`);
        collected.push(...page.items.map((item) => item.id));
        cursor = page.cursor;
        pages += 1;
        if (!page.hasMore) break;
      }
      expect(collected).toEqual(ids);
      expect(pages).toBe(3);
    });

    it('trag brisanja stize na kasnijoj stranici, a klijent ga primenjuje i kad stavku nema', async () => {
      const fresh = await newAccount(env);
      const kept = await create(fresh);
      const removed = await create(fresh);
      const last = await create(fresh);
      await request(fresh, 'DELETE', `/vault/items/${removed.id}`);

      // Prva stranica (since=0) preskace obrisane, ali kasnije stranice ih ukljucuju.
      const seen: [string, boolean][] = [];
      let cursor = 0;
      for (;;) {
        const page = await list(fresh, `?since=${cursor}&limit=1`);
        seen.push(...page.items.map((item): [string, boolean] => [item.id, item.deleted]));
        cursor = page.cursor;
        if (!page.hasMore) break;
      }
      expect(seen).toEqual([
        [kept.id, false],
        [last.id, false],
        [removed.id, true],
      ]);
    });

    it('odbija neispravan upit', async () => {
      for (const query of ['?since=-1', '?since=abc', '?limit=0', '?limit=501', '?x=1']) {
        const response = await request(alice, 'GET', `/vault/items${query}`);
        expect(response.statusCode).toBe(400);
        expect(response.json().error.code).toBe('VALIDATION_ERROR');
      }
    });
  });

  describe('izolacija izmedju korisnika', () => {
    it('drugi korisnik ne moze da procita, izmeni ni obrise tudju stavku', async () => {
      const { id, envelope, revision } = await create(alice, { secret: 'alisina-tajna' });

      const read = await request(bob, 'GET', `/vault/items/${id}`);
      expect(read.statusCode).toBe(404);
      expect(read.json()).toEqual(notFoundBody);
      expect(read.body).not.toContain('alisina-tajna');

      const update = await request(bob, 'PUT', `/vault/items/${id}`, {
        envelope: await seal(bob, id, { hijacked: true }),
        baseRevision: revision,
      });
      expect(update.statusCode).toBe(404);

      expect((await request(bob, 'DELETE', `/vault/items/${id}`)).statusCode).toBe(204);

      const row = await env.prisma.vaultItem.findUniqueOrThrow({
        where: { userId_id: { userId: alice.userId, id } },
      });
      expect(row.envelope).toEqual(envelope);
      expect(row.deletedAt).toBeNull();
      expect(row.revision).toBe(revision);
    });

    it('odgovor za tudju stavku je isti kao za nepostojecu', async () => {
      const { id, revision } = await create(alice);
      const foreign = await request(bob, 'PUT', `/vault/items/${id}`, {
        envelope: await seal(bob, id, {}),
        baseRevision: revision,
      });
      const missingId = randomUUID();
      const missing = await request(bob, 'PUT', `/vault/items/${missingId}`, {
        envelope: await seal(bob, missingId, {}),
        baseRevision: revision,
      });
      expect(foreign.statusCode).toBe(missing.statusCode);
      expect(foreign.json()).toEqual(missing.json());
    });

    it('listing nikad ne sadrzi tudje stavke', async () => {
      const fresh = await newAccount(env);
      await create(alice);
      const mine = await create(fresh);
      const result = await list(fresh);
      expect(result.items.map((item) => item.id)).toEqual([mine.id]);
    });

    it('isti ID kod dva korisnika ne smeta: ne otkriva tudje stavke i ne dira ih', async () => {
      const shared = randomUUID();
      const aliceEnvelope = await seal(alice, shared, { owner: 'alice' });
      const bobEnvelope = await seal(bob, shared, { owner: 'bob' });

      const a = await request(alice, 'PUT', `/vault/items/${shared}`, {
        envelope: aliceEnvelope,
        baseRevision: null,
      });
      const b = await request(bob, 'PUT', `/vault/items/${shared}`, {
        envelope: bobEnvelope,
        baseRevision: null,
      });
      expect(a.statusCode).toBe(201);
      expect(b.statusCode).toBe(201);

      const readA = await request(alice, 'GET', `/vault/items/${shared}`);
      const readB = await request(bob, 'GET', `/vault/items/${shared}`);
      expect(readA.json().envelope).toEqual(aliceEnvelope);
      expect(readB.json().envelope).toEqual(bobEnvelope);
    });
  });

  describe('ogranicenja i validacija', () => {
    it('ogranicava broj stavki po korisniku, a brisanje oslobadja mesto', async () => {
      const limited = await createTestEnv({ MAX_ITEMS_PER_USER: '3' });
      try {
        const account = await newAccount(limited);
        const items = [];
        for (let i = 0; i < 3; i++) {
          items.push(await create(account, { i }, limited));
        }
        const full = await create(account, { i: 4 }, limited);
        expect(full.response.statusCode).toBe(422);
        expect(full.response.json().error.code).toBe('VAULT_FULL');

        const first = items[0];
        if (!first) throw new Error('missing item');
        const edit = await request(
          account,
          'PUT',
          `/vault/items/${first.id}`,
          {
            envelope: await seal(account, first.id, { edited: true }),
            baseRevision: first.revision,
          },
          limited,
        );
        expect(edit.statusCode).toBe(200);

        await request(account, 'DELETE', `/vault/items/${first.id}`, undefined, limited);
        expect((await create(account, { i: 5 }, limited)).response.statusCode).toBe(201);
      } finally {
        await limited.close();
      }
    });

    it('odbija neispravna, dodatna i nedostajuca polja', async () => {
      const id = randomUUID();
      const envelope = await seal(alice, id, {});
      const bad: object[] = [
        {},
        { envelope },
        { baseRevision: null },
        { envelope, baseRevision: 0 },
        { envelope, baseRevision: '1' },
        { envelope, baseRevision: null, userId: alice.userId },
        { envelope, baseRevision: null, revision: 99 },
        { envelope: { ...envelope, v: 2 }, baseRevision: null },
        { envelope: { ...envelope, iv: 'kratko' }, baseRevision: null },
        { envelope: { ...envelope, ct: 'x' }, baseRevision: null },
        { envelope: { ...envelope, extra: 1 }, baseRevision: null },
        { envelope: 'tekst', baseRevision: null },
      ];
      for (const payload of bad) {
        const response = await request(alice, 'PUT', `/vault/items/${id}`, payload);
        expect(response.statusCode).toBe(400);
        expect(response.json().error.code).toBe('VALIDATION_ERROR');
      }
      expect((await request(alice, 'GET', `/vault/items/${id}`)).statusCode).toBe(404);
    });

    it('odbija prevelik sifrat, a prihvata onaj na granici', async () => {
      const id = randomUUID();
      const iv = 'A'.repeat(16);
      const tooBig = await request(alice, 'PUT', `/vault/items/${id}`, {
        envelope: { v: 1, iv, ct: 'A'.repeat(MAX_ITEM_CIPHERTEXT_CHARS + 1) },
        baseRevision: null,
      });
      expect(tooBig.statusCode).toBe(400);

      const atLimit = await request(alice, 'PUT', `/vault/items/${id}`, {
        envelope: { v: 1, iv, ct: 'A'.repeat(MAX_ITEM_CIPHERTEXT_CHARS) },
        baseRevision: null,
      });
      expect(atLimit.statusCode).toBe(201);
    });

    it('odbija telo vece od 1 MiB', async () => {
      const id = randomUUID();
      const response = await request(alice, 'PUT', `/vault/items/${id}`, {
        envelope: { v: 1, iv: 'A'.repeat(16), ct: 'A'.repeat(1024 * 1024 + 10) },
        baseRevision: null,
      });
      expect(response.statusCode).toBe(413);
    });

    it('odgovori se ne kesiraju', async () => {
      const response = await request(alice, 'GET', '/vault/items');
      expect(response.headers['cache-control']).toBe('no-store');
    });
  });

  describe('kraj-do-kraja: server nikad ne vidi otvoreni tekst', () => {
    it('drugi uredjaj sa samo lozinkom otvara vault i desifruje stavke', async () => {
      const owner = await newAccount(env);
      const secrets = [
        { site: 'banka.example', username: 'stefan', password: 'lozinka-1' },
        { site: 'posta.example', username: 'stefan@posta', password: 'lozinka-2' },
      ];
      const created = [];
      for (const secret of secrets) {
        created.push({ ...(await create(owner, secret)), secret });
      }

      const device = await logIn(env, owner);
      const me = (
        await env.app.inject({
          method: 'GET',
          url: '/auth/me',
          headers: bearer(device.accessToken),
        })
      ).json();
      const { kek } = await deriveKeys(PASSWORD, fromBase64Url(me.kdfSalt), {
        memoryKiB: me.kdfMemoryKiB,
        iterations: me.kdfIterations,
        parallelism: me.kdfParallelism,
      });
      const vaultKey = await unwrapVaultKey(me.wrappedVaultKey, kek);

      const synced = (
        await env.app.inject({
          method: 'GET',
          url: '/vault/items',
          headers: bearer(device.accessToken),
        })
      ).json<{ items: SyncItem[] }>();

      expect(synced.items).toHaveLength(2);
      for (const item of synced.items) {
        const original = created.find((entry) => entry.id === item.id);
        if (!original || !item.envelope) throw new Error('unexpected item');
        const plain = await decryptItem(vaultKey, item.envelope, {
          userId: me.id,
          itemId: item.id,
        });
        expect(plain).toEqual(original.secret);
      }
    });

    it('server ne moze da zameni sifrate izmedju stavki (AAD vezuje sifrat za stavku)', async () => {
      const owner = await newAccount(env);
      const first = await create(owner, { site: 'prva' });
      const second = await create(owner, { site: 'druga' });

      await env.prisma.vaultItem.update({
        where: { userId_id: { userId: owner.userId, id: second.id } },
        data: { envelope: { ...first.envelope } },
      });
      const served = (await request(owner, 'GET', `/vault/items/${second.id}`)).json<SyncItem>();
      if (!served.envelope) throw new Error('missing envelope');

      await expect(
        decryptItem(owner.vaultKey, served.envelope, { userId: owner.userId, itemId: second.id }),
      ).rejects.toThrow();
      await expect(
        decryptItem(owner.vaultKey, served.envelope, { userId: owner.userId, itemId: first.id }),
      ).resolves.toEqual({ site: 'prva' });
    });

    it('server ne moze da podmetne stavku jednog korisnika drugom', async () => {
      const victim = await newAccount(env);
      const attacker = await newAccount(env);
      const { id, envelope } = await create(attacker, { site: 'napadac' });

      await expect(
        decryptItem(victim.vaultKey, envelope, { userId: victim.userId, itemId: id }),
      ).rejects.toThrow();
    });
  });
});
