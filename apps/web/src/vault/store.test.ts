import { decryptItem, encryptItem } from '@sleepsafe/crypto';
import { type ItemData, type ItemEnvelope, itemEnvelopeSchema } from '@sleepsafe/shared';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../api/http';
import type { VaultApi } from '../api/vault';
import { FakeServer } from '../test/fakeServer';
import { VaultError, type VaultErrorCode, VaultStore } from './store';

const EMAIL = 'korisnik@example.com';
const PASSWORD = 'moja dugacka master lozinka';

const item = (title: string, extra: Partial<ItemData> = {}): ItemData => ({
  title,
  username: 'marko',
  password: 'tajna-lozinka-123',
  url: 'https://primer.example',
  notes: '',
  ...extra,
});

describe('VaultStore', () => {
  let template: FakeServer;
  let userId: string;
  let vaultKey: CryptoKey;
  let server: FakeServer;
  let store: VaultStore;

  beforeAll(async () => {
    template = new FakeServer();
    ({ id: userId, vaultKey } = await template.seedUser(EMAIL, PASSWORD));
  });

  async function connect(pageSize?: number) {
    server = new FakeServer();
    for (const [email, user] of template.users) server.users.set(email, user);
    server.startSession(EMAIL);
    await server.refresh();
    store = new VaultStore({ api: server, vaultKey, userId, ...(pageSize ? { pageSize } : {}) });
  }

  beforeEach(async () => {
    await connect();
  });

  const seal = async (data: unknown, itemId: string, key: CryptoKey = vaultKey) =>
    itemEnvelopeSchema.parse(await encryptItem(key, data, { userId, itemId }));

  // Stavka kao da ju je napravio drugi uredjaj istog naloga.
  async function fromOtherDevice(data: ItemData, id: string = crypto.randomUUID()) {
    const envelope = await seal(data, id);
    const { revision } = server.putAsOtherDevice(userId, id, { envelope, baseRevision: null });
    return { id, revision };
  }

  const rejectsWith = async (promise: Promise<unknown>, code: VaultErrorCode) => {
    const error = await promise.then(
      () => null,
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(VaultError);
    expect((error as VaultError).code).toBe(code);
  };

  const titles = () => store.getState().entries.map((entry) => entry.data.title);
  const stubApi = (list: VaultApi['list']): VaultApi => ({
    list,
    put: async (id) => ({ id, revision: 1 }),
    remove: async () => {},
  });

  describe('ucitavanje', () => {
    it('prazan vault: spreman, bez stavki', async () => {
      await store.sync();
      const state = store.getState();
      expect(state.status).toBe('ready');
      expect(state.entries).toEqual([]);
      expect(state.unreadable).toBe(0);
      expect(state.error).toBeNull();
      expect(state.syncing).toBe(false);
    });

    it('desifruje stavke i sortira ih po naslovu, bez obzira na velika slova i č', async () => {
      await fromOtherDevice(item('dinar'));
      await fromOtherDevice(item('Čačak'));
      await fromOtherDevice(item('banka'));
      await fromOtherDevice(item('Alfa'));
      await store.sync();
      expect(titles()).toEqual(['Alfa', 'banka', 'Čačak', 'dinar']);
      expect(store.getState().entries[0]?.data).toEqual(item('Alfa'));
    });

    it('obrisane stavke se ne prikazuju', async () => {
      const gone = await fromOtherDevice(item('obrisana'));
      await fromOtherDevice(item('ostaje'));
      server.removeAsOtherDevice(userId, gone.id);
      await store.sync();
      expect(titles()).toEqual(['ostaje']);
    });

    it('povlaci stranicu po stranicu dok server kaze da ima jos', async () => {
      await connect(2);
      for (const title of ['a', 'b', 'c', 'd', 'e']) await fromOtherDevice(item(title));
      await store.sync();
      expect(titles()).toEqual(['a', 'b', 'c', 'd', 'e']);
      expect(server.callsTo('vault.list')).toHaveLength(3);
    });

    it('dva istovremena sync() poziva salju samo jedan zahtev', async () => {
      await fromOtherDevice(item('a'));
      await Promise.all([store.sync(), store.sync()]);
      expect(server.callsTo('vault.list')).toHaveLength(1);
      expect(titles()).toEqual(['a']);
    });

    it('greska pri prvom ucitavanju: status error, a ponovni pokusaj radi', async () => {
      await fromOtherDevice(item('a'));
      server.down = true;
      await expect(store.sync()).resolves.toBeUndefined();
      expect(store.getState().status).toBe('error');
      expect(store.getState().error).toMatchObject({ code: 'NETWORK' });

      server.down = false;
      await store.sync();
      expect(store.getState().status).toBe('ready');
      expect(store.getState().error).toBeNull();
      expect(titles()).toEqual(['a']);
    });

    it('greska pri osvezavanju: stavke ostaju vidljive, greska se ocisti kad prodje', async () => {
      await fromOtherDevice(item('a'));
      await store.sync();

      server.down = true;
      await store.sync();
      expect(store.getState().status).toBe('ready');
      expect(store.getState().error).toMatchObject({ code: 'NETWORK' });
      expect(titles()).toEqual(['a']);

      server.down = false;
      await store.sync();
      expect(store.getState().error).toBeNull();
    });

    it('server koji stalno kaze "ima jos" bez napretka daje gresku, ne beskonacnu petlju', async () => {
      const list = vi.fn(async () => ({ items: [], cursor: 0, hasMore: true }));
      store = new VaultStore({ api: stubApi(list), vaultKey, userId });
      await store.sync();
      expect(store.getState().status).toBe('error');
      expect(store.getState().error).toMatchObject({ code: 'BAD_RESPONSE' });
      expect(list).toHaveBeenCalledTimes(1);
    });

    it('stavke koje se ne mogu otvoriti se broje, a ostale se normalno ucitavaju', async () => {
      const otherKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
        'encrypt',
        'decrypt',
      ]);
      const put = (id: string, envelope: ItemEnvelope) =>
        server.putAsOtherDevice(userId, id, { envelope, baseRevision: null });

      const wrongKey = crypto.randomUUID();
      put(wrongKey, await seal(item('tudj kljuc'), wrongKey, otherKey));
      const wrongContext = crypto.randomUUID();
      put(wrongContext, await seal(item('presadjena'), crypto.randomUUID()));
      const badShape = crypto.randomUUID();
      put(badShape, await seal({ title: 5 }, badShape));
      await fromOtherDevice(item('ispravna'));

      await store.sync();
      expect(titles()).toEqual(['ispravna']);
      expect(store.getState().unreadable).toBe(3);
      expect(store.getState().status).toBe('ready');
    });
  });

  describe('izmene', () => {
    it('create: upis bez osnovne revizije, a server dobija samo sifrat vezan za nalog i stavku', async () => {
      await store.sync();
      const data = item('Banka', { password: 'veoma-tajna-lozinka' });
      const id = await store.create(data);

      const [call] = server.callsTo('vault.put');
      const sent = call?.args as {
        id: string;
        body: { envelope: ItemEnvelope; baseRevision: null };
      };
      expect(sent.id).toBe(id);
      expect(sent.body.baseRevision).toBeNull();
      expect(JSON.stringify(sent)).not.toContain('veoma-tajna-lozinka');
      expect(JSON.stringify(sent)).not.toContain('Banka');

      const context = { userId, itemId: id };
      expect(await decryptItem(vaultKey, sent.body.envelope, context)).toEqual(data);
      await expect(
        decryptItem(vaultKey, sent.body.envelope, { userId, itemId: crypto.randomUUID() }),
      ).rejects.toThrow();
      await expect(
        decryptItem(vaultKey, sent.body.envelope, { userId: crypto.randomUUID(), itemId: id }),
      ).rejects.toThrow();

      expect(titles()).toEqual(['Banka']);
      expect(store.get(id)?.revision).toBe(1);
    });

    it('naslov se cuva bez razmaka na krajevima', async () => {
      await store.sync();
      const id = await store.create(item('  Banka  '));
      expect(store.get(id)?.data.title).toBe('Banka');
    });

    it('update: koristi trenutnu reviziju, a svaka izmena je nova revizija', async () => {
      await store.sync();
      const id = await store.create(item('Prva'));
      await store.update(id, item('Druga'));
      await store.update(id, item('Treca'));

      const bases = server
        .callsTo('vault.put')
        .map((call) => (call.args as { body: { baseRevision: number | null } }).body.baseRevision);
      expect(bases).toEqual([null, 1, 2]);
      expect(store.get(id)?.revision).toBe(3);
      expect(titles()).toEqual(['Treca']);
    });

    it('neispravna stavka se odbija pre bilo kakvog zahteva', async () => {
      await store.sync();
      await rejectsWith(store.create(item('   ')), 'INVALID_ITEM');
      await rejectsWith(store.create(item('x', { notes: 'a'.repeat(10_001) })), 'INVALID_ITEM');
      const id = await store.create(item('ok'));
      await rejectsWith(store.update(id, item('')), 'INVALID_ITEM');
      expect(server.callsTo('vault.put')).toHaveLength(1);
    });

    it('stavka cji sifrat prelazi granicu servera se odbija bez zahteva', async () => {
      await store.sync();
      const control = '\u0001'; // u JSON-u zauzima 6 znakova
      const huge = item(control.repeat(200), {
        username: control.repeat(500),
        password: control.repeat(1000),
        url: control.repeat(2048),
        notes: control.repeat(10_000),
      });
      await rejectsWith(store.create(huge), 'TOO_LARGE');
      expect(server.callsTo('vault.put')).toHaveLength(0);
    });

    it('izmena nepoznate stavke: NOT_FOUND bez zahteva', async () => {
      await store.sync();
      await rejectsWith(store.update(crypto.randomUUID(), item('x')), 'NOT_FOUND');
      expect(server.callsTo('vault.put')).toHaveLength(0);
    });

    it('konflikt: drugi uredjaj je vec izmenio stavku, pa se prikazuje njegova verzija', async () => {
      const { id, revision } = await fromOtherDevice(item('original'));
      await store.sync();

      server.putAsOtherDevice(userId, id, {
        envelope: await seal(item('sa drugog uredjaja'), id),
        baseRevision: revision,
      });

      await rejectsWith(store.update(id, item('moja izmena')), 'CONFLICT');
      expect(titles()).toEqual(['sa drugog uredjaja']);
      // Sada je osnovna revizija tacna, pa izmena prolazi.
      await store.update(id, item('moja izmena'));
      expect(titles()).toEqual(['moja izmena']);
    });

    it('stavka obrisana na drugom uredjaju: konflikt, a stavka nestaje i ovde', async () => {
      const { id } = await fromOtherDevice(item('nestaje'));
      await store.sync();
      server.removeAsOtherDevice(userId, id);

      await rejectsWith(store.update(id, item('nova verzija')), 'CONFLICT');
      expect(titles()).toEqual([]);
    });

    it('brisanje: uklanja stavku lokalno i na serveru, a ponovljeno brisanje ne smeta', async () => {
      const { id } = await fromOtherDevice(item('za brisanje'));
      await fromOtherDevice(item('ostaje'));
      await store.sync();

      await store.remove(id);
      expect(titles()).toEqual(['ostaje']);
      await expect(store.remove(id)).resolves.toBeUndefined();

      const fresh = new VaultStore({ api: server, vaultKey, userId });
      await fresh.sync();
      expect(fresh.getState().entries.map((entry) => entry.data.title)).toEqual(['ostaje']);
    });

    it('ogranicenje broja stavki: VAULT_FULL', async () => {
      server.itemLimit = 1;
      await store.sync();
      await store.create(item('prva'));
      await rejectsWith(store.create(item('druga')), 'VAULT_FULL');
      expect(titles()).toEqual(['prva']);
    });

    it('mrezna greska pri upisu: stanje se ne menja, a greska stize do pozivaoca', async () => {
      await store.sync();
      const id = await store.create(item('a'));
      server.down = true;
      await expect(store.update(id, item('b'))).rejects.toBeInstanceOf(ApiError);
      await expect(store.remove(id)).rejects.toBeInstanceOf(ApiError);
      await expect(store.create(item('c'))).rejects.toMatchObject({ code: 'NETWORK' });
      expect(titles()).toEqual(['a']);
    });
  });

  describe('sinhronizacija sa drugih uredjaja', () => {
    it('donosi nove, izmenjene i obrisane stavke, a tombstone za nepoznatu stavku ne smeta', async () => {
      const a = await fromOtherDevice(item('A'));
      const b = await fromOtherDevice(item('B'));
      await store.sync();
      expect(titles()).toEqual(['A', 'B']);

      server.putAsOtherDevice(userId, a.id, {
        envelope: await seal(item('A izmenjena'), a.id),
        baseRevision: a.revision,
      });
      server.removeAsOtherDevice(userId, b.id);
      await fromOtherDevice(item('C'));
      const ghost = await fromOtherDevice(item('nikad videna'));
      server.removeAsOtherDevice(userId, ghost.id);

      await store.sync();
      expect(titles()).toEqual(['A izmenjena', 'C']);
      expect(store.getState().unreadable).toBe(0);
      // Drugi krug trazi samo ono posle kursora.
      const since = server
        .callsTo('vault.list')
        .map((call) => (call.args as { since: number }).since);
      expect(since[0]).toBe(0);
      expect(since[1]).toBeGreaterThan(0);
    });

    it('konflikt dok je sinhronizacija u toku: ceka je, pa povlaci najnovije stanje', async () => {
      const { id, revision } = await fromOtherDevice(item('v1'));
      await store.sync();

      // Sinhronizacija koja je vec dobila odgovor (bez izmene ispod), ali jos nije zavrsena.
      const release = server.holdList();
      const stale = store.sync();
      await vi.waitFor(() => expect(server.callsTo('vault.list')).toHaveLength(2));

      server.putAsOtherDevice(userId, id, {
        envelope: await seal(item('v2'), id),
        baseRevision: revision,
      });
      const updating = store.update(id, item('moja izmena'));
      await vi.waitFor(() => expect(server.callsTo('vault.put')).toHaveLength(1));
      release();

      await rejectsWith(updating, 'CONFLICT');
      await stale;
      expect(titles()).toEqual(['v2']);
    });

    it('upis koji zavrsi kasno ne prepisuje novije stanje koje je sinhronizacija vec donela', async () => {
      const id = crypto.randomUUID();
      const stamp = () => new Date().toISOString();
      const v1 = await seal(item('v1'), id);
      const other = await seal(item('sa drugog uredjaja'), id);
      let releasePut!: () => void;
      const putGate = new Promise<void>((resolve) => (releasePut = resolve));
      let round = 0;
      const api: VaultApi = {
        list: async () => {
          round += 1;
          const revision = round === 1 ? 1 : 3;
          const envelope = round === 1 ? v1 : other;
          return {
            items: [{ id, revision, deleted: false, envelope, updatedAt: stamp() }],
            cursor: revision,
            hasMore: false,
          };
        },
        put: async () => {
          await putGate;
          return { id, revision: 2 };
        },
        remove: async () => {},
      };
      store = new VaultStore({ api, vaultKey, userId });
      await store.sync();

      const updating = store.update(id, item('moja izmena'));
      await store.sync(); // donosi reviziju 3 dok upis jos traje
      expect(store.get(id)?.revision).toBe(3);
      releasePut();
      await updating;

      expect(titles()).toEqual(['sa drugog uredjaja']);
      expect(store.get(id)?.revision).toBe(3);
    });

    it('sopstveni upis se ne prepisuje starijim odgovorom servera', async () => {
      const id = crypto.randomUUID();
      const first = await seal(item('stara verzija'), id);
      const api: VaultApi = {
        list: async () => {
          return {
            items: [
              {
                id,
                revision: 1,
                deleted: false,
                envelope: first,
                updatedAt: new Date().toISOString(),
              },
            ],
            cursor: 1,
            hasMore: false,
          };
        },
        put: async () => ({ id, revision: 2 }),
        remove: async () => {},
      };
      store = new VaultStore({ api, vaultKey, userId });
      await store.sync();
      await store.update(id, item('nova verzija'));
      expect(titles()).toEqual(['nova verzija']);

      await store.sync(); // server jos vraca reviziju 1
      expect(titles()).toEqual(['nova verzija']);
      expect(store.get(id)?.revision).toBe(2);
    });
  });

  describe('pretplata na promene', () => {
    it('obavestava o promenama i vraca isti objekat dok se nista ne promeni', async () => {
      const listener = vi.fn();
      const unsubscribe = store.subscribe(listener);
      expect(store.getState()).toBe(store.getState());

      await store.sync();
      expect(listener).toHaveBeenCalled();
      const before = store.getState();
      expect(store.getState()).toBe(before);

      unsubscribe();
      listener.mockClear();
      await store.create(item('x'));
      expect(listener).not.toHaveBeenCalled();
    });
  });

  describe('zakljucavanje (dispose)', () => {
    const internals = () => {
      const raw = store as unknown as Record<string, unknown>;
      return { vaultKey: raw['vaultKey'], entries: raw['entries'] as Map<string, unknown> };
    };

    it('brise stavke i kljuc iz memorije, a dalje operacije se odbijaju', async () => {
      const { id } = await fromOtherDevice(item('a'));
      await store.sync();
      expect(internals().entries.size).toBe(1);

      store.dispose();
      expect(store.getState()).toEqual({
        status: 'disposed',
        entries: [],
        unreadable: 0,
        syncing: false,
        error: null,
      });
      expect(internals().vaultKey).toBeNull();
      expect(internals().entries.size).toBe(0);
      expect(store.get(id)).toBeUndefined();

      const requests = server.calls.length;
      await rejectsWith(store.create(item('b')), 'DISPOSED');
      await rejectsWith(store.update(id, item('b')), 'DISPOSED');
      await rejectsWith(store.remove(id), 'DISPOSED');
      await expect(store.sync()).resolves.toBeUndefined();
      expect(server.calls).toHaveLength(requests);
      expect(store.getState().status).toBe('disposed');
    });

    it('odgovor koji stigne posle zakljucavanja se ignorise', async () => {
      await fromOtherDevice(item('tajna stavka'));
      const release = server.holdList();
      const syncing = store.sync();
      await vi.waitFor(() => expect(server.callsTo('vault.list')).toHaveLength(1));

      store.dispose();
      release();
      await syncing;

      expect(store.getState().status).toBe('disposed');
      expect(store.getState().entries).toEqual([]);
      expect(internals().entries.size).toBe(0);
    });

    it('posle zakljucavanja se ne traze naredne stranice', async () => {
      let release!: () => void;
      const gate = new Promise<void>((resolve) => (release = resolve));
      const list = vi.fn(async () => {
        await gate;
        return { items: [], cursor: list.mock.calls.length, hasMore: true };
      });
      store = new VaultStore({ api: stubApi(list), vaultKey, userId });
      const syncing = store.sync();
      await vi.waitFor(() => expect(list).toHaveBeenCalledTimes(1));

      store.dispose();
      release();
      await syncing;
      expect(list).toHaveBeenCalledTimes(1);
    });

    it('upis koji je poceo pre zakljucavanja se ne salje i ne vraca stavku u memoriju', async () => {
      await store.sync();
      const pending = store.create(item('kasni upis'));
      store.dispose();
      await rejectsWith(pending, 'DISPOSED');
      expect(server.callsTo('vault.put')).toHaveLength(0);
      expect(internals().entries.size).toBe(0);
      expect(store.getState().entries).toEqual([]);
    });
  });
});
