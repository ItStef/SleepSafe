import {
  decryptItem,
  deriveKeys,
  encryptItem,
  fromBase64Url,
  unwrapVaultKey,
} from '@sleepsafe/crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { inlineDeriver } from '../crypto/deriver';
import { CODE, FakeServer, TEST_KDF } from '../test/fakeServer';
import { ClientError } from './errors';
import { AuthStore } from './store';

const EMAIL = 'korisnik@example.com';
const PASSWORD = 'moja dugacka master lozinka';

describe('AuthStore', () => {
  let server: FakeServer;
  let store: AuthStore;

  beforeEach(() => {
    server = new FakeServer();
    store = new AuthStore({
      api: server,
      vaultApi: server,
      deriver: inlineDeriver,
      kdfParams: TEST_KDF,
    });
  });

  const status = () => store.getState().status;

  const secrets = () => {
    const internal = store as unknown as Record<string, unknown>;
    return {
      profile: internal['profile'],
      challengeId: internal['challengeId'],
      pendingRegistration: internal['pendingRegistration'],
      pendingLogin: internal['pendingLogin'],
      vault: internal['vault'],
    };
  };
  const allEmpty = {
    profile: null,
    challengeId: null,
    pendingRegistration: null,
    pendingLogin: null,
    vault: null,
  };

  async function registerAndVerify(email = EMAIL, password = PASSWORD) {
    await store.register(email, password);
    await store.verifyEmail(CODE);
  }

  async function signIn(email = EMAIL, password = PASSWORD) {
    await store.login(email, password);
    await store.verifyLoginCode(CODE);
  }

  describe('pokretanje', () => {
    it('bez sesije: odjavljen, bez poruke', async () => {
      await store.boot();
      expect(store.getState()).toEqual({ status: 'signedOut' });
    });

    it('sa vazecom sesijom: zakljucan, korisnik samo unosi lozinku', async () => {
      await server.seedUser(EMAIL, PASSWORD);
      server.startSession(EMAIL);
      await store.boot();
      expect(store.getState()).toEqual({ status: 'locked', email: EMAIL });
    });

    it('server nedostupan: odjavljen sa porukom', async () => {
      server.down = true;
      await store.boot();
      expect(store.getState()).toEqual({ status: 'signedOut', notice: 'serverUnavailable' });
    });
  });

  describe('registracija', () => {
    it('salje samo izvedene vrednosti: nikad lozinku', async () => {
      await store.register('  KORISNIK@Example.com ', PASSWORD);

      const [call] = server.callsTo('register');
      const body = call?.args as Record<string, unknown>;
      expect(body).toMatchObject({
        email: EMAIL,
        kdfMemoryKiB: TEST_KDF.memoryKiB,
        kdfIterations: TEST_KDF.iterations,
        kdfParallelism: TEST_KDF.parallelism,
        wrappedVaultKey: { v: 1 },
      });
      expect(String(body['authKey'])).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(String(body['kdfSalt'])).toMatch(/^[A-Za-z0-9_-]{22}$/);
      expect(JSON.stringify(server.calls)).not.toContain(PASSWORD);
      expect(store.getState()).toEqual({ status: 'verifyingEmail', email: EMAIL });
    });

    it('neispravan email se odbija pre bilo kakvog zahteva', async () => {
      await expect(store.register('nije-email', PASSWORD)).rejects.toMatchObject({
        code: 'INVALID_EMAIL',
      });
      expect(server.calls).toHaveLength(0);
    });

    it('pogresan kod ostavlja korisnika na istom koraku, a tacan potvrdjuje nalog', async () => {
      await store.register(EMAIL, PASSWORD);
      await expect(store.verifyEmail('000000')).rejects.toMatchObject({ code: 'INVALID_CODE' });
      expect(status()).toBe('verifyingEmail');

      await store.verifyEmail(CODE);
      expect(store.getState()).toEqual({ status: 'signedOut', notice: 'emailVerified' });
      expect(server.users.get(EMAIL)?.verified).toBe(true);
    });

    it('ponovno slanje koda: novi izazov radi, stari ne', async () => {
      await store.register(EMAIL, PASSWORD);
      const first = (server.callsTo('register')[0]?.args as { authKey: string }).authKey;
      await store.resendVerification();
      expect(server.callsTo('register')).toHaveLength(2);
      // Isti (vec izvedeni) kljucevi se salju ponovo, lozinka se ne trazi ponovo.
      expect((server.callsTo('register')[1]?.args as { authKey: string }).authKey).toBe(first);
      await store.verifyEmail(CODE);
      expect(status()).toBe('signedOut');
    });

    it('koraci u pogresnom stanju se odbijaju', async () => {
      await expect(store.verifyEmail(CODE)).rejects.toMatchObject({ code: 'BAD_STATE' });
      await expect(store.verifyLoginCode(CODE)).rejects.toMatchObject({ code: 'BAD_STATE' });
      await expect(store.unlock(PASSWORD)).rejects.toMatchObject({ code: 'BAD_STATE' });
    });
  });

  describe('prijava', () => {
    it('cela tacka: registracija, prijava i otkljucan vault sa ispravnim kljucem', async () => {
      await registerAndVerify();
      await store.login(EMAIL, PASSWORD);
      expect(store.getState()).toEqual({ status: 'loginCode', email: EMAIL });
      await store.verifyLoginCode(CODE);

      const state = store.getState();
      if (state.status !== 'unlocked') throw new Error('expected unlocked');
      expect(state.user.email).toBe(EMAIL);

      const stored = server.users.get(EMAIL)?.request;
      if (!stored) throw new Error('missing user');
      const { kek } = await deriveKeys(PASSWORD, fromBase64Url(stored.kdfSalt), TEST_KDF);
      const independentKey = await unwrapVaultKey(stored.wrappedVaultKey, kek);

      const context = { userId: state.user.id, itemId: 'stavka-1' };
      const sealed = await encryptItem(state.vaultKey, { site: 'banka.example' }, context);
      expect(await decryptItem(independentKey, sealed, context)).toEqual({ site: 'banka.example' });
    });

    it('lozinka nikad ne napusta klijenta, ni u jednom koraku', async () => {
      await registerAndVerify();
      await signIn();
      store.lock();
      await store.unlock(PASSWORD);
      expect(JSON.stringify(server.calls)).not.toContain(PASSWORD);
    });

    it('pogresna lozinka i nepostojeci nalog daju isti odgovor, i ne otvaraju izazov', async () => {
      await registerAndVerify();
      await expect(store.login(EMAIL, 'pogresna lozinka!!')).rejects.toMatchObject({
        code: 'INVALID_CREDENTIALS',
      });
      await expect(store.login('niko@example.com', PASSWORD)).rejects.toMatchObject({
        code: 'INVALID_CREDENTIALS',
      });
      expect(store.getState()).toEqual({ status: 'signedOut', notice: 'emailVerified' });
    });

    it('odbija preslabe KDF parametre sa servera i ne salje Auth kljuc', async () => {
      await registerAndVerify();
      server.preloginOverride = { kdfMemoryKiB: 1024 };
      await expect(store.login(EMAIL, PASSWORD)).rejects.toBeInstanceOf(ClientError);
      await expect(store.login(EMAIL, PASSWORD)).rejects.toMatchObject({ code: 'WEAK_KDF' });
      expect(server.callsTo('login')).toHaveLength(0);

      server.preloginOverride = { kdfIterations: 1 };
      await expect(store.login(EMAIL, PASSWORD)).rejects.toMatchObject({ code: 'WEAK_KDF' });
      expect(server.callsTo('login')).toHaveLength(0);
    });

    it('pogresan kod za prijavu ostavlja korisnika na istom koraku', async () => {
      await registerAndVerify();
      await store.login(EMAIL, PASSWORD);
      await expect(store.verifyLoginCode('000000')).rejects.toMatchObject({ code: 'INVALID_CODE' });
      expect(status()).toBe('loginCode');
      await store.verifyLoginCode(CODE);
      expect(status()).toBe('unlocked');
    });

    it('ponovno slanje koda za prijavu ne trazi ponovo lozinku', async () => {
      await registerAndVerify();
      await store.login(EMAIL, PASSWORD);
      const first = (server.callsTo('login')[0]?.args as { authKey: string }).authKey;
      await store.resendLoginCode();
      expect((server.callsTo('login')[1]?.args as { authKey: string }).authKey).toBe(first);
      await store.verifyLoginCode(CODE);
      expect(status()).toBe('unlocked');
    });

    it('odustajanje brise sve privremeno: dalje potvrde nisu moguce', async () => {
      await registerAndVerify();
      await store.login(EMAIL, PASSWORD);
      store.cancelPending();
      expect(store.getState()).toEqual({ status: 'signedOut' });
      await expect(store.verifyLoginCode(CODE)).rejects.toMatchObject({ code: 'BAD_STATE' });
    });

    it('vault koji se ne otvara posle uspesne prijave je ostecen (ne "pogresna lozinka")', async () => {
      await registerAndVerify();
      await server.seedUser('drugi@example.com', 'sasvim druga lozinka');
      const other = server.users.get('drugi@example.com');
      const mine = server.users.get(EMAIL);
      if (!other || !mine) throw new Error('missing users');
      mine.request = { ...mine.request, wrappedVaultKey: other.request.wrappedVaultKey };

      await store.login(EMAIL, PASSWORD);
      await expect(store.verifyLoginCode(CODE)).rejects.toMatchObject({ code: 'VAULT_CORRUPT' });
      expect(status()).toBe('loginCode');
    });
  });

  describe('zakljucavanje i otkljucavanje', () => {
    beforeEach(async () => {
      await registerAndVerify();
      await signIn();
    });

    it('zakljucavanje brise kljuc iz stanja, a sesija ostaje', () => {
      store.lock();
      expect(store.getState()).toEqual({ status: 'locked', email: EMAIL });
      expect(server.callsTo('logout')).toHaveLength(0);
    });

    it('pogresna lozinka ne otkljucava, tacna otkljucava (bez ikakvog zahteva za proveru)', async () => {
      store.lock();
      await expect(store.unlock('pogresna master lozinka')).rejects.toMatchObject({
        code: 'WRONG_PASSWORD',
      });
      expect(status()).toBe('locked');

      const before = server.calls.length;
      await store.unlock(PASSWORD);
      expect(status()).toBe('unlocked');
      // Osim citanja profila (me), nista drugo se ne salje serveru.
      expect(server.calls.slice(before).map((c) => c.name)).toEqual(['me']);
    });

    it('otkljucavanje koristi svez profil: promena lozinke sa drugog uredjaja se odmah primeni', async () => {
      store.lock();
      await server.changePasswordElsewhere(EMAIL, 'potpuno nova lozinka');

      await expect(store.unlock(PASSWORD)).rejects.toMatchObject({ code: 'WRONG_PASSWORD' });
      await store.unlock('potpuno nova lozinka');
      expect(status()).toBe('unlocked');
    });

    it('lock() van otkljucanog stanja ne radi nista', () => {
      store.lock();
      store.lock();
      expect(status()).toBe('locked');
    });
  });

  describe('odjava i istek sesije', () => {
    it('odjava zove server i brise sve', async () => {
      await registerAndVerify();
      await signIn();
      await store.logout();
      expect(server.callsTo('logout')).toHaveLength(1);
      expect(store.getState()).toEqual({ status: 'signedOut' });
    });

    it('odjava uspeva lokalno i kad server nije dostupan', async () => {
      await registerAndVerify();
      await signIn();
      server.failLogout = true;
      await store.logout();
      expect(store.getState()).toEqual({ status: 'signedOut' });
    });

    it('istek sesije u toku rada vraca na prijavu sa porukom', async () => {
      await registerAndVerify();
      await signIn();
      store.sessionExpired();
      expect(store.getState()).toEqual({ status: 'signedOut', notice: 'sessionExpired' });
    });

    it('istek sesije pri pokretanju (nema sesije) ne prikazuje poruku', () => {
      store.sessionExpired();
      expect(store.getState()).toEqual({ status: 'signedOut' });
    });
  });

  describe('vault', () => {
    const openVault = () => {
      const state = store.getState();
      if (state.status !== 'unlocked') throw new Error('expected unlocked');
      return state.vault;
    };
    const item = (title: string) => ({
      title,
      username: 'marko',
      password: 'tajna',
      url: '',
      notes: '',
    });

    it('otkljucavanje daje vault za tog korisnika, koji stavke cuva sifrovane na serveru', async () => {
      await registerAndVerify();
      await signIn();
      const vault = openVault();
      const state = store.getState();
      if (state.status !== 'unlocked') throw new Error('expected unlocked');
      expect(vault.getState().status).toBe('idle');

      await vault.sync();
      const id = await vault.create(item('Banka'));

      const [call] = server.callsTo('vault.put');
      const sent = call?.args as { body: { envelope: { v: 1; iv: string; ct: string } } };
      expect(JSON.stringify(sent)).not.toContain('Banka');
      // Isti kljuc i isti korisnik (AAD): stavku otvara nezavisno izvedeni kljuc iz stanja.
      expect(
        await decryptItem(state.vaultKey, sent.body.envelope, {
          userId: state.user.id,
          itemId: id,
        }),
      ).toEqual(item('Banka'));
    });

    it('stavke prezive zakljucavanje i ponovno otkljucavanje (sa servera), a stari vault je obrisan', async () => {
      await registerAndVerify();
      await signIn();
      const first = openVault();
      await first.sync();
      await first.create(item('Banka'));

      store.lock();
      expect(first.getState().status).toBe('disposed');
      expect(first.getState().entries).toEqual([]);

      await store.unlock(PASSWORD);
      const second = openVault();
      expect(second).not.toBe(first);
      expect(second.getState().entries).toEqual([]); // nista se ne drzi u memoriji izmedju
      await second.sync();
      expect(second.getState().entries.map((entry) => entry.data.title)).toEqual(['Banka']);
    });

    it('zakljucavanje, odjava i istek sesije brisu vault iz memorije', async () => {
      await registerAndVerify();
      await signIn();

      let vault = openVault();
      await vault.sync();
      await vault.create(item('a'));
      store.lock();
      expect(vault.getState().status).toBe('disposed');
      expect(secrets().vault).toBeNull();

      await store.unlock(PASSWORD);
      vault = openVault();
      await store.logout();
      expect(vault.getState().status).toBe('disposed');
      expect(secrets().vault).toBeNull();

      await signIn();
      vault = openVault();
      store.sessionExpired();
      expect(vault.getState().status).toBe('disposed');
      expect(secrets().vault).toBeNull();
    });

    it('vault ne ostaje u memoriji ni kad se otkljucano stanje napusti drugim putem (nova prijava)', async () => {
      await registerAndVerify();
      await signIn();
      const vault = openVault();
      await vault.sync();
      await vault.create(item('a'));

      await store.login(EMAIL, PASSWORD);
      expect(status()).toBe('loginCode');
      expect(vault.getState().status).toBe('disposed');
      expect(vault.getState().entries).toEqual([]);
      expect(secrets().vault).toBeNull();
    });

    it('pogresna lozinka pri otkljucavanju ne pravi vault', async () => {
      await registerAndVerify();
      await signIn();
      store.lock();
      await expect(store.unlock('pogresna lozinka')).rejects.toMatchObject({
        code: 'WRONG_PASSWORD',
      });
      expect(status()).toBe('locked');
      expect(secrets().vault).toBeNull();
    });
  });

  describe('tajne u memoriji', () => {
    it('izmedju koraka se drze samo dok su potrebni, a odustajanje ih brise', async () => {
      await store.register(EMAIL, PASSWORD);
      expect(secrets().pendingRegistration).not.toBeNull();
      store.cancelPending();
      expect(secrets()).toEqual(allEmpty);

      await registerAndVerify();
      await store.login(EMAIL, PASSWORD);
      expect(secrets().pendingLogin).not.toBeNull();
      store.cancelPending();
      expect(secrets()).toEqual(allEmpty);
    });

    it('posle uspesne prijave izvedeni KEK i Auth kljuc se vise ne drze', async () => {
      await registerAndVerify();
      await signIn();
      expect(secrets().pendingLogin).toBeNull();
      expect(secrets().challengeId).toBeNull();
    });

    it('odjava i istek sesije brisu sve', async () => {
      await registerAndVerify();
      await signIn();
      expect(secrets().profile).not.toBeNull();
      await store.logout();
      expect(secrets()).toEqual(allEmpty);

      await signIn();
      store.sessionExpired();
      expect(secrets()).toEqual(allEmpty);
    });
  });

  describe('pretplate', () => {
    it('obavestava pretplatnike pri svakoj promeni stanja, do odjave pretplate', async () => {
      const listener = vi.fn();
      const unsubscribe = store.subscribe(listener);
      await store.boot();
      expect(listener).toHaveBeenCalledTimes(1);

      unsubscribe();
      store.sessionExpired();
      expect(listener).toHaveBeenCalledTimes(1);
    });
  });
});
