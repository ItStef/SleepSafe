import { describe, expect, it } from 'vitest';
import { constantTimeEqual, fromBase64Url, toBase64Url } from '../bytes';
import { type KdfParams, deriveKeys, generateSalt } from '../kdf';
import {
  type Envelope,
  ENVELOPE_VERSION,
  createVault,
  decryptItem,
  encryptItem,
  rewrapVaultKey,
  unwrapVaultKey,
} from '../vault';

const TEST_PARAMS: KdfParams = { memoryKiB: 1024, iterations: 1, parallelism: 1 };
const ctx = { userId: 'user-1', itemId: 'item-1' };

async function newKek() {
  return (await deriveKeys('lozinka', generateSalt(), TEST_PARAMS)).kek;
}

function tamperCiphertext(envelope: Envelope): Envelope {
  const bytes = fromBase64Url(envelope.ct);
  bytes[0] = (bytes[0] ?? 0) ^ 1;
  return { ...envelope, ct: toBase64Url(bytes) };
}

describe('createVault i unwrapVaultKey', () => {
  it('pravi neizvoziv AES-256-GCM Vault Key i umotani oblik u verziji 1', async () => {
    const { vaultKey, wrappedVaultKey } = await createVault(await newKek());
    expect(vaultKey.extractable).toBe(false);
    expect(vaultKey.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    expect([...vaultKey.usages].sort()).toEqual(['decrypt', 'encrypt']);
    expect(wrappedVaultKey.v).toBe(ENVELOPE_VERSION);
    // 32 bajta kljuca + 16 bajtova taga
    expect(fromBase64Url(wrappedVaultKey.ct)).toHaveLength(48);
  });

  it('odmotani kljuc desifruje ono sto je sifrovano originalnim', async () => {
    const kek = await newKek();
    const { vaultKey, wrappedVaultKey } = await createVault(kek);
    const envelope = await encryptItem(vaultKey, { title: 'GitHub' }, ctx);

    const restored = await unwrapVaultKey(wrappedVaultKey, kek);
    expect(await decryptItem(restored, envelope, ctx)).toEqual({ title: 'GitHub' });
  });

  it('svaki vault dobija drugaciji kljuc', async () => {
    const kek = await newKek();
    const a = await createVault(kek);
    const b = await createVault(kek);
    expect(a.wrappedVaultKey.ct).not.toBe(b.wrappedVaultKey.ct);
    const envelope = await encryptItem(a.vaultKey, 'x', ctx);
    await expect(decryptItem(b.vaultKey, envelope, ctx)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('odmotavanje pogresnim KEK-om ne uspeva', async () => {
    const { wrappedVaultKey } = await createVault(await newKek());
    await expect(unwrapVaultKey(wrappedVaultKey, await newKek())).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('odmotavanje izmenjenog zapisa ne uspeva', async () => {
    const kek = await newKek();
    const { wrappedVaultKey } = await createVault(kek);
    await expect(unwrapVaultKey(tamperCiphertext(wrappedVaultKey), kek)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('izvoziv kljuc se dobija samo na izricit zahtev', async () => {
    const kek = await newKek();
    const { wrappedVaultKey } = await createVault(kek);
    expect((await unwrapVaultKey(wrappedVaultKey, kek)).extractable).toBe(false);
    expect((await unwrapVaultKey(wrappedVaultKey, kek, { extractable: true })).extractable).toBe(
      true,
    );
  });

  it('odbija nepoznatu verziju i neispravan zapis', async () => {
    const kek = await newKek();
    const { wrappedVaultKey } = await createVault(kek);
    await expect(unwrapVaultKey({ ...wrappedVaultKey, v: 2 }, kek)).rejects.toMatchObject({
      code: 'UNSUPPORTED_VERSION',
    });
    await expect(unwrapVaultKey({ ...wrappedVaultKey, iv: '***' }, kek)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(
      unwrapVaultKey({ v: 1, iv: 5, ct: null } as unknown as Envelope, kek),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

describe('rewrapVaultKey (promena master lozinke)', () => {
  it('novi KEK otvara isti Vault Key, a stari vise ne', async () => {
    const oldKek = await newKek();
    const newerKek = await newKek();
    const { vaultKey, wrappedVaultKey } = await createVault(oldKek);
    const envelope = await encryptItem(vaultKey, { password: 'tajna' }, ctx);

    const rewrapped = await rewrapVaultKey(wrappedVaultKey, oldKek, newerKek);

    // Stavka se nije menjala, a ipak se desifruje kljucem dobijenim novim KEK-om.
    const restored = await unwrapVaultKey(rewrapped, newerKek);
    expect(await decryptItem(restored, envelope, ctx)).toEqual({ password: 'tajna' });
    await expect(unwrapVaultKey(rewrapped, oldKek)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('ne uspeva ako se zada pogresan stari KEK', async () => {
    const { wrappedVaultKey } = await createVault(await newKek());
    await expect(
      rewrapVaultKey(wrappedVaultKey, await newKek(), await newKek()),
    ).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
  });
});

describe('encryptItem i decryptItem', () => {
  async function vault() {
    return (await createVault(await newKek())).vaultKey;
  }

  it('krug: cuva ugnjezdene objekte i srpska slova', async () => {
    const key = await vault();
    const item = {
      title: 'Banka',
      username: 'stefan',
      password: 'šđčćž-🔐',
      tags: ['posao', 'novac'],
      meta: { updated: 1700000000, favorite: true },
    };
    const envelope = await encryptItem(key, item, ctx);
    expect(await decryptItem(key, envelope, ctx)).toEqual(item);
  });

  it('zapis se moze serijalizovati kao JSON (kako ga server cuva) i ne sadrzi otvoreni tekst', async () => {
    const key = await vault();
    const envelope = await encryptItem(key, { title: 'MojaTajnaStavka' }, ctx);
    const stored = JSON.stringify(envelope);
    expect(stored).not.toContain('MojaTajnaStavka');
    expect(await decryptItem(key, JSON.parse(stored) as Envelope, ctx)).toEqual({
      title: 'MojaTajnaStavka',
    });
  });

  it('isti sadrzaj se svaki put sifruje drugacije', async () => {
    const key = await vault();
    const a = await encryptItem(key, { x: 1 }, ctx);
    const b = await encryptItem(key, { x: 1 }, ctx);
    expect(a.iv).not.toBe(b.iv);
    expect(a.ct).not.toBe(b.ct);
  });

  it('sifrat ne moze da se prebaci na drugu stavku ni drugom korisniku', async () => {
    const key = await vault();
    const envelope = await encryptItem(key, 'tajna', ctx);
    await expect(decryptItem(key, envelope, { ...ctx, itemId: 'item-2' })).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
    await expect(decryptItem(key, envelope, { ...ctx, userId: 'user-2' })).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('kontekst je jednoznacan: ("a|b","c") nije isto sto i ("a","b|c")', async () => {
    const key = await vault();
    const envelope = await encryptItem(key, 'tajna', { userId: 'a|b', itemId: 'c' });
    await expect(decryptItem(key, envelope, { userId: 'a', itemId: 'b|c' })).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('izmenjen sifrat, pogresan kljuc i nepoznata verzija se odbijaju', async () => {
    const key = await vault();
    const envelope = await encryptItem(key, 'tajna', ctx);
    await expect(decryptItem(key, tamperCiphertext(envelope), ctx)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
    await expect(decryptItem(await vault(), envelope, ctx)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
    await expect(decryptItem(key, { ...envelope, v: 2 }, ctx)).rejects.toMatchObject({
      code: 'UNSUPPORTED_VERSION',
    });
  });

  it('odbija prazan kontekst i vrednost koja se ne moze serijalizovati', async () => {
    const key = await vault();
    await expect(encryptItem(key, 'x', { userId: '', itemId: 'i' })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(encryptItem(key, 'x', { userId: 'u', itemId: '' })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(encryptItem(key, undefined, ctx)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
  });
});

describe('ceo tok: registracija, prijava, promena master lozinke', () => {
  interface ServerRecord {
    salt: string;
    authKey: string;
    wrappedVaultKey: Envelope;
    items: Record<string, Envelope>;
  }

  async function register(password: string): Promise<ServerRecord> {
    const salt = generateSalt();
    const { authKey, kek } = await deriveKeys(password, salt, TEST_PARAMS);
    const { vaultKey, wrappedVaultKey } = await createVault(kek);
    const item = { title: 'GitHub', username: 'stefan', password: 'Str0ng!Pass' };
    const envelope = await encryptItem(vaultKey, item, { userId: 'u1', itemId: 'i1' });
    return {
      salt: toBase64Url(salt),
      authKey: toBase64Url(authKey),
      wrappedVaultKey,
      items: { i1: envelope },
    };
  }

  async function login(server: ServerRecord, password: string) {
    const { authKey, kek } = await deriveKeys(password, fromBase64Url(server.salt), TEST_PARAMS);
    const authOk = constantTimeEqual(authKey, fromBase64Url(server.authKey));
    return { authOk, kek };
  }

  it('ispravna lozinka: Auth kljuc se poklapa i stavka se desifruje', async () => {
    const server = await register('moja lozinka');
    const { authOk, kek } = await login(server, 'moja lozinka');
    expect(authOk).toBe(true);

    const vaultKey = await unwrapVaultKey(server.wrappedVaultKey, kek);
    const item = await decryptItem(vaultKey, server.items['i1'] as Envelope, {
      userId: 'u1',
      itemId: 'i1',
    });
    expect(item).toEqual({ title: 'GitHub', username: 'stefan', password: 'Str0ng!Pass' });
  });

  it('pogresna lozinka: Auth kljuc se ne poklapa i vault se ne otvara', async () => {
    const server = await register('moja lozinka');
    const { authOk, kek } = await login(server, 'pogresna lozinka');
    expect(authOk).toBe(false);
    await expect(unwrapVaultKey(server.wrappedVaultKey, kek)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('server nigde ne cuva lozinku ni otvoreni tekst', async () => {
    const server = await register('moja lozinka');
    const stored = JSON.stringify(server);
    expect(stored).not.toContain('moja lozinka');
    expect(stored).not.toContain('Str0ng!Pass');
    expect(stored).not.toContain('GitHub');
  });

  it('promena master lozinke: nova radi, stara ne, stavke ostaju netaknute', async () => {
    const server = await register('stara lozinka');
    const oldKeys = await login(server, 'stara lozinka');

    const newSalt = generateSalt();
    const newKeys = await deriveKeys('nova lozinka', newSalt, TEST_PARAMS);
    server.wrappedVaultKey = await rewrapVaultKey(server.wrappedVaultKey, oldKeys.kek, newKeys.kek);
    server.salt = toBase64Url(newSalt);
    server.authKey = toBase64Url(newKeys.authKey);

    const fresh = await login(server, 'nova lozinka');
    expect(fresh.authOk).toBe(true);
    const vaultKey = await unwrapVaultKey(server.wrappedVaultKey, fresh.kek);
    expect(
      await decryptItem(vaultKey, server.items['i1'] as Envelope, { userId: 'u1', itemId: 'i1' }),
    ).toMatchObject({ title: 'GitHub' });

    const old = await login(server, 'stara lozinka');
    expect(old.authOk).toBe(false);
    await expect(unwrapVaultKey(server.wrappedVaultKey, old.kek)).rejects.toThrow();
  });
});
