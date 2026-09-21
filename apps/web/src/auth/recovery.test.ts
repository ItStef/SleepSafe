import {
  createVault,
  deriveKeys,
  deriveRecoveryKeys,
  fromBase64Url,
  generateSalt,
  toBase64Url,
  unwrapVaultKey,
} from '@sleepsafe/crypto';
import { recoveryBundleSchema } from '@sleepsafe/shared';
import { describe, expect, it } from 'vitest';
import { type KeyDeriver, inlineDeriver } from '../crypto/deriver';
import { TEST_KDF } from '../test/fakeServer';
import { RECOVERY_CONCURRENCY, buildRecoveryBundle } from './recovery';

async function exportableVaultKey() {
  const master = await deriveKeys('pomocna lozinka', generateSalt(), TEST_KDF);
  const { wrappedVaultKey } = await createVault(master.kek);
  return unwrapVaultKey(wrappedVaultKey, master.kek, { extractable: true });
}

const rawKey = async (key: CryptoKey) =>
  toBase64Url(new Uint8Array(await crypto.subtle.exportKey('raw', key)));

describe('buildRecoveryBundle', () => {
  it('pravi trazeni broj razlicitih kodova i paket koji prolazi semu servera', async () => {
    const vaultKey = await exportableVaultKey();
    const { bundle, codes } = await buildRecoveryBundle({
      deriver: inlineDeriver,
      vaultKey,
      count: 20,
      params: TEST_KDF,
    });
    expect(codes).toHaveLength(20);
    expect(new Set(codes).size).toBe(20);
    expect(recoveryBundleSchema.safeParse(bundle).success).toBe(true);
    expect(bundle.kdfMemoryKiB).toBe(TEST_KDF.memoryKiB);
    expect(bundle.kdfIterations).toBe(TEST_KDF.iterations);
  });

  it('svaki kod otvara svoj omotac i to je isti Vault Key; server dobija samo izvedene vrednosti', async () => {
    const vaultKey = await exportableVaultKey();
    const { bundle, codes } = await buildRecoveryBundle({
      deriver: inlineDeriver,
      vaultKey,
      count: 4,
      params: TEST_KDF,
    });
    const salt = fromBase64Url(bundle.kdfSalt);
    const original = await rawKey(vaultKey);

    for (const [index, code] of codes.entries()) {
      const keys = await deriveRecoveryKeys(code, salt, TEST_KDF);
      const entry = bundle.codes[index];
      if (!entry) throw new Error('missing entry');
      expect(entry.authKey).toBe(toBase64Url(keys.authKey));
      const opened = await unwrapVaultKey(entry.wrappedVaultKey, keys.kek, { extractable: true });
      expect(await rawKey(opened)).toBe(original);

      // Kod nigde nije u paketu: ni sam, ni bez crtice.
      expect(JSON.stringify(bundle)).not.toContain(code);
    }
    // Omotac jednog koda ne otvara se kljucem drugog.
    const other = await deriveRecoveryKeys(codes[1] as string, salt, TEST_KDF);
    const first = bundle.codes[0];
    if (!first) throw new Error('missing entry');
    await expect(unwrapVaultKey(first.wrappedVaultKey, other.kek)).rejects.toThrow();
  });

  it('kljuc koji se ne moze izvesti (neizvoziv) se odbija', async () => {
    const master = await deriveKeys('x lozinka', generateSalt(), TEST_KDF);
    const { vaultKey } = await createVault(master.kek); // neizvoziv
    await expect(
      buildRecoveryBundle({ deriver: inlineDeriver, vaultKey, count: 2, params: TEST_KDF }),
    ).rejects.toThrow();
  });

  it('radi ograniceno paralelno: nikad vise izvodjenja odjednom od zadatog', async () => {
    let running = 0;
    let peak = 0;
    const counting: KeyDeriver = {
      derive: inlineDeriver.derive,
      deriveRecovery: async (code, salt, params) => {
        running += 1;
        peak = Math.max(peak, running);
        await new Promise((resolve) => setTimeout(resolve, 5));
        const keys = await inlineDeriver.deriveRecovery(code, salt, params);
        running -= 1;
        return keys;
      },
    };
    const vaultKey = await exportableVaultKey();
    await buildRecoveryBundle({
      deriver: counting,
      vaultKey,
      count: 8,
      params: TEST_KDF,
      concurrency: 2,
    });
    expect(peak).toBe(2);

    peak = 0;
    await buildRecoveryBundle({ deriver: counting, vaultKey, count: 8, params: TEST_KDF });
    expect(peak).toBe(RECOVERY_CONCURRENCY);
  });

  it('paket ima izvedene vrednosti u redosledu kodova, a greska pri izvodjenju prekida sve', async () => {
    const failing: KeyDeriver = {
      derive: inlineDeriver.derive,
      deriveRecovery: async () => {
        throw new Error('worker pao');
      },
    };
    const vaultKey = await exportableVaultKey();
    await expect(
      buildRecoveryBundle({ deriver: failing, vaultKey, count: 3, params: TEST_KDF }),
    ).rejects.toThrow('worker pao');
  });
});
