import { describe, expect, it } from 'vitest';
import { toBase64Url } from '../bytes';
import { CryptoError } from '../errors';
import { type KdfParams, deriveKeys, generateSalt } from '../kdf';
import {
  RECOVERY_ALPHABET,
  RECOVERY_CODE_LENGTH,
  deriveRecoveryKeys,
  formatRecoveryCode,
  generateRecoveryCode,
  generateRecoveryCodes,
  normalizeRecoveryCode,
  recoveryAuthToString,
} from '../recovery';
import { createVault, rewrapVaultKey, unwrapVaultKey, wrapVaultKey } from '../vault';

const PARAMS: KdfParams = { memoryKiB: 1024, iterations: 1, parallelism: 1 };

describe('generateRecoveryCode', () => {
  it('pravi 10 znakova iz azbuke bez dvosmislenih (I, O, 0, 1)', () => {
    for (let i = 0; i < 200; i++) {
      const code = generateRecoveryCode();
      expect(code).toHaveLength(RECOVERY_CODE_LENGTH);
      for (const char of code) expect(RECOVERY_ALPHABET).toContain(char);
      expect(code).not.toMatch(/[IO01]/);
    }
    expect(RECOVERY_ALPHABET).toHaveLength(32);
    expect(new Set(RECOVERY_ALPHABET).size).toBe(32);
  });

  it('sadrzi i slova i cifre (u skupu je 24 slova i 8 cifara)', () => {
    const joined = Array.from({ length: 300 }, generateRecoveryCode).join('');
    expect(joined).toMatch(/[A-Z]/);
    expect(joined).toMatch(/[2-9]/);
  });

  it('svaki znak azbuke se pojavljuje priblizno podjednako (bez pristrasnosti)', () => {
    const counts = new Map<string, number>();
    const draws = 3000; // 30 000 znakova, ocekivano ~937 po znaku
    for (let i = 0; i < draws; i++) {
      for (const char of generateRecoveryCode()) counts.set(char, (counts.get(char) ?? 0) + 1);
    }
    expect(counts.size).toBe(32);
    for (const count of counts.values()) {
      expect(count).toBeGreaterThan(750);
      expect(count).toBeLessThan(1130);
    }
  });
});

describe('generateRecoveryCodes', () => {
  it('pravi trazeni broj razlicitih kodova', () => {
    const codes = generateRecoveryCodes(20);
    expect(codes).toHaveLength(20);
    expect(new Set(codes).size).toBe(20);
  });

  it('odbija neispravan broj', () => {
    for (const bad of [0, -1, 1.5, 101, Number.NaN]) {
      expect(() => generateRecoveryCodes(bad)).toThrow(CryptoError);
    }
  });
});

describe('normalizeRecoveryCode / formatRecoveryCode', () => {
  it('prihvata malim slovima, sa crticom, razmacima i tabovima', () => {
    expect(normalizeRecoveryCode('abcde-fghjk')).toBe('ABCDEFGHJK');
    expect(normalizeRecoveryCode(' ABCDE FGHJK ')).toBe('ABCDEFGHJK');
    expect(normalizeRecoveryCode('ab cd-ef\tgh jk')).toBe('ABCDEFGHJK');
    expect(normalizeRecoveryCode('ABCDEFGHJK')).toBe('ABCDEFGHJK');
  });

  it('prikazuje u obliku 5-5', () => {
    expect(formatRecoveryCode('abcdefghjk')).toBe('ABCDE-FGHJK');
    expect(formatRecoveryCode('ABCDE-FGHJK')).toBe('ABCDE-FGHJK');
    expect(formatRecoveryCode(generateRecoveryCode())).toMatch(/^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
  });

  it('odbija pogresnu duzinu i znakove van azbuke', () => {
    const bad = [
      '',
      'ABCDE',
      'ABCDE-FGHJ',
      'ABCDE-FGHJKL',
      'ABCDE-FGHJ0',
      'ABCDE-FGHJ1',
      'ABCDE-FGHIK',
      'ABCDE-FGHOK',
      'ABCDE-FGHJ!',
    ];
    for (const value of bad) {
      expect(() => normalizeRecoveryCode(value), value).toThrow(CryptoError);
      expect(() => formatRecoveryCode(value), value).toThrow(CryptoError);
    }
  });
});

describe('deriveRecoveryKeys', () => {
  const salt = generateSalt();

  it('isti kod i so daju iste kljuceve, a razliciti kod ili so razlicite', async () => {
    const a = await deriveRecoveryKeys('ABCDE-FGHJK', salt, PARAMS);
    const same = await deriveRecoveryKeys('abcdefghjk', salt, PARAMS);
    const otherCode = await deriveRecoveryKeys('ABCDE-FGHJL', salt, PARAMS);
    const otherSalt = await deriveRecoveryKeys('ABCDE-FGHJK', generateSalt(), PARAMS);
    expect(toBase64Url(a.authKey)).toBe(toBase64Url(same.authKey));
    expect(toBase64Url(a.authKey)).not.toBe(toBase64Url(otherCode.authKey));
    expect(toBase64Url(a.authKey)).not.toBe(toBase64Url(otherSalt.authKey));
    expect(a.authKey).toHaveLength(32);
    expect(recoveryAuthToString(a.authKey)).toHaveLength(43);
  });

  it('KEK je neizvoziv AES-GCM kljuc samo za umotavanje', async () => {
    const { kek } = await deriveRecoveryKeys('ABCDE-FGHJK', salt, PARAMS);
    expect(kek.extractable).toBe(false);
    expect(kek.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    expect([...kek.usages].sort()).toEqual(['unwrapKey', 'wrapKey']);
  });

  it('kljucevi iz koda se nikad ne poklapaju sa kljucevima iz lozinke (razdvajanje domena)', async () => {
    const code = 'ABCDEFGHJK';
    const fromCode = await deriveRecoveryKeys(code, salt, PARAMS);
    const fromPassword = await deriveKeys(code, salt, PARAMS);
    expect(toBase64Url(fromCode.authKey)).not.toBe(toBase64Url(fromPassword.authKey));
  });

  it('odbija los kod i prekratku so', async () => {
    await expect(deriveRecoveryKeys('KRATAK', salt, PARAMS)).rejects.toBeInstanceOf(CryptoError);
    await expect(
      deriveRecoveryKeys('ABCDE-FGHJK', new Uint8Array(8), PARAMS),
    ).rejects.toBeInstanceOf(CryptoError);
  });

  it('cela tacka: Vault Key umotan kodom otvara se samo tim kodom, a prenosi se na novu lozinku', async () => {
    const master = await deriveKeys('stara lozinka', generateSalt(), PARAMS);
    const { wrappedVaultKey } = await createVault(master.kek);
    const extractable = await unwrapVaultKey(wrappedVaultKey, master.kek, { extractable: true });

    const code = generateRecoveryCode();
    const recovery = await deriveRecoveryKeys(code, salt, PARAMS);
    const blob = await wrapVaultKey(extractable, recovery.kek);

    // Pogresan kod ne otvara.
    const wrong = await deriveRecoveryKeys(generateRecoveryCode(), salt, PARAMS);
    await expect(unwrapVaultKey(blob, wrong.kek)).rejects.toBeInstanceOf(CryptoError);

    // Pravi kod otvara, pa se ponovo umotava novom lozinkom.
    const next = await deriveKeys('nova lozinka', generateSalt(), PARAMS);
    const rewrapped = await rewrapVaultKey(blob, recovery.kek, next.kek);
    const reopened = await unwrapVaultKey(rewrapped, next.kek, { extractable: true });
    const original = new Uint8Array(await crypto.subtle.exportKey('raw', extractable));
    const restored = new Uint8Array(await crypto.subtle.exportKey('raw', reopened));
    expect(toBase64Url(restored)).toBe(toBase64Url(original));
  });
});
