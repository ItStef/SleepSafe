import { describe, expect, it } from 'vitest';
import { type Bytes, constantTimeEqual, randomBytes, utf8Encode } from '../bytes';
import { CryptoError } from '../errors';
import {
  DEFAULT_KDF_PARAMS,
  type KdfParams,
  SALT_LENGTH,
  argon2idRaw,
  assertAcceptableKdfParams,
  deriveKeys,
  deriveMasterKey,
  generateSalt,
  hkdfSha256,
} from '../kdf';

const TEST_PARAMS: KdfParams = { memoryKiB: 1024, iterations: 1, parallelism: 1 };

function fromHex(hex: string): Bytes {
  const clean = hex.replaceAll(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('Argon2id', () => {
  it('poklapa se sa vektorom iz referentne implementacije (phc-winner-argon2, test.c)', async () => {
    // password="password", salt="somesalt", m=65536 KiB, t=2, p=1, izlaz 32 bajta
    const key = await argon2idRaw(utf8Encode('password'), utf8Encode('somesalt'), {
      memoryKiB: 65536,
      iterations: 2,
      parallelism: 1,
    });
    expect(toHex(key)).toBe('09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7');
  });

  it('odbija neispravne parametre', async () => {
    const pw = utf8Encode('x');
    const salt = randomBytes(16);
    await expect(
      argon2idRaw(pw, salt, { memoryKiB: 4, iterations: 1, parallelism: 1 }),
    ).rejects.toThrow(CryptoError);
    await expect(
      argon2idRaw(pw, salt, { memoryKiB: 1024, iterations: 0, parallelism: 1 }),
    ).rejects.toThrow(CryptoError);
    await expect(
      argon2idRaw(pw, salt, { memoryKiB: 1024, iterations: 1, parallelism: 1.5 }),
    ).rejects.toThrow(CryptoError);
  });
});

describe('HKDF-SHA256', () => {
  it('RFC 5869, test slucaj 1', async () => {
    const okm = await hkdfSha256(
      fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      fromHex('000102030405060708090a0b0c'),
      fromHex('f0f1f2f3f4f5f6f7f8f9'),
      42,
    );
    expect(toHex(okm)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });

  it('RFC 5869, test slucaj 3 (prazna so i prazan info)', async () => {
    const okm = await hkdfSha256(
      fromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      new Uint8Array(0),
      new Uint8Array(0),
      42,
    );
    expect(toHex(okm)).toBe(
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
    );
  });

  it('razliciti info daje nezavisne kljuceve', async () => {
    const ikm = randomBytes(32);
    const a = await hkdfSha256(ikm, new Uint8Array(0), utf8Encode('a'), 32);
    const b = await hkdfSha256(ikm, new Uint8Array(0), utf8Encode('b'), 32);
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it('odbija neispravnu duzinu', async () => {
    const empty = new Uint8Array(0);
    await expect(hkdfSha256(randomBytes(32), empty, empty, 0)).rejects.toThrow(CryptoError);
    await expect(hkdfSha256(randomBytes(32), empty, empty, 8161)).rejects.toThrow(CryptoError);
  });
});

describe('deriveMasterKey', () => {
  it('je deterministican za iste ulaze', async () => {
    const salt = generateSalt();
    const a = await deriveMasterKey('lozinka', salt, TEST_PARAMS);
    const b = await deriveMasterKey('lozinka', salt, TEST_PARAMS);
    expect(a).toHaveLength(32);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it('razlicita lozinka, so ili parametri daju razlicit kljuc', async () => {
    const salt = generateSalt();
    const base = await deriveMasterKey('lozinka', salt, TEST_PARAMS);
    const otherPassword = await deriveMasterKey('lozinka2', salt, TEST_PARAMS);
    const otherSalt = await deriveMasterKey('lozinka', generateSalt(), TEST_PARAMS);
    const otherParams = await deriveMasterKey('lozinka', salt, { ...TEST_PARAMS, iterations: 2 });
    expect(constantTimeEqual(base, otherPassword)).toBe(false);
    expect(constantTimeEqual(base, otherSalt)).toBe(false);
    expect(constantTimeEqual(base, otherParams)).toBe(false);
  });

  it('normalizuje unicode (NFKC): slovo e sa akcentom u dva zapisa je ista lozinka', async () => {
    const salt = generateSalt();
    // \u00e9 je jedan znak (é), a e + \u0301 je isti znak zapisan kao dva koda.
    const composed = await deriveMasterKey('caf\u00e9', salt, TEST_PARAMS);
    const decomposed = await deriveMasterKey('cafe\u0301', salt, TEST_PARAMS);
    expect(constantTimeEqual(composed, decomposed)).toBe(true);
  });

  it('odbija praznu lozinku i prekratku so', async () => {
    await expect(deriveMasterKey('', generateSalt(), TEST_PARAMS)).rejects.toThrow(CryptoError);
    await expect(deriveMasterKey('x', randomBytes(SALT_LENGTH - 1), TEST_PARAMS)).rejects.toThrow(
      CryptoError,
    );
  });
});

describe('deriveKeys', () => {
  it('daje Auth kljuc od 32 bajta koji nije Master Key', async () => {
    const salt = generateSalt();
    const { authKey } = await deriveKeys('lozinka', salt, TEST_PARAMS);
    const masterKey = await deriveMasterKey('lozinka', salt, TEST_PARAMS);
    expect(authKey).toHaveLength(32);
    expect(constantTimeEqual(authKey, masterKey)).toBe(false);
  });

  it('je deterministican, a druga lozinka daje drugi Auth kljuc', async () => {
    const salt = generateSalt();
    const a = await deriveKeys('lozinka', salt, TEST_PARAMS);
    const b = await deriveKeys('lozinka', salt, TEST_PARAMS);
    const c = await deriveKeys('druga', salt, TEST_PARAMS);
    expect(constantTimeEqual(a.authKey, b.authKey)).toBe(true);
    expect(constantTimeEqual(a.authKey, c.authKey)).toBe(false);
  });

  it('KEK je AES-256-GCM kljuc koji se ne moze izvesti i sluzi samo za umotavanje', async () => {
    const { kek } = await deriveKeys('lozinka', generateSalt(), TEST_PARAMS);
    expect(kek.type).toBe('secret');
    expect(kek.extractable).toBe(false);
    expect(kek.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 });
    expect([...kek.usages].sort()).toEqual(['unwrapKey', 'wrapKey']);
  });

  it('isti KEK se izvodi iz iste lozinke i soli, a drugi iz druge lozinke', async () => {
    const salt = generateSalt();
    const first = await deriveKeys('lozinka', salt, TEST_PARAMS);
    const second = await deriveKeys('lozinka', salt, TEST_PARAMS);
    const other = await deriveKeys('druga', salt, TEST_PARAMS);

    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
      'encrypt',
      'decrypt',
    ]);
    const iv = randomBytes(12);
    const alg = { name: 'AES-GCM', iv };
    const wrapped = await crypto.subtle.wrapKey('raw', key, first.kek, alg);

    await expect(
      crypto.subtle.unwrapKey('raw', wrapped, second.kek, alg, 'AES-GCM', false, ['decrypt']),
    ).resolves.toBeDefined();
    await expect(
      crypto.subtle.unwrapKey('raw', wrapped, other.kek, alg, 'AES-GCM', false, ['decrypt']),
    ).rejects.toThrow();
  });
});

describe('assertAcceptableKdfParams', () => {
  it('prihvata podrazumevane parametre', () => {
    expect(() => assertAcceptableKdfParams(DEFAULT_KDF_PARAMS)).not.toThrow();
  });

  it('odbija preslabe parametre (downgrade napad)', () => {
    expect(() => assertAcceptableKdfParams({ ...DEFAULT_KDF_PARAMS, memoryKiB: 1024 })).toThrow(
      CryptoError,
    );
    expect(() => assertAcceptableKdfParams({ ...DEFAULT_KDF_PARAMS, iterations: 1 })).toThrow(
      CryptoError,
    );
  });

  it('odbija preterano velike parametre (zastita od iscrpljivanja memorije)', () => {
    expect(() =>
      assertAcceptableKdfParams({ ...DEFAULT_KDF_PARAMS, memoryKiB: 4 * 1024 * 1024 }),
    ).toThrow(CryptoError);
    expect(() => assertAcceptableKdfParams({ ...DEFAULT_KDF_PARAMS, iterations: 100 })).toThrow(
      CryptoError,
    );
    expect(() => assertAcceptableKdfParams({ ...DEFAULT_KDF_PARAMS, parallelism: 64 })).toThrow(
      CryptoError,
    );
  });

  it('odbija besmislene vrednosti', () => {
    expect(() =>
      assertAcceptableKdfParams({ ...DEFAULT_KDF_PARAMS, iterations: Number.NaN }),
    ).toThrow(CryptoError);
  });
});
