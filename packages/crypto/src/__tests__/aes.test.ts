import { describe, expect, it } from 'vitest';
import {
  IV_LENGTH,
  TAG_LENGTH_BYTES,
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesGcmEncryptWithIv,
} from '../aes';
import { type Bytes, randomBytes, utf8Decode, utf8Encode } from '../bytes';
import { CryptoError } from '../errors';
import { generateSalt, deriveKeys } from '../kdf';

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

function importKey(raw: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

function newKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

const noAad = new Uint8Array(0);

describe('AES-256-GCM: zvanicni vektori (McGrew i Viega, NIST GCM specifikacija)', () => {
  it('test slucaj 13: prazan tekst, nulti kljuc i IV', async () => {
    const out = await aesGcmEncryptWithIv(
      await importKey(new Uint8Array(32)),
      new Uint8Array(12),
      new Uint8Array(0),
      noAad,
    );
    // Sifrat je prazan, ostaje samo tag.
    expect(toHex(out)).toBe('530f8afbc74536b9a963b4f1c4cb738b');
  });

  it('test slucaj 14: 16 nultih bajtova', async () => {
    const out = await aesGcmEncryptWithIv(
      await importKey(new Uint8Array(32)),
      new Uint8Array(12),
      new Uint8Array(16),
      noAad,
    );
    expect(toHex(out)).toBe(
      'cea7403d4d606b6e074ec5d3baf39d18' + 'd0d1c8a799996bf0265b98b5d48ab919',
    );
  });

  it('test slucaj 16: sa dodatnim autentifikovanim podacima (AAD)', async () => {
    const key = await importKey(
      fromHex('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308'),
    );
    const iv = fromHex('cafebabefacedbaddecaf888');
    const plaintext = fromHex(
      'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72' +
        '1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    );
    const aad = fromHex('feedfacedeadbeeffeedfacedeadbeefabaddad2');

    const out = await aesGcmEncryptWithIv(key, iv, plaintext, aad);

    expect(toHex(out)).toBe(
      '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa' +
        '8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662' +
        '76fc6ece0f4e1768cddf8853bb2d551b',
    );
    // I desifrovanje vraca original.
    expect(toHex(await aesGcmDecrypt(key, iv, out, aad))).toBe(toHex(plaintext));
  });
});

describe('aesGcmEncrypt i aesGcmDecrypt', () => {
  it('krug: desifrovanje vraca originalni tekst (ukljucujuci srpska slova)', async () => {
    const key = await newKey();
    const aad = utf8Encode('kontekst');
    const text = 'lozinka: šđčćž 🔐';
    const { iv, ciphertext } = await aesGcmEncrypt(key, utf8Encode(text), aad);
    expect(utf8Decode(await aesGcmDecrypt(key, iv, ciphertext, aad))).toBe(text);
  });

  it('radi i za prazan tekst', async () => {
    const key = await newKey();
    const { iv, ciphertext } = await aesGcmEncrypt(key, new Uint8Array(0), noAad);
    expect(ciphertext).toHaveLength(TAG_LENGTH_BYTES);
    expect(await aesGcmDecrypt(key, iv, ciphertext, noAad)).toHaveLength(0);
  });

  it('sifrat je duzi od teksta tacno za tag', async () => {
    const key = await newKey();
    const { iv, ciphertext } = await aesGcmEncrypt(key, randomBytes(100), noAad);
    expect(iv).toHaveLength(IV_LENGTH);
    expect(ciphertext).toHaveLength(100 + TAG_LENGTH_BYTES);
  });

  it('isti tekst se svaki put sifruje drugacije (novi IV)', async () => {
    const key = await newKey();
    const text = utf8Encode('ista lozinka');
    const a = await aesGcmEncrypt(key, text, noAad);
    const b = await aesGcmEncrypt(key, text, noAad);
    expect(a.iv).not.toEqual(b.iv);
    expect(a.ciphertext).not.toEqual(b.ciphertext);
  });

  it('2000 sifrovanja daje 2000 razlicitih IV-ova', async () => {
    const key = await newKey();
    const seen = new Set<string>();
    for (let i = 0; i < 2000; i++) {
      const { iv } = await aesGcmEncrypt(key, new Uint8Array(1), noAad);
      seen.add(toHex(iv));
    }
    expect(seen.size).toBe(2000);
  });
});

describe('aesGcmDecrypt odbija sve sto nije neizmenjeno', () => {
  async function encrypted() {
    const key = await newKey();
    const aad = utf8Encode('stavka-1');
    const { iv, ciphertext } = await aesGcmEncrypt(key, utf8Encode('tajna'), aad);
    return { key, aad, iv, ciphertext };
  }

  it('izmenjen bajt u sifratu', async () => {
    const { key, aad, iv, ciphertext } = await encrypted();
    const tampered = new Uint8Array(ciphertext);
    tampered[0] = (tampered[0] ?? 0) ^ 1;
    await expect(aesGcmDecrypt(key, iv, tampered, aad)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('izmenjen tag na kraju', async () => {
    const { key, aad, iv, ciphertext } = await encrypted();
    const tampered = new Uint8Array(ciphertext);
    const last = tampered.length - 1;
    tampered[last] = (tampered[last] ?? 0) ^ 1;
    await expect(aesGcmDecrypt(key, iv, tampered, aad)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('odsecen sifrat', async () => {
    const { key, aad, iv, ciphertext } = await encrypted();
    await expect(aesGcmDecrypt(key, iv, ciphertext.slice(0, -1), aad)).rejects.toThrow(CryptoError);
  });

  it('pogresan AAD (server je zamenio sifrat izmedju stavki)', async () => {
    const { key, iv, ciphertext } = await encrypted();
    await expect(aesGcmDecrypt(key, iv, ciphertext, utf8Encode('stavka-2'))).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('pogresan kljuc', async () => {
    const { aad, iv, ciphertext } = await encrypted();
    await expect(aesGcmDecrypt(await newKey(), iv, ciphertext, aad)).rejects.toMatchObject({
      code: 'DECRYPT_FAILED',
    });
  });

  it('pogresan IV', async () => {
    const { key, aad, ciphertext } = await encrypted();
    await expect(aesGcmDecrypt(key, randomBytes(IV_LENGTH), ciphertext, aad)).rejects.toMatchObject(
      {
        code: 'DECRYPT_FAILED',
      },
    );
  });

  it('IV pogresne duzine je greska ulaza, a ne desifrovanja', async () => {
    const { key, aad, ciphertext } = await encrypted();
    await expect(aesGcmDecrypt(key, randomBytes(8), ciphertext, aad)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(
      aesGcmEncryptWithIv(key, randomBytes(16), new Uint8Array(1), noAad),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

describe('razdvajanje uloga kljuceva', () => {
  it('KEK (kljuc za umotavanje) ne moze direktno da sifruje stavke', async () => {
    const { kek } = await deriveKeys('lozinka', generateSalt(), {
      memoryKiB: 1024,
      iterations: 1,
      parallelism: 1,
    });
    await expect(aesGcmEncrypt(kek, utf8Encode('x'), noAad)).rejects.toThrow();
  });
});
