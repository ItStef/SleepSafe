import { describe, expect, it } from 'vitest';
import {
  concatBytes,
  constantTimeEqual,
  fromBase64Url,
  randomBytes,
  toBase64Url,
  utf8Decode,
  utf8Encode,
} from '../bytes';
import { CryptoError } from '../errors';

describe('randomBytes', () => {
  it('vraca trazenu duzinu', () => {
    expect(randomBytes(0)).toHaveLength(0);
    expect(randomBytes(32)).toHaveLength(32);
  });

  it('svaki poziv daje razlicite bajtove', () => {
    expect(randomBytes(32)).not.toEqual(randomBytes(32));
  });

  it('odbija neispravnu duzinu', () => {
    expect(() => randomBytes(-1)).toThrow(CryptoError);
    expect(() => randomBytes(1.5)).toThrow(CryptoError);
    expect(() => randomBytes(65537)).toThrow(CryptoError);
  });
});

describe('base64url', () => {
  const vectors: [string, string][] = [
    ['', ''],
    ['f', 'Zg'],
    ['fo', 'Zm8'],
    ['foo', 'Zm9v'],
    ['foob', 'Zm9vYg'],
    ['fooba', 'Zm9vYmE'],
    ['foobar', 'Zm9vYmFy'],
  ];

  it.each(vectors)('kodira "%s" u "%s"', (plain, encoded) => {
    expect(toBase64Url(utf8Encode(plain))).toBe(encoded);
  });

  it.each(vectors)('dekodira "%s" nazad u "%s"', (plain, encoded) => {
    expect(utf8Decode(fromBase64Url(encoded))).toBe(plain);
  });

  it('koristi - i _ umesto + i /', () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe]);
    expect(toBase64Url(bytes)).toBe('-__-');
  });

  it('krug: dekodiranje vraca iste bajtove za sve duzine', () => {
    for (let length = 0; length < 70; length++) {
      const bytes = randomBytes(length);
      expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
    }
  });

  it('odbija nedozvoljene karaktere i punjenje', () => {
    expect(() => fromBase64Url('Zm9v+')).toThrow(CryptoError);
    expect(() => fromBase64Url('Zm9v/')).toThrow(CryptoError);
    expect(() => fromBase64Url('Zg==')).toThrow(CryptoError);
    expect(() => fromBase64Url('Z')).toThrow(CryptoError);
  });

  it('odbija nekanonski oblik (neiskorisceni bitovi nisu nula)', () => {
    expect(() => fromBase64Url('Zh')).toThrow(CryptoError);
  });
});

describe('constantTimeEqual', () => {
  it('prepoznaje jednake i razlicite nizove', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(constantTimeEqual(new Uint8Array([9, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(false);
  });

  it('razlicite duzine nisu jednake', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });

  it('dva prazna niza su jednaka', () => {
    expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

describe('concatBytes i utf8', () => {
  it('spaja delove redom', () => {
    const out = concatBytes(new Uint8Array([1, 2]), new Uint8Array([3]), new Uint8Array(0));
    expect(out).toEqual(new Uint8Array([1, 2, 3]));
  });

  it('utf8 krug cuva srpska slova i emoji', () => {
    const text = 'šđčćž ŠĐČĆŽ 🔐';
    expect(utf8Decode(utf8Encode(text))).toBe(text);
  });

  it('utf8Decode odbija neispravan niz bajtova', () => {
    expect(() => utf8Decode(new Uint8Array([0xff, 0xfe]))).toThrow();
  });
});
