import { describe, expect, it } from 'vitest';
import {
  authKeySchema,
  challengeIdSchema,
  emailSchema,
  otpCodeSchema,
  preloginRequestSchema,
  registerRequestSchema,
  verifyCodeRequestSchema,
  wrappedKeyEnvelopeSchema,
  accessTokenResponseSchema,
  loginRequestSchema,
  meResponseSchema,
} from '../auth';

const authKey = 'A'.repeat(43);
const envelope = { v: 1, iv: 'A'.repeat(16), ct: 'A'.repeat(64) };
const validRegister = {
  email: 'korisnik@example.com',
  authKey,
  kdfSalt: 'A'.repeat(22),
  kdfMemoryKiB: 65536,
  kdfIterations: 3,
  kdfParallelism: 1,
  wrappedVaultKey: envelope,
};

describe('emailSchema', () => {
  it('normalizuje: uklanja razmake i pravi mala slova', () => {
    expect(emailSchema.parse('  Korisnik@Example.COM  ')).toBe('korisnik@example.com');
  });

  it('odbija neispravne adrese', () => {
    for (const bad of ['', 'bez-znaka', '@example.com', 'a@', 'a b@example.com', 'a@b', 42, null]) {
      expect(emailSchema.safeParse(bad).success).toBe(false);
    }
  });

  it('odbija predugacku adresu', () => {
    expect(emailSchema.safeParse(`${'a'.repeat(250)}@example.com`).success).toBe(false);
  });
});

describe('authKeySchema', () => {
  it('prihvata tacno 43 znaka base64url, a odbija sve drugo', () => {
    expect(authKeySchema.safeParse(authKey).success).toBe(true);
    for (const bad of [
      'A'.repeat(42),
      'A'.repeat(44),
      `${'A'.repeat(42)}=`,
      `${'A'.repeat(42)}+`,
      '',
    ]) {
      expect(authKeySchema.safeParse(bad).success).toBe(false);
    }
  });
});

describe('otpCodeSchema i challengeIdSchema', () => {
  it('kod je tacno 6 cifara', () => {
    expect(otpCodeSchema.safeParse('012345').success).toBe(true);
    for (const bad of ['12345', '1234567', 'abcdef', '12345 ', '١٢٣٤٥٦', 123456]) {
      expect(otpCodeSchema.safeParse(bad).success).toBe(false);
    }
  });

  it('izazov je UUID', () => {
    expect(challengeIdSchema.safeParse('3f2b8c1e-7a44-4d0b-9a55-1c2d3e4f5a6b').success).toBe(true);
    expect(challengeIdSchema.safeParse('nije-uuid').success).toBe(false);
  });
});

describe('wrappedKeyEnvelopeSchema', () => {
  it('prihvata tacne duzine, a odbija pogresnu verziju, duzine i dodatna polja', () => {
    expect(wrappedKeyEnvelopeSchema.safeParse(envelope).success).toBe(true);
    expect(wrappedKeyEnvelopeSchema.safeParse({ ...envelope, v: 2 }).success).toBe(false);
    expect(wrappedKeyEnvelopeSchema.safeParse({ ...envelope, iv: 'A'.repeat(15) }).success).toBe(
      false,
    );
    expect(wrappedKeyEnvelopeSchema.safeParse({ ...envelope, ct: 'A'.repeat(65) }).success).toBe(
      false,
    );
    expect(wrappedKeyEnvelopeSchema.safeParse({ ...envelope, extra: 1 }).success).toBe(false);
  });
});

describe('registerRequestSchema', () => {
  it('prihvata ispravan zahtev i normalizuje email', () => {
    const parsed = registerRequestSchema.parse({
      ...validRegister,
      email: ' Korisnik@EXAMPLE.com ',
    });
    expect(parsed.email).toBe('korisnik@example.com');
  });

  it('odbija nepoznata polja (npr. pokusaj slanja lozinke ili uloge)', () => {
    expect(registerRequestSchema.safeParse({ ...validRegister, password: 'tajna' }).success).toBe(
      false,
    );
    expect(registerRequestSchema.safeParse({ ...validRegister, isAdmin: true }).success).toBe(
      false,
    );
  });

  it('odbija nedostajuca i neispravna polja', () => {
    for (const key of Object.keys(validRegister)) {
      const copy: Record<string, unknown> = { ...validRegister };
      delete copy[key];
      expect(registerRequestSchema.safeParse(copy).success).toBe(false);
    }
    expect(registerRequestSchema.safeParse({ ...validRegister, kdfMemoryKiB: 1.5 }).success).toBe(
      false,
    );
    expect(registerRequestSchema.safeParse({ ...validRegister, kdfIterations: '3' }).success).toBe(
      false,
    );
    expect(registerRequestSchema.safeParse(null).success).toBe(false);
    expect(registerRequestSchema.safeParse(undefined).success).toBe(false);
  });
});

describe('ostali zahtevi', () => {
  it('prelogin trazi samo email', () => {
    expect(preloginRequestSchema.parse({ email: 'A@Example.com' })).toEqual({
      email: 'a@example.com',
    });
    expect(preloginRequestSchema.safeParse({ email: 'a@example.com', x: 1 }).success).toBe(false);
  });

  it('verifikacija koda trazi izazov i kod', () => {
    const ok = { challengeId: '3f2b8c1e-7a44-4d0b-9a55-1c2d3e4f5a6b', code: '123456' };
    expect(verifyCodeRequestSchema.safeParse(ok).success).toBe(true);
    expect(verifyCodeRequestSchema.safeParse({ ...ok, code: '12' }).success).toBe(false);
    expect(verifyCodeRequestSchema.safeParse({ code: '123456' }).success).toBe(false);
  });
});

describe('prijava i odgovori', () => {
  it('login trazi tacno email i Auth kljuc', () => {
    expect(loginRequestSchema.parse({ email: ' A@Example.com ', authKey })).toEqual({
      email: 'a@example.com',
      authKey,
    });
    expect(loginRequestSchema.safeParse({ email: 'a@example.com' }).success).toBe(false);
    expect(
      loginRequestSchema.safeParse({ email: 'a@example.com', authKey: 'kratak' }).success,
    ).toBe(false);
    expect(
      loginRequestSchema.safeParse({ email: 'a@example.com', authKey, password: 'x' }).success,
    ).toBe(false);
  });

  it('odgovor sa tokenom trazi JWT oblika i pozitivan rok', () => {
    const ok = { accessToken: 'aaa.bbb.ccc', expiresIn: 900 };
    expect(accessTokenResponseSchema.safeParse(ok).success).toBe(true);
    expect(accessTokenResponseSchema.safeParse({ ...ok, accessToken: 'nije-jwt' }).success).toBe(
      false,
    );
    expect(accessTokenResponseSchema.safeParse({ ...ok, expiresIn: 0 }).success).toBe(false);
    expect(accessTokenResponseSchema.safeParse({ ...ok, refreshToken: 'x' }).success).toBe(false);
  });

  it('odgovor me sadrzi KDF parametre i umotani kljuc, i nista vise', () => {
    const { kdfSalt, kdfMemoryKiB, kdfIterations, kdfParallelism, wrappedVaultKey } = validRegister;
    const ok = {
      id: '3f2b8c1e-7a44-4d0b-9a55-1c2d3e4f5a6b',
      email: 'korisnik@example.com',
      kdfSalt,
      kdfMemoryKiB,
      kdfIterations,
      kdfParallelism,
      wrappedVaultKey,
    };
    expect(meResponseSchema.safeParse(ok).success).toBe(true);
    expect(meResponseSchema.safeParse({ ...ok, authHash: 'x' }).success).toBe(false);
    expect(meResponseSchema.safeParse({ ...ok, id: 'nije-uuid' }).success).toBe(false);
  });
});
