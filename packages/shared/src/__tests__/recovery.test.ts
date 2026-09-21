import { describe, expect, it } from 'vitest';
import {
  recoveryResetRequestSchema,
  recoveryStartRequestSchema,
  recoveryStartResponseSchema,
  recoveryStatusSchema,
  recoveryVerifyResponseSchema,
  replaceRecoveryCodesRequestSchema,
} from '../recovery';

const id = '3f2b8c1e-7a44-4d0b-9a55-1c2d3e4f5a6b';
const key = 'A'.repeat(43);
const envelope = { v: 1, iv: 'A'.repeat(16), ct: 'A'.repeat(64) };
const kdf = { kdfSalt: 'B'.repeat(22), kdfMemoryKiB: 65536, kdfIterations: 3, kdfParallelism: 1 };

describe('recoveryStartRequestSchema / recoveryStartResponseSchema', () => {
  it('normalizuje email i odbija nepoznata polja', () => {
    expect(recoveryStartRequestSchema.parse({ email: ' A@Example.com ' }).email).toBe(
      'a@example.com',
    );
    expect(recoveryStartRequestSchema.safeParse({ email: 'a@example.com', x: 1 }).success).toBe(
      false,
    );
    expect(recoveryStartRequestSchema.safeParse({ email: 'nije-email' }).success).toBe(false);
  });

  it('odgovor nosi challengeId i parametre za izvodjenje kljuceva', () => {
    expect(recoveryStartResponseSchema.safeParse({ challengeId: id, ...kdf }).success).toBe(true);
    expect(recoveryStartResponseSchema.safeParse({ challengeId: id }).success).toBe(false);
  });
});

describe('recoveryVerifyResponseSchema', () => {
  const valid = {
    resetId: id,
    resetToken: key,
    codes: [{ id, wrappedVaultKey: envelope }],
  };

  it('prihvata 1 do 20 kodova, a ne prazan ni prevelik niz', () => {
    expect(recoveryVerifyResponseSchema.safeParse(valid).success).toBe(true);
    expect(recoveryVerifyResponseSchema.safeParse({ ...valid, codes: [] }).success).toBe(false);
    const many = Array.from({ length: 21 }, () => ({ id, wrappedVaultKey: envelope }));
    expect(recoveryVerifyResponseSchema.safeParse({ ...valid, codes: many }).success).toBe(false);
  });

  it('odbija los token i dodatna polja', () => {
    expect(recoveryVerifyResponseSchema.safeParse({ ...valid, resetToken: 'kratak' }).success).toBe(
      false,
    );
    expect(recoveryVerifyResponseSchema.safeParse({ ...valid, extra: 1 }).success).toBe(false);
  });
});

describe('recoveryResetRequestSchema', () => {
  const valid = {
    resetId: id,
    resetToken: key,
    codeId: id,
    recoveryAuth: key,
    newAuthKey: key,
    ...kdf,
    wrappedVaultKey: envelope,
  };

  it('prihvata ispravan zahtev, odbija nedostajuca i dodatna polja', () => {
    expect(recoveryResetRequestSchema.safeParse(valid).success).toBe(true);
    expect(recoveryResetRequestSchema.safeParse({ ...valid, password: 'tajna' }).success).toBe(
      false,
    );
    const missing: Record<string, unknown> = { ...valid };
    delete missing['recoveryAuth'];
    expect(recoveryResetRequestSchema.safeParse(missing).success).toBe(false);
    expect(recoveryResetRequestSchema.safeParse({ ...valid, codeId: 'nije-uuid' }).success).toBe(
      false,
    );
  });
});

describe('recoveryStatusSchema / replaceRecoveryCodesRequestSchema', () => {
  it('status ima ukupno, preostalo i vreme (ili null)', () => {
    expect(
      recoveryStatusSchema.safeParse({ total: 20, remaining: 17, createdAt: null }).success,
    ).toBe(true);
    expect(
      recoveryStatusSchema.safeParse({
        total: 20,
        remaining: -1,
        createdAt: '2026-01-01T00:00:00.000Z',
      }).success,
    ).toBe(false);
  });

  it('novi skup trazi trenutnu lozinku i tacno 20 kodova', () => {
    const codes = Array.from({ length: 20 }, (_, index) => ({
      authKey: String.fromCharCode(65 + index).repeat(43),
      wrappedVaultKey: envelope,
    }));
    const valid = { currentAuthKey: key, recovery: { ...kdf, codes } };
    expect(replaceRecoveryCodesRequestSchema.safeParse(valid).success).toBe(true);
    expect(
      replaceRecoveryCodesRequestSchema.safeParse({ ...valid, currentAuthKey: undefined }).success,
    ).toBe(false);
    expect(
      replaceRecoveryCodesRequestSchema.safeParse({
        ...valid,
        recovery: { ...kdf, codes: codes.slice(0, 5) },
      }).success,
    ).toBe(false);
  });
});
