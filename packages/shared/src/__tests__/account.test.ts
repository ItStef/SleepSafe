import { describe, expect, it } from 'vitest';
import {
  changePasswordRequestSchema,
  deleteAccountRequestSchema,
  listSessionsResponseSchema,
  sessionInfoSchema,
} from '../account';

const key = 'A'.repeat(43);
const validChange = {
  currentAuthKey: key,
  newAuthKey: 'B'.repeat(43),
  kdfSalt: 'C'.repeat(22),
  kdfMemoryKiB: 65536,
  kdfIterations: 3,
  kdfParallelism: 1,
  wrappedVaultKey: { v: 1, iv: 'A'.repeat(16), ct: 'A'.repeat(64) },
};

describe('changePasswordRequestSchema', () => {
  it('prihvata ispravan zahtev', () => {
    expect(changePasswordRequestSchema.safeParse(validChange).success).toBe(true);
  });

  it('odbija nedostajuce polje, i to svako ponaosob', () => {
    for (const field of Object.keys(validChange)) {
      const copy: Record<string, unknown> = { ...validChange };
      delete copy[field];
      expect(changePasswordRequestSchema.safeParse(copy).success).toBe(false);
    }
  });

  it('odbija dodatna polja i pogresne oblike kljuceva', () => {
    expect(changePasswordRequestSchema.safeParse({ ...validChange, password: 'x' }).success).toBe(
      false,
    );
    expect(
      changePasswordRequestSchema.safeParse({ ...validChange, newAuthKey: 'kratak' }).success,
    ).toBe(false);
    expect(
      changePasswordRequestSchema.safeParse({
        ...validChange,
        wrappedVaultKey: { ...validChange.wrappedVaultKey, ct: 'x' },
      }).success,
    ).toBe(false);
  });
});

describe('ostale seme naloga', () => {
  it('brisanje naloga trazi samo Auth kljuc', () => {
    expect(deleteAccountRequestSchema.safeParse({ authKey: key }).success).toBe(true);
    expect(deleteAccountRequestSchema.safeParse({}).success).toBe(false);
    expect(deleteAccountRequestSchema.safeParse({ authKey: key, confirm: true }).success).toBe(
      false,
    );
  });

  it('sesija ima ID, uredjaj, vremena i oznaku trenutne', () => {
    const session = {
      id: '3f2b8c1e-7a44-4d0b-9a55-1c2d3e4f5a6b',
      userAgent: null,
      createdAt: '2030-01-01T12:00:00.000Z',
      lastUsedAt: '2030-01-02T12:00:00.000Z',
      current: true,
    };
    expect(sessionInfoSchema.safeParse(session).success).toBe(true);
    expect(listSessionsResponseSchema.safeParse({ sessions: [session] }).success).toBe(true);
    expect(sessionInfoSchema.safeParse({ ...session, refreshTokenHash: 'x' }).success).toBe(false);
  });
});
