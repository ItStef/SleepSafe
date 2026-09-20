import { describe, expect, it } from 'vitest';
import {
  MAX_ITEM_CIPHERTEXT_CHARS,
  itemEnvelopeSchema,
  itemIdSchema,
  listItemsQuerySchema,
  putItemRequestSchema,
  syncItemSchema,
} from '../vault';

const envelope = { v: 1, iv: 'A'.repeat(16), ct: 'A'.repeat(40) };
const id = '3f2b8c1e-7a44-4d0b-9a55-1c2d3e4f5a6b';

describe('itemEnvelopeSchema', () => {
  it('prihvata ispravnu stavku', () => {
    expect(itemEnvelopeSchema.safeParse(envelope).success).toBe(true);
  });

  it('odbija pogresnu verziju, IV, prekratak i predugacak sifrat i dodatna polja', () => {
    const bad = [
      { ...envelope, v: 2 },
      { ...envelope, iv: 'A'.repeat(15) },
      { ...envelope, iv: 'A'.repeat(17) },
      { ...envelope, ct: 'A'.repeat(21) },
      { ...envelope, ct: 'A'.repeat(MAX_ITEM_CIPHERTEXT_CHARS + 1) },
      { ...envelope, ct: 'nije base64url!' },
      { ...envelope, extra: 1 },
    ];
    for (const value of bad) {
      expect(itemEnvelopeSchema.safeParse(value).success).toBe(false);
    }
  });

  it('prihvata sifrat tacno do granice velicine', () => {
    const atLimit = { ...envelope, ct: 'A'.repeat(MAX_ITEM_CIPHERTEXT_CHARS) };
    expect(itemEnvelopeSchema.safeParse(atLimit).success).toBe(true);
  });
});

describe('putItemRequestSchema', () => {
  it('baseRevision je null (nova) ili pozitivan ceo broj', () => {
    expect(putItemRequestSchema.safeParse({ envelope, baseRevision: null }).success).toBe(true);
    expect(putItemRequestSchema.safeParse({ envelope, baseRevision: 7 }).success).toBe(true);
    for (const baseRevision of [0, -1, 1.5, '3', undefined]) {
      expect(putItemRequestSchema.safeParse({ envelope, baseRevision }).success).toBe(false);
    }
  });

  it('odbija dodatna polja (npr. userId ili revision koje klijent ne sme da postavlja)', () => {
    expect(
      putItemRequestSchema.safeParse({ envelope, baseRevision: null, userId: id }).success,
    ).toBe(false);
    expect(
      putItemRequestSchema.safeParse({ envelope, baseRevision: null, revision: 99 }).success,
    ).toBe(false);
  });
});

describe('syncItemSchema i upit', () => {
  it('obrisana stavka nema sifrat, aktivna ga ima', () => {
    const base = { id, revision: 3, updatedAt: '2030-01-01T12:00:00.000Z' };
    expect(syncItemSchema.safeParse({ ...base, deleted: true, envelope: null }).success).toBe(true);
    expect(syncItemSchema.safeParse({ ...base, deleted: false, envelope }).success).toBe(true);
    expect(syncItemSchema.safeParse({ ...base, deleted: false }).success).toBe(false);
  });

  it('ID stavke je UUID', () => {
    expect(itemIdSchema.safeParse(id).success).toBe(true);
    expect(itemIdSchema.safeParse('nije-uuid').success).toBe(false);
  });

  it('upit ima podrazumevane vrednosti i granice', () => {
    expect(listItemsQuerySchema.parse({})).toEqual({ since: 0, limit: 200 });
    expect(listItemsQuerySchema.parse({ since: '15', limit: '50' })).toEqual({
      since: 15,
      limit: 50,
    });
    for (const bad of [
      { since: '-1' },
      { since: 'abc' },
      { limit: '0' },
      { limit: '501' },
      { x: 1 },
    ]) {
      expect(listItemsQuerySchema.safeParse(bad).success).toBe(false);
    }
  });
});
