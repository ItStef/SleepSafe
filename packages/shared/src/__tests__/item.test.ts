import { describe, expect, it } from 'vitest';
import { ITEM_LIMITS, emptyItemData, itemDataSchema } from '../item';

const valid = {
  title: 'Banka',
  username: 'marko',
  password: 'tajna',
  url: 'https://banka.example',
  notes: 'beleska',
};

describe('itemDataSchema', () => {
  it('prihvata ispravnu stavku i uklanja razmake oko naslova', () => {
    expect(itemDataSchema.parse(valid)).toEqual(valid);
    expect(itemDataSchema.parse({ ...valid, title: '  Banka  ' }).title).toBe('Banka');
  });

  it('ne dira lozinku, korisnicko ime ni beleske (razmaci su deo vrednosti)', () => {
    const padded = { ...valid, username: ' marko ', password: ' tajna ', notes: '\nx\n' };
    expect(itemDataSchema.parse(padded)).toEqual(padded);
  });

  it('trazi naslov i odbija dodatna i nedostajuca polja', () => {
    const bad = [
      { ...valid, title: '' },
      { ...valid, title: '   ' },
      { ...valid, extra: 1 },
      { title: 'x' },
      { ...valid, password: 5 },
      null,
    ];
    for (const value of bad) {
      expect(itemDataSchema.safeParse(value).success).toBe(false);
    }
  });

  it('prihvata tacno granicu duzine, a odbija jedan znak preko', () => {
    for (const field of Object.keys(ITEM_LIMITS) as (keyof typeof ITEM_LIMITS)[]) {
      const limit = ITEM_LIMITS[field];
      expect(itemDataSchema.safeParse({ ...valid, [field]: 'a'.repeat(limit) }).success).toBe(true);
      expect(itemDataSchema.safeParse({ ...valid, [field]: 'a'.repeat(limit + 1) }).success).toBe(
        false,
      );
    }
  });

  it('prazna stavka nije ispravna dok se ne unese naslov', () => {
    expect(itemDataSchema.safeParse(emptyItemData()).success).toBe(false);
    expect(itemDataSchema.safeParse({ ...emptyItemData(), title: 'x' }).success).toBe(true);
  });
});
