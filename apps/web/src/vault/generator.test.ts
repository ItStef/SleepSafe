import { describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_GENERATOR,
  GENERATOR_LIMITS,
  type GeneratorOptions,
  estimateEntropyBits,
  generatePassword,
  isGeneratorValid,
  secureRandomInt,
} from './generator';

const options = (change: Partial<GeneratorOptions> = {}): GeneratorOptions => ({
  ...DEFAULT_GENERATOR,
  ...change,
});

describe('secureRandomInt', () => {
  it('vraca ceo broj u opsegu, i za 1 i za veoma velike granice', () => {
    for (const max of [1, 2, 7, 26, 1000, 2 ** 31, 2 ** 32]) {
      for (let i = 0; i < 50; i++) {
        const value = secureRandomInt(max);
        expect(Number.isInteger(value)).toBe(true);
        expect(value).toBeGreaterThanOrEqual(0);
        expect(value).toBeLessThan(max);
      }
    }
    expect(secureRandomInt(1)).toBe(0);
  });

  it('odbija neispravne granice', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, 2 ** 32 + 1]) {
      expect(() => secureRandomInt(bad)).toThrow(RangeError);
    }
  });

  it('odbacuje vrednosti iz repa opsega umesto da ih skuplja modulom (bez pristrasnosti)', () => {
    // Za max=3: 2^32 % 3 = 1, pa je 4294967295 (2^32 - 1) u repu i mora da se odbaci.
    const draws = [4294967295, 4294967295, 5];
    const spy = vi.spyOn(crypto, 'getRandomValues').mockImplementation(((buffer: Uint32Array) => {
      buffer[0] = draws.shift() as number;
      return buffer;
    }) as typeof crypto.getRandomValues);
    try {
      expect(secureRandomInt(3)).toBe(2); // 5 % 3
      expect(spy).toHaveBeenCalledTimes(3);
    } finally {
      spy.mockRestore();
    }
  });

  it('brojevi su priblizno ravnomerno rasporedjeni', () => {
    const counts = new Array<number>(10).fill(0);
    const draws = 30_000;
    for (let i = 0; i < draws; i++) {
      const value = secureRandomInt(10);
      counts[value] = (counts[value] ?? 0) + 1;
    }
    for (const count of counts) {
      expect(count).toBeGreaterThan(2500);
      expect(count).toBeLessThan(3500);
    }
  });
});

describe('generatePassword', () => {
  const lower = /[a-z]/;
  const upper = /[A-Z]/;
  const digit = /[0-9]/;
  const symbol = /[^A-Za-z0-9]/;

  it('pravi lozinku tacne duzine sa svim izabranim grupama (sto puta zaredom)', () => {
    for (let i = 0; i < 100; i++) {
      const password = generatePassword(options());
      expect(password).toHaveLength(20);
      expect(password).toMatch(lower);
      expect(password).toMatch(upper);
      expect(password).toMatch(digit);
      expect(password).toMatch(symbol);
    }
  });

  it('koristi samo izabrane grupe', () => {
    for (let i = 0; i < 50; i++) {
      expect(generatePassword(options({ upper: false, digits: false, symbols: false }))).toMatch(
        /^[a-z]{20}$/,
      );
      expect(generatePassword(options({ lower: false, upper: false, symbols: false }))).toMatch(
        /^[0-9]{20}$/,
      );
      expect(generatePassword(options({ symbols: false }))).toMatch(/^[A-Za-z0-9]{20}$/);
    }
  });

  it('najkraca i najduza dozvoljena lozinka', () => {
    expect(generatePassword(options({ length: GENERATOR_LIMITS.minLength }))).toHaveLength(8);
    expect(generatePassword(options({ length: GENERATOR_LIMITS.maxLength }))).toHaveLength(128);
  });

  it('izbegava dvosmislene znakove kad se to trazi, a i dalje ima sve grupe', () => {
    for (let i = 0; i < 100; i++) {
      const password = generatePassword(options({ avoidAmbiguous: true, length: 30 }));
      expect(password).not.toMatch(/[Il1O0o]/);
      expect(password).toMatch(lower);
      expect(password).toMatch(upper);
      expect(password).toMatch(digit);
      expect(password).toMatch(symbol);
    }
  });

  it('odbija neispravne postavke', () => {
    const bad = [
      options({ length: 7 }),
      options({ length: 129 }),
      options({ length: 20.5 }),
      options({ lower: false, upper: false, digits: false, symbols: false }),
    ];
    for (const value of bad) {
      expect(isGeneratorValid(value)).toBe(false);
      expect(() => generatePassword(value)).toThrow(RangeError);
    }
    expect(isGeneratorValid(options())).toBe(true);
  });

  it('dve uzastopne lozinke su razlicite', () => {
    expect(generatePassword(options())).not.toBe(generatePassword(options()));
  });

  it('slucajnost dolazi iskljucivo iz prosledjenog izvora: po jedan poziv za svaku grupu, svaki preostali znak i svako mesanje', () => {
    const calls: number[] = [];
    const random = (max: number) => {
      calls.push(max);
      return 0;
    };
    const password = generatePassword(
      options({ length: 8, lower: true, upper: true, digits: true, symbols: false }),
      random,
    );
    expect(password).toHaveLength(8);
    // 3 grupe (26, 26, 10), 5 znakova iz skupa od 62, 7 koraka mesanja (8, 7, ..., 2).
    expect(calls).toEqual([26, 26, 10, 62, 62, 62, 62, 62, 8, 7, 6, 5, 4, 3, 2]);
  });
});

describe('estimateEntropyBits', () => {
  it('raste sa duzinom i velicinom skupa znakova', () => {
    const short = estimateEntropyBits(options({ length: 10 }));
    const long = estimateEntropyBits(options({ length: 20 }));
    expect(long).toBeGreaterThan(short);
    const digitsOnly = estimateEntropyBits(
      options({ lower: false, upper: false, symbols: false, length: 10 }),
    );
    expect(digitsOnly).toBe(Math.floor(10 * Math.log2(10)));
    expect(short).toBeGreaterThan(digitsOnly);
  });

  it('bez ijedne grupe je nula', () => {
    expect(
      estimateEntropyBits(options({ lower: false, upper: false, digits: false, symbols: false })),
    ).toBe(0);
  });
});
