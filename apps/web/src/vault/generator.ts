export interface GeneratorOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
}

export const GENERATOR_LIMITS = { minLength: 8, maxLength: 128 } as const;

export const DEFAULT_GENERATOR: GeneratorOptions = {
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
};

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.?/';
const AMBIGUOUS = /[Il1O0o]/g;

export type RandomInt = (maxExclusive: number) => number;

// Ravnomeran slucajan ceo broj u [0, maxExclusive). Odbacuje vrednosti iz "repa" opsega, jer bi
// obican `% max` favorizovao manje brojeve (pristrasnost).
export const secureRandomInt: RandomInt = (maxExclusive) => {
  if (!Number.isInteger(maxExclusive) || maxExclusive < 1 || maxExclusive > 2 ** 32) {
    throw new RangeError('maxExclusive must be an integer between 1 and 2^32');
  }
  const limit = 2 ** 32 - (2 ** 32 % maxExclusive);
  const buffer = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buffer);
    const value = buffer[0] as number;
    if (value < limit) {
      return value % maxExclusive;
    }
  }
};

function classes(options: GeneratorOptions): string[] {
  const chosen: string[] = [];
  if (options.lower) chosen.push(LOWER);
  if (options.upper) chosen.push(UPPER);
  if (options.digits) chosen.push(DIGITS);
  if (options.symbols) chosen.push(SYMBOLS);
  return options.avoidAmbiguous
    ? chosen.map((set) => set.replace(AMBIGUOUS, '')).filter((set) => set !== '')
    : chosen;
}

export function isGeneratorValid(options: GeneratorOptions): boolean {
  const sets = classes(options);
  return (
    Number.isInteger(options.length) &&
    options.length >= GENERATOR_LIMITS.minLength &&
    options.length <= GENERATOR_LIMITS.maxLength &&
    sets.length > 0 &&
    options.length >= sets.length
  );
}

// Svaka izabrana grupa znakova je zastupljena bar jednom (mnogi sajtovi to traze), ostatak je
// ravnomeran izbor iz svih izabranih grupa, a na kraju se sve promesa.
export function generatePassword(
  options: GeneratorOptions,
  random: RandomInt = secureRandomInt,
): string {
  if (!isGeneratorValid(options)) {
    throw new RangeError('Invalid generator options');
  }
  const sets = classes(options);
  const pool = sets.join('');
  const chars: string[] = sets.map((set) => set[random(set.length)] as string);
  while (chars.length < options.length) {
    chars.push(pool[random(pool.length)] as string);
  }
  for (let i = chars.length - 1; i > 0; i--) {
    const j = random(i + 1);
    [chars[i], chars[j]] = [chars[j] as string, chars[i] as string];
  }
  return chars.join('');
}

// Grubo: koliko bitova entropije daje izbor iz ovog skupa (bez uticaja obaveznih grupa).
export function estimateEntropyBits(options: GeneratorOptions): number {
  const size = classes(options).join('').length;
  return size === 0 ? 0 : Math.floor(options.length * Math.log2(size));
}
