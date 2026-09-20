import { describe, expect, it } from 'vitest';
import { FailureThrottle } from '../throttle';

const MINUTE = 60_000;
const t0 = new Date('2030-01-01T12:00:00Z');
const after = (milliseconds: number) => new Date(t0.getTime() + milliseconds);

describe('FailureThrottle', () => {
  it('na pocetku nikoga ne blokira', () => {
    expect(new FailureThrottle(3, 15 * MINUTE).isBlocked('a@example.com', t0)).toBe(false);
  });

  it('blokira tek kad broj neuspeha dostigne granicu', () => {
    const throttle = new FailureThrottle(3, 15 * MINUTE);
    throttle.recordFailure('a@example.com', t0);
    throttle.recordFailure('a@example.com', t0);
    expect(throttle.isBlocked('a@example.com', t0)).toBe(false);
    throttle.recordFailure('a@example.com', t0);
    expect(throttle.isBlocked('a@example.com', t0)).toBe(true);
  });

  it('svaki kljuc se broji zasebno', () => {
    const throttle = new FailureThrottle(1, 15 * MINUTE);
    throttle.recordFailure('a@example.com', t0);
    expect(throttle.isBlocked('a@example.com', t0)).toBe(true);
    expect(throttle.isBlocked('b@example.com', t0)).toBe(false);
  });

  it('blokada traje do kraja prozora, a posle toga brojanje krece iz pocetka', () => {
    const throttle = new FailureThrottle(2, 15 * MINUTE);
    throttle.recordFailure('a@example.com', t0);
    throttle.recordFailure('a@example.com', t0);
    expect(throttle.isBlocked('a@example.com', after(15 * MINUTE - 1))).toBe(true);
    expect(throttle.isBlocked('a@example.com', after(15 * MINUTE))).toBe(false);

    throttle.recordFailure('a@example.com', after(16 * MINUTE));
    expect(throttle.isBlocked('a@example.com', after(16 * MINUTE))).toBe(false);
  });

  it('neuspesi izvan prozora se ne sabiraju', () => {
    const throttle = new FailureThrottle(2, 15 * MINUTE);
    throttle.recordFailure('a@example.com', t0);
    throttle.recordFailure('a@example.com', after(20 * MINUTE));
    expect(throttle.isBlocked('a@example.com', after(20 * MINUTE))).toBe(false);
  });

  it('broj pracenih kljuceva je ogranicen: najstariji se izbacuje', () => {
    const throttle = new FailureThrottle(1, 15 * MINUTE, 3);
    for (const key of ['a', 'b', 'c', 'd', 'e']) {
      throttle.recordFailure(key, t0);
    }
    expect(throttle.size).toBe(3);
    expect(throttle.isBlocked('a', t0)).toBe(false);
    expect(throttle.isBlocked('b', t0)).toBe(false);
    expect(throttle.isBlocked('e', t0)).toBe(true);
  });

  it('kad je puno, prvo se brisu istekli zapisi, a ne aktivni', () => {
    const throttle = new FailureThrottle(1, 15 * MINUTE, 3);
    throttle.recordFailure('stari-1', t0);
    throttle.recordFailure('stari-2', t0);
    throttle.recordFailure('stari-3', after(10 * MINUTE));

    throttle.recordFailure('novi', after(16 * MINUTE));
    expect(throttle.size).toBe(2);
    expect(throttle.isBlocked('stari-3', after(16 * MINUTE))).toBe(true);
    expect(throttle.isBlocked('novi', after(16 * MINUTE))).toBe(true);
  });
});
