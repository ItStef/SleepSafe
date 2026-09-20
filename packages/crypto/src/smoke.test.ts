import { describe, expect, it } from 'vitest';

describe('okruzenje', () => {
  it('Vitest radi', () => {
    expect(1 + 1).toBe(2);
  });

  it('WebCrypto je dostupan i vraca nasumicne bajtove', () => {
    const a = crypto.getRandomValues(new Uint8Array(32));
    const b = crypto.getRandomValues(new Uint8Array(32));
    expect(a).toHaveLength(32);
    expect(a).not.toEqual(b);
  });

  it('crypto.subtle postoji', () => {
    expect(crypto.subtle).toBeDefined();
  });
});
