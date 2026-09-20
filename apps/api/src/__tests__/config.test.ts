import { describe, expect, it } from 'vitest';
import { ZodError } from 'zod';
import { loadConfig } from '../config';

const valid = {
  DATABASE_URL: 'postgresql://u:p@localhost:5432/db',
  JWT_SECRET: 'j'.repeat(32),
  SERVER_PEPPER: 'p'.repeat(32),
};

describe('loadConfig', () => {
  it('popunjava podrazumevane vrednosti', () => {
    const config = loadConfig(valid);
    expect(config.NODE_ENV).toBe('development');
    expect(config.HOST).toBe('127.0.0.1');
    expect(config.PORT).toBe(3000);
    expect(config.APP_URL).toBe('http://localhost:5173');
    expect(config.TRUST_PROXY).toBe(false);
    expect(config.RATE_LIMIT_PER_MINUTE).toBe(120);
  });

  it('pretvara tekst iz okruzenja u brojeve i logicke vrednosti', () => {
    const config = loadConfig({ ...valid, PORT: '8080', TRUST_PROXY: 'true' });
    expect(config.PORT).toBe(8080);
    expect(config.TRUST_PROXY).toBe(true);
  });

  it('odbija nedostajuci DATABASE_URL', () => {
    const env: Record<string, string | undefined> = { ...valid };
    delete env['DATABASE_URL'];
    expect(() => loadConfig(env)).toThrow(ZodError);
  });

  it('odbija prekratke tajne', () => {
    expect(() => loadConfig({ ...valid, JWT_SECRET: 'kratko' })).toThrow(ZodError);
    expect(() => loadConfig({ ...valid, SERVER_PEPPER: 'kratko' })).toThrow(ZodError);
  });

  it('odbija iste vrednosti za JWT_SECRET i SERVER_PEPPER', () => {
    const same = 's'.repeat(40);
    expect(() => loadConfig({ ...valid, JWT_SECRET: same, SERVER_PEPPER: same })).toThrow(
      /must be different/,
    );
  });

  it('odbija neispravan port, adresu klijenta i logicku vrednost', () => {
    expect(() => loadConfig({ ...valid, PORT: '0' })).toThrow(ZodError);
    expect(() => loadConfig({ ...valid, PORT: '70000' })).toThrow(ZodError);
    expect(() => loadConfig({ ...valid, PORT: 'abc' })).toThrow(ZodError);
    expect(() => loadConfig({ ...valid, APP_URL: 'nije-adresa' })).toThrow(ZodError);
    expect(() => loadConfig({ ...valid, TRUST_PROXY: 'da' })).toThrow(ZodError);
  });

  it('u produkciji odbija tajne iz sablona .env.example', () => {
    const example = { JWT_SECRET: 'promeni-me'.repeat(4), SERVER_PEPPER: 'p'.repeat(32) };
    expect(() => loadConfig({ ...valid, ...example, NODE_ENV: 'production' })).toThrow(
      /must be changed/,
    );
    expect(() => loadConfig({ ...valid, ...example, NODE_ENV: 'development' })).not.toThrow();
  });
});
