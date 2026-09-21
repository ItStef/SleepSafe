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

describe('loadConfig: email server', () => {
  it('podrazumevano cilja lokalni Mailpit bez sifrovanja i bez lozinke', () => {
    const config = loadConfig(valid);
    expect(config.SMTP_HOST).toBe('127.0.0.1');
    expect(config.SMTP_PORT).toBe(1025);
    expect(config.SMTP_TLS).toBe('none');
    expect(config.SMTP_USER).toBeUndefined();
    expect(config.SMTP_PASS).toBeUndefined();
    expect(config.SMTP_FROM).toContain('no-reply@');
  });

  it('prihvata podesavanja pravog email servera', () => {
    const config = loadConfig({
      ...valid,
      SMTP_HOST: 'smtp.example.com',
      SMTP_PORT: '587',
      SMTP_TLS: 'starttls',
      SMTP_USER: 'korisnik',
      SMTP_PASS: 'lozinka',
    });
    expect(config.SMTP_PORT).toBe(587);
    expect(config.SMTP_TLS).toBe('starttls');
    expect(config.SMTP_USER).toBe('korisnik');
  });

  it('odbija nepoznat nacin sifrovanja i neispravan port', () => {
    expect(() => loadConfig({ ...valid, SMTP_TLS: 'ssl' })).toThrow(ZodError);
    expect(() => loadConfig({ ...valid, SMTP_PORT: '0' })).toThrow(ZodError);
  });

  it('trazi da se korisnik i lozinka zadaju zajedno', () => {
    expect(() => loadConfig({ ...valid, SMTP_USER: 'korisnik' })).toThrow(/set together/);
    expect(() => loadConfig({ ...valid, SMTP_PASS: 'lozinka' })).toThrow(/set together/);
  });

  it('u produkciji ne dozvoljava nesifrovanu vezu ka email serveru', () => {
    const production = { ...valid, NODE_ENV: 'production' };
    expect(() => loadConfig({ ...production, SMTP_TLS: 'none' })).toThrow(/starttls or tls/);
    expect(() => loadConfig({ ...production, SMTP_TLS: 'starttls' })).not.toThrow();
    expect(() => loadConfig({ ...production, SMTP_TLS: 'tls' })).not.toThrow();
    expect(() => loadConfig({ ...valid, NODE_ENV: 'development', SMTP_TLS: 'none' })).not.toThrow();
  });

  it('podrazumevane vrednosti za sesije i prijavu', () => {
    const config = loadConfig(valid);
    expect(config.ACCESS_TOKEN_TTL_SECONDS).toBe(900);
    expect(config.SESSION_TTL_DAYS).toBe(30);
    expect(config.LOGIN_MAX_FAILURES).toBe(10);
    expect(config.LOGIN_LOCKOUT_MINUTES).toBe(15);
  });

  it('odbija nerazumne rokove sesija i pragove prijave', () => {
    for (const bad of [
      { ACCESS_TOKEN_TTL_SECONDS: '10' },
      { ACCESS_TOKEN_TTL_SECONDS: '86400' },
      { SESSION_TTL_DAYS: '0' },
      { SESSION_TTL_DAYS: '3650' },
      { LOGIN_MAX_FAILURES: '0' },
      { LOGIN_LOCKOUT_MINUTES: '0' },
    ]) {
      expect(() => loadConfig({ ...valid, ...bad })).toThrow(ZodError);
    }
  });
  it('ogranicenje broja stavki po korisniku: podrazumevano 10000, najmanje 1', () => {
    expect(loadConfig(valid).MAX_ITEMS_PER_USER).toBe(10_000);
    expect(loadConfig({ ...valid, MAX_ITEMS_PER_USER: '50' }).MAX_ITEMS_PER_USER).toBe(50);
    expect(() => loadConfig({ ...valid, MAX_ITEMS_PER_USER: '0' })).toThrow(ZodError);
  });
});
