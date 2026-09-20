import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app';
import { type Config, loadConfig } from '../config';
import { type PrismaClient, createPrismaClient } from '../db';
import { MemoryMailer } from '../mailer';

const APP_URL = 'http://localhost:5173';

function testConfig(overrides: Record<string, string> = {}): Config {
  return loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: 'postgresql://u:p@localhost:5432/db',
    JWT_SECRET: 'j'.repeat(32),
    SERVER_PEPPER: 'p'.repeat(32),
    APP_URL,
    ...overrides,
  });
}

const workingDb = { $queryRaw: () => Promise.resolve([{ ok: 1 }]) } as unknown as PrismaClient;
const brokenDb = {
  $queryRaw: () => Promise.reject(new Error('konekcija sa lozinkom hunter2 odbijena')),
} as unknown as PrismaClient;

describe('server', () => {
  const apps: FastifyInstance[] = [];

  async function create(overrides: Record<string, string> = {}, prisma = workingDb) {
    const app = await buildApp({
      config: testConfig(overrides),
      prisma,
      mailer: new MemoryMailer(),
    });
    apps.push(app);
    return app;
  }

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  describe('/health', () => {
    it('vraca 200 kada baza radi', async () => {
      const app = await create();
      const response = await app.inject({ method: 'GET', url: '/health' });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({ status: 'ok' });
    });

    it('vraca 503 bez ikakvih detalja kada baza ne radi', async () => {
      const app = await create({}, brokenDb);
      const response = await app.inject({ method: 'GET', url: '/health' });
      expect(response.statusCode).toBe(503);
      expect(response.json()).toEqual({ status: 'error' });
      expect(response.body).not.toContain('hunter2');
    });

    it('nije ogranicen brojem zahteva', async () => {
      const app = await create({ RATE_LIMIT_PER_MINUTE: '2' });
      for (let i = 0; i < 6; i++) {
        const response = await app.inject({ method: 'GET', url: '/health' });
        expect(response.statusCode).toBe(200);
      }
    });

    it('radi i sa pravom bazom kada je dostupna', async () => {
      const url = process.env['DATABASE_URL'];
      if (!url) {
        return;
      }
      const prisma = createPrismaClient(url);
      try {
        const app = await create({}, prisma);
        const response = await app.inject({ method: 'GET', url: '/health' });
        expect(response.statusCode).toBe(200);
      } finally {
        await prisma.$disconnect();
      }
    });
  });

  describe('bezbednosna zaglavlja', () => {
    it('postavlja zaglavlja i ne otkriva tehnologiju servera', async () => {
      const app = await create();
      const { headers } = await app.inject({ method: 'GET', url: '/health' });
      expect(headers['x-content-type-options']).toBe('nosniff');
      expect(headers['x-frame-options']).toBeDefined();
      const csp = String(headers['content-security-policy']);
      expect(csp).toContain("default-src 'none'");
      expect(csp).toContain("frame-ancestors 'none'");
      // Minimalan CSP: nista sto API ne koristi nije dozvoljeno.
      expect(csp).not.toContain('script-src');
      expect(csp).not.toContain('unsafe-inline');
      expect(headers['strict-transport-security']).toBeDefined();
      expect(headers['x-powered-by']).toBeUndefined();
    });
  });

  describe('CORS', () => {
    it('dozvoljava samo adresu veb klijenta, sa kolacicima', async () => {
      const app = await create();
      const allowed = await app.inject({
        method: 'GET',
        url: '/health',
        headers: { origin: APP_URL },
      });
      expect(allowed.headers['access-control-allow-origin']).toBe(APP_URL);
      expect(allowed.headers['access-control-allow-credentials']).toBe('true');

      const foreign = await app.inject({
        method: 'GET',
        url: '/health',
        headers: { origin: 'https://zlonamerni.example' },
      });
      expect(foreign.headers['access-control-allow-origin']).toBeUndefined();
    });
  });

  describe('greske', () => {
    it('nepoznata adresa vraca 404 u JSON obliku', async () => {
      const app = await create();
      const response = await app.inject({ method: 'GET', url: '/nema-me' });
      expect(response.statusCode).toBe(404);
      expect(response.json()).toEqual({ error: { code: 'NOT_FOUND', message: 'Not found' } });
    });

    it('neispravan JSON vraca 400 bez tehnickih detalja', async () => {
      const app = await create();
      app.post('/echo', async (request) => request.body);
      const response = await app.inject({
        method: 'POST',
        url: '/echo',
        headers: { 'content-type': 'application/json' },
        payload: '{"pokvaren": ',
      });
      expect(response.statusCode).toBe(400);
      expect(response.json()).toEqual({ error: { code: 'BAD_REQUEST', message: 'Bad request' } });
    });

    it('prevelika poruka se odbija', async () => {
      const app = await create();
      app.post('/echo', async (request) => request.body);
      const response = await app.inject({
        method: 'POST',
        url: '/echo',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ podaci: 'x'.repeat(1024 * 1024 + 1) }),
      });
      expect(response.statusCode).toBe(413);
    });

    it('neocekivana greska vraca 500 i ne otkriva unutrasnje detalje', async () => {
      const app = await create();
      app.get('/pukni', async () => {
        throw new Error('SELECT * FROM users WHERE password = hunter2');
      });
      const response = await app.inject({ method: 'GET', url: '/pukni' });
      expect(response.statusCode).toBe(500);
      expect(response.json()).toEqual({
        error: { code: 'INTERNAL', message: 'Internal server error' },
      });
      expect(response.body).not.toContain('hunter2');
      expect(response.body).not.toContain('SELECT');
    });
  });

  describe('ogranicenje broja zahteva', () => {
    it('posle limita vraca 429 i zaglavlje Retry-After', async () => {
      const app = await create({ RATE_LIMIT_PER_MINUTE: '3' });
      app.get('/proba', async () => ({ ok: true }));

      for (let i = 0; i < 3; i++) {
        expect((await app.inject({ method: 'GET', url: '/proba' })).statusCode).toBe(200);
      }
      const blocked = await app.inject({ method: 'GET', url: '/proba' });
      expect(blocked.statusCode).toBe(429);
      expect(blocked.json()).toEqual({
        error: { code: 'RATE_LIMITED', message: 'Too many requests' },
      });
      expect(blocked.headers['retry-after']).toBeDefined();
    });
  });
});
