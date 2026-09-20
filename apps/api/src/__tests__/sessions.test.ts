import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { type PrismaClient, createPrismaClient } from '../db';
import { hashRefreshToken } from '../security';
import { REFRESH_REUSE_GRACE_MS, createSession, revokeSession, rotateSession } from '../sessions';

const databaseUrl = process.env['DATABASE_URL'];
const pepper = 'p'.repeat(32);
const DAY = 24 * 60 * 60 * 1000;
const ttlMs = 30 * DAY;

describe.skipIf(!databaseUrl)('sesije i rotacija refresh tokena', () => {
  let prisma: PrismaClient;
  let userId: string;
  const now = new Date('2030-01-01T12:00:00Z');
  const later = (milliseconds: number) => new Date(now.getTime() + milliseconds);

  beforeAll(async () => {
    prisma = createPrismaClient(databaseUrl as string);
    const user = await prisma.user.create({
      data: {
        email: `sesije-${randomUUID()}@example.com`,
        authHash: 'x',
        kdfSalt: 'x',
        kdfMemoryKiB: 19456,
        kdfIterations: 2,
        kdfParallelism: 1,
        wrappedVaultKey: {},
      },
    });
    userId = user.id;
  });

  afterAll(async () => {
    await prisma.user.delete({ where: { id: userId } });
    await prisma.$disconnect();
  });

  const create = (userAgent?: string) =>
    createSession(prisma, pepper, { userId, userAgent, now, ttlMs });
  const rotate = (refreshToken: string, at: Date = now) =>
    rotateSession(prisma, pepper, { refreshToken, now: at, ttlMs });
  const row = (sessionId: string) => prisma.session.findUniqueOrThrow({ where: { id: sessionId } });

  it('u bazi je samo heš refresh tokena, nikad sam token', async () => {
    const { sessionId, refreshToken } = await create();
    expect(refreshToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const stored = await row(sessionId);
    expect(stored.refreshTokenHash).toBe(hashRefreshToken(refreshToken, pepper));
    expect(JSON.stringify(stored)).not.toContain(refreshToken);
    expect(stored.expiresAt.getTime()).toBe(now.getTime() + ttlMs);
    expect(stored.revokedAt).toBeNull();
  });

  it('svaka sesija dobija drugaciji token', async () => {
    const first = await create();
    const second = await create();
    expect(first.refreshToken).not.toBe(second.refreshToken);
    expect(first.sessionId).not.toBe(second.sessionId);
  });

  it('User-Agent se skracuje na 255 znakova', async () => {
    const { sessionId } = await create('x'.repeat(1000));
    expect((await row(sessionId)).userAgent).toHaveLength(255);
  });

  it('rotacija menja token, pamti prethodni heš i produzava sesiju', async () => {
    const { sessionId, refreshToken } = await create();
    const at = later(2 * DAY);
    const result = await rotate(refreshToken, at);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.session.sessionId).toBe(sessionId);
    expect(result.session.userId).toBe(userId);
    expect(result.session.refreshToken).not.toBe(refreshToken);

    const stored = await row(sessionId);
    expect(stored.refreshTokenHash).toBe(hashRefreshToken(result.session.refreshToken, pepper));
    expect(stored.previousRefreshTokenHash).toBe(hashRefreshToken(refreshToken, pepper));
    expect(stored.lastUsedAt).toEqual(at);
    expect(stored.expiresAt.getTime()).toBe(at.getTime() + ttlMs);
  });

  it('novi token radi, i to vise puta zaredom', async () => {
    const { refreshToken } = await create();
    const first = await rotate(refreshToken);
    if (!first.ok) throw new Error('first rotation failed');
    const second = await rotate(first.session.refreshToken, later(60_000));
    expect(second.ok).toBe(true);
  });

  it('ponovna upotreba starog tokena posle roka ponistava celu sesiju', async () => {
    const { sessionId, refreshToken } = await create();
    const rotated = await rotate(refreshToken);
    if (!rotated.ok) throw new Error('rotation failed');

    const replay = await rotate(refreshToken, later(REFRESH_REUSE_GRACE_MS + 1000));
    expect(replay).toEqual({ ok: false, clearCookie: true });
    expect((await row(sessionId)).revokedAt).not.toBeNull();

    const legit = await rotate(rotated.session.refreshToken, later(REFRESH_REUSE_GRACE_MS + 2000));
    expect(legit).toEqual({ ok: false, clearCookie: true });
  });

  it('ponovna upotreba unutar roka je bezopasna trka: odbija se, ali sesija ostaje', async () => {
    const { sessionId, refreshToken } = await create();
    const rotated = await rotate(refreshToken);
    if (!rotated.ok) throw new Error('rotation failed');

    const replay = await rotate(refreshToken, later(REFRESH_REUSE_GRACE_MS - 1000));
    expect(replay).toEqual({ ok: false, clearCookie: false });
    expect((await row(sessionId)).revokedAt).toBeNull();
    expect((await rotate(rotated.session.refreshToken, later(REFRESH_REUSE_GRACE_MS))).ok).toBe(
      true,
    );
  });

  it('od istovremenih zahteva sa istim tokenom uspeva tacno jedan', async () => {
    const { sessionId, refreshToken } = await create();
    const results = await Promise.all(Array.from({ length: 10 }, () => rotate(refreshToken)));
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect((await row(sessionId)).revokedAt).toBeNull();
  });

  it('istekla sesija se ne moze obnoviti', async () => {
    const { refreshToken } = await create();
    expect(await rotate(refreshToken, later(ttlMs + 1000))).toEqual({
      ok: false,
      clearCookie: true,
    });
    expect((await rotate(refreshToken, later(ttlMs - 1000))).ok).toBe(true);
  });

  it('nepoznat token se odbija', async () => {
    expect(await rotate('A'.repeat(43))).toEqual({ ok: false, clearCookie: true });
  });

  it('ponistena sesija se ne moze obnoviti', async () => {
    const { refreshToken } = await create();
    await revokeSession(prisma, pepper, { refreshToken, now });
    expect(await rotate(refreshToken)).toEqual({ ok: false, clearCookie: true });
  });

  it('revokeSession ponistava sesiju, a ponovljen poziv i nepoznat token nisu greska', async () => {
    const { sessionId, refreshToken } = await create();
    await revokeSession(prisma, pepper, { refreshToken, now });
    const revokedAt = (await row(sessionId)).revokedAt;
    expect(revokedAt).toEqual(now);

    await revokeSession(prisma, pepper, { refreshToken, now: later(1000) });
    expect((await row(sessionId)).revokedAt).toEqual(revokedAt);
    await expect(
      revokeSession(prisma, pepper, { refreshToken: 'B'.repeat(43), now }),
    ).resolves.toBeUndefined();
  });

  it('ponistavanje jedne sesije ne dira drugu', async () => {
    const first = await create();
    const second = await create();
    await revokeSession(prisma, pepper, { refreshToken: first.refreshToken, now });
    expect((await rotate(second.refreshToken)).ok).toBe(true);
  });
});
