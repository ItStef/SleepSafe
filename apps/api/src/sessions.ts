import type { PrismaClient } from './db';
import { generateRefreshToken, hashRefreshToken } from './security';

export const REFRESH_REUSE_GRACE_MS = 10_000;
const MAX_USER_AGENT_LENGTH = 255;

export interface SessionTokens {
  sessionId: string;
  userId: string;
  refreshToken: string;
}

export type RotateResult =
  { ok: true; session: SessionTokens } | { ok: false; clearCookie: boolean };

export async function createSession(
  prisma: PrismaClient,
  pepper: string,
  params: { userId: string; userAgent: string | undefined; now: Date; ttlMs: number },
): Promise<SessionTokens> {
  const refreshToken = generateRefreshToken();
  const session = await prisma.session.create({
    data: {
      userId: params.userId,
      refreshTokenHash: hashRefreshToken(refreshToken, pepper),
      userAgent: params.userAgent?.slice(0, MAX_USER_AGENT_LENGTH) ?? null,
      lastUsedAt: params.now,
      expiresAt: new Date(params.now.getTime() + params.ttlMs),
    },
  });
  return { sessionId: session.id, userId: params.userId, refreshToken };
}

export async function rotateSession(
  prisma: PrismaClient,
  pepper: string,
  params: { refreshToken: string; now: Date; ttlMs: number },
): Promise<RotateResult> {
  const { refreshToken, now, ttlMs } = params;
  const oldHash = hashRefreshToken(refreshToken, pepper);
  const newToken = generateRefreshToken();
  const newHash = hashRefreshToken(newToken, pepper);

  const rotated = await prisma.session.updateMany({
    where: { refreshTokenHash: oldHash, revokedAt: null, expiresAt: { gt: now } },
    data: {
      refreshTokenHash: newHash,
      previousRefreshTokenHash: oldHash,
      lastUsedAt: now,
      expiresAt: new Date(now.getTime() + ttlMs),
    },
  });

  if (rotated.count === 1) {
    const session = await prisma.session.findUniqueOrThrow({
      where: { refreshTokenHash: newHash },
      select: { id: true, userId: true },
    });
    return {
      ok: true,
      session: { sessionId: session.id, userId: session.userId, refreshToken: newToken },
    };
  }

  const reused = await prisma.session.findFirst({
    where: { previousRefreshTokenHash: oldHash, revokedAt: null, expiresAt: { gt: now } },
    select: { id: true, lastUsedAt: true },
  });
  if (!reused) {
    return { ok: false, clearCookie: true };
  }
  if (now.getTime() - reused.lastUsedAt.getTime() <= REFRESH_REUSE_GRACE_MS) {
    return { ok: false, clearCookie: false };
  }
  await prisma.session.updateMany({
    where: { id: reused.id, revokedAt: null },
    data: { revokedAt: now },
  });
  return { ok: false, clearCookie: true };
}

export async function revokeSession(
  prisma: PrismaClient,
  pepper: string,
  params: { refreshToken: string; now: Date },
): Promise<void> {
  await prisma.session.updateMany({
    where: { refreshTokenHash: hashRefreshToken(params.refreshToken, pepper), revokedAt: null },
    data: { revokedAt: params.now },
  });
}
