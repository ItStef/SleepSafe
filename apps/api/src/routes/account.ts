import { assertAcceptableKdfParams } from '@sleepsafe/crypto';
import {
  type ListSessionsResponse,
  changePasswordRequestSchema,
  deleteAccountRequestSchema,
} from '@sleepsafe/shared';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { recordAuditEvent } from '../audit';
import { createAuthenticator } from '../authenticate';
import { type NoticeKind, buildNoticeEmail } from '../emails';
import { AppError } from '../errors';
import { hashAuthKey, verifyAuthKey } from '../security';
import type { AuthDeps } from './auth';

export function registerAccountRoutes(app: FastifyInstance, deps: AuthDeps): void {
  const { config, prisma, mailer, clock, throttle } = deps;
  const authenticate = createAuthenticator({ config, prisma, clock });
  const authLimit = {
    rateLimit: { max: config.AUTH_RATE_LIMIT_PER_MINUTE, timeWindow: '1 minute' },
  };

  async function confirmPassword(userId: string, authKey: string, now: Date) {
    const user = await prisma.user.findUniqueOrThrow({
      where: { id: userId },
      select: { email: true, authHash: true },
    });
    if (throttle.isBlocked(user.email, now)) {
      throw new AppError(429, 'TOO_MANY_ATTEMPTS', 'Too many failed attempts, try again later');
    }
    if (!verifyAuthKey(authKey, user.authHash, config.SERVER_PEPPER)) {
      throttle.recordFailure(user.email, now);
      throw new AppError(403, 'INVALID_PASSWORD', 'Invalid password');
    }
    return user;
  }

  function notify(request: FastifyRequest, to: string, kind: NoticeKind): void {
    void mailer
      .send(buildNoticeEmail(to, kind))
      .catch((error: unknown) => request.log.error(error, 'failed to send notice email'));
  }

  app.post('/auth/change-password', { config: authLimit }, async (request, reply) => {
    const { userId, sessionId } = await authenticate(request);
    const body = changePasswordRequestSchema.parse(request.body);
    try {
      assertAcceptableKdfParams({
        memoryKiB: body.kdfMemoryKiB,
        iterations: body.kdfIterations,
        parallelism: body.kdfParallelism,
      });
    } catch {
      throw new AppError(400, 'VALIDATION_ERROR', 'Invalid request');
    }

    const now = clock();
    const user = await confirmPassword(userId, body.currentAuthKey, now);

    await prisma.$transaction(async (tx) => {
      const changed = await tx.user.updateMany({
        where: { id: userId, authHash: user.authHash },
        data: {
          authHash: hashAuthKey(body.newAuthKey, config.SERVER_PEPPER),
          kdfSalt: body.kdfSalt,
          kdfMemoryKiB: body.kdfMemoryKiB,
          kdfIterations: body.kdfIterations,
          kdfParallelism: body.kdfParallelism,
          wrappedVaultKey: body.wrappedVaultKey,
        },
      });
      if (changed.count !== 1) {
        throw new AppError(403, 'INVALID_PASSWORD', 'Invalid password');
      }
      await tx.session.updateMany({
        where: { userId, id: { not: sessionId }, revokedAt: null },
        data: { revokedAt: now },
      });
      await tx.otpChallenge.updateMany({
        where: { userId, consumedAt: null },
        data: { consumedAt: now },
      });
      await tx.auditEvent.create({
        data: {
          userId,
          type: 'PASSWORD_CHANGED',
          ip: request.ip,
          userAgent: request.headers['user-agent']?.slice(0, 255) ?? null,
          createdAt: now,
        },
      });
    });

    notify(request, user.email, 'PASSWORD_CHANGED');
    return reply.code(204).send();
  });


  app.get('/auth/sessions', async (request): Promise<ListSessionsResponse> => {
    const { userId, sessionId } = await authenticate(request);
    const rows = await prisma.session.findMany({
      where: { userId, revokedAt: null, expiresAt: { gt: clock() } },
      orderBy: { lastUsedAt: 'desc' },
      take: 100,
      select: { id: true, userAgent: true, createdAt: true, lastUsedAt: true },
    });
    return {
      sessions: rows.map((row) => ({
        id: row.id,
        userAgent: row.userAgent,
        createdAt: row.createdAt.toISOString(),
        lastUsedAt: row.lastUsedAt.toISOString(),
        current: row.id === sessionId,
      })),
    };
  });

  app.delete('/auth/sessions/:id', async (request, reply) => {
    const { userId } = await authenticate(request);
    const id = z.uuid().parse((request.params as { id?: unknown }).id);
    await prisma.session.updateMany({
      where: { id, userId, revokedAt: null },
      data: { revokedAt: clock() },
    });
    void recordAuditEvent(prisma, { userId, type: 'SESSION_REVOKED', request });
    return reply.code(204).send();
  });

  app.post('/auth/sessions/revoke-others', async (request, reply) => {
    const { userId, sessionId } = await authenticate(request);
    await prisma.session.updateMany({
      where: { userId, id: { not: sessionId }, revokedAt: null },
      data: { revokedAt: clock() },
    });
    void recordAuditEvent(prisma, { userId, type: 'SESSION_REVOKED', request });
    return reply.code(204).send();
  });

  app.post('/auth/delete-account', { config: authLimit }, async (request, reply) => {
    const { userId } = await authenticate(request);
    const { authKey } = deleteAccountRequestSchema.parse(request.body);
    const user = await confirmPassword(userId, authKey, clock());
    await prisma.user.deleteMany({ where: { id: userId } });
    notify(request, user.email, 'ACCOUNT_DELETED');
    return reply.code(204).send();
  });
}
