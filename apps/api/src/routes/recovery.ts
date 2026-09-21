import { randomUUID } from 'node:crypto';
import { DEFAULT_KDF_PARAMS, assertAcceptableKdfParams } from '@sleepsafe/crypto';
import {
  type RecoveryStartResponse,
  type RecoveryVerifyResponse,
  recoveryResetRequestSchema,
  recoveryStartRequestSchema,
  recoveryVerifyRequestSchema,
  wrappedKeyEnvelopeSchema,
} from '@sleepsafe/shared';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { OTP_TTL_MINUTES, issueChallenge, redeemChallenge } from '../challenges';
import { type NoticeKind, buildNoticeEmail, buildOtpEmail } from '../emails';
import { AppError } from '../errors';
import { RESET_MAX_ATTEMPTS, RESET_TOKEN_TTL_MINUTES, invalidRecovery } from '../recovery';
import {
  fakeRecoverySalt,
  generateResetToken,
  hashAuthKey,
  hashResetToken,
  verifyRecoveryAuth,
  verifyResetToken,
} from '../security';
import type { AuthDeps } from './auth';

export function registerRecoveryRoutes(app: FastifyInstance, deps: AuthDeps): void {
  const { config, prisma, mailer, clock, throttle } = deps;
  const authLimit = {
    rateLimit: { max: config.AUTH_RATE_LIMIT_PER_MINUTE, timeWindow: '1 minute' },
  };

  function notify(request: FastifyRequest, to: string, kind: NoticeKind): void {
    void mailer
      .send(buildNoticeEmail(to, kind))
      .catch((error: unknown) => request.log.error(error, 'failed to send notice email'));
  }

  function blockedError(): AppError {
    return new AppError(429, 'TOO_MANY_ATTEMPTS', 'Too many failed attempts, try again later');
  }

  // 1. Zahtev: uvek 202 i isti oblik odgovora, bez obzira da li nalog postoji ili ima kodove.
  app.post('/auth/recovery/start', { config: authLimit }, async (request, reply) => {
    const { email } = recoveryStartRequestSchema.parse(request.body);
    const now = clock();
    if (throttle.isBlocked(email, now)) {
      throw blockedError();
    }

    const decoy: RecoveryStartResponse = {
      challengeId: randomUUID(),
      kdfSalt: fakeRecoverySalt(email, config.SERVER_PEPPER),
      kdfMemoryKiB: DEFAULT_KDF_PARAMS.memoryKiB,
      kdfIterations: DEFAULT_KDF_PARAMS.iterations,
      kdfParallelism: DEFAULT_KDF_PARAMS.parallelism,
    };

    const user = await prisma.user.findUnique({ where: { email } });
    if (
      !user ||
      user.emailVerifiedAt === null ||
      user.recoverySalt === null ||
      user.recoveryKdfMemoryKiB === null ||
      user.recoveryKdfIterations === null ||
      user.recoveryKdfParallelism === null
    ) {
      return reply.code(202).send(decoy);
    }
    const unused = await prisma.recoveryCode.count({ where: { userId: user.id, usedAt: null } });
    if (unused === 0) {
      return reply.code(202).send(decoy);
    }

    const { challengeId, code } = await issueChallenge(prisma, config.SERVER_PEPPER, {
      userId: user.id,
      purpose: 'RECOVERY',
      now,
    });
    void mailer
      .send(buildOtpEmail(email, code, 'RECOVERY', OTP_TTL_MINUTES))
      .catch((error: unknown) => request.log.error(error, 'failed to send recovery email'));

    const response: RecoveryStartResponse = {
      challengeId,
      kdfSalt: user.recoverySalt,
      kdfMemoryKiB: user.recoveryKdfMemoryKiB,
      kdfIterations: user.recoveryKdfIterations,
      kdfParallelism: user.recoveryKdfParallelism,
    };
    return reply.code(202).send(response);
  });

  // 2. Kod iz emaila: tek tada server vraca omotane kljuceve i jednokratni token za promenu.
  app.post('/auth/recovery/verify', { config: authLimit }, async (request) => {
    const { challengeId, code } = recoveryVerifyRequestSchema.parse(request.body);
    const now = clock();
    const { userId } = await redeemChallenge(prisma, config.SERVER_PEPPER, {
      challengeId,
      code,
      purpose: 'RECOVERY',
      now,
    });

    const codes = await prisma.recoveryCode.findMany({
      where: { userId, usedAt: null },
      orderBy: { id: 'asc' },
      select: { id: true, wrappedVaultKey: true },
    });
    if (codes.length === 0) {
      throw new AppError(400, 'INVALID_CODE', 'Invalid or expired code');
    }

    const resetId = randomUUID();
    const resetToken = generateResetToken();
    await prisma.$transaction([
      prisma.otpChallenge.updateMany({
        where: { userId, purpose: 'RECOVERY_RESET', consumedAt: null },
        data: { consumedAt: now },
      }),
      prisma.otpChallenge.create({
        data: {
          id: resetId,
          userId,
          purpose: 'RECOVERY_RESET',
          codeHash: hashResetToken(resetToken, resetId, config.SERVER_PEPPER),
          expiresAt: new Date(now.getTime() + RESET_TOKEN_TTL_MINUTES * 60_000),
        },
      }),
    ]);

    const response: RecoveryVerifyResponse = {
      resetId,
      resetToken,
      codes: codes.map((row) => ({
        id: row.id,
        wrappedVaultKey: wrappedKeyEnvelopeSchema.parse(row.wrappedVaultKey),
      })),
    };
    return response;
  });

  // 3. Nova master lozinka. Trosi kod (jednokratan) i odjavljuje sve sesije.
  app.post('/auth/recovery/reset', { config: authLimit }, async (request, reply) => {
    const body = recoveryResetRequestSchema.parse(request.body);
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

    const reset = await prisma.otpChallenge.findUnique({
      where: { id: body.resetId },
      include: { user: { select: { email: true } } },
    });
    if (!reset || reset.purpose !== 'RECOVERY_RESET') {
      throw invalidRecovery();
    }
    const email = reset.user.email;
    if (throttle.isBlocked(email, now)) {
      throw blockedError();
    }

    // Svaki pokusaj se broji unapred (atomski), pa token ne moze da se pogadja u nedogled.
    const claimed = await prisma.otpChallenge.updateMany({
      where: {
        id: reset.id,
        purpose: 'RECOVERY_RESET',
        consumedAt: null,
        expiresAt: { gt: now },
        attempts: { lt: RESET_MAX_ATTEMPTS },
      },
      data: { attempts: { increment: 1 } },
    });
    if (claimed.count !== 1) {
      throw invalidRecovery();
    }
    if (!verifyResetToken(body.resetToken, reset.id, reset.codeHash, config.SERVER_PEPPER)) {
      throttle.recordFailure(email, now);
      throw invalidRecovery();
    }

    const code = await prisma.recoveryCode.findFirst({
      where: { id: body.codeId, userId: reset.userId, usedAt: null },
    });
    if (!code || !verifyRecoveryAuth(body.recoveryAuth, code.codeHash, config.SERVER_PEPPER)) {
      throttle.recordFailure(email, now);
      throw invalidRecovery();
    }

    await prisma.$transaction(async (tx) => {
      // Kod se zakljucava prvi, uvek istim redosledom: dva zahteva (sa razlicitim tokenima) za isti
      // kod tako ne mogu da se uzajamno blokiraju, pa gubitnik dobija uredan 400, a ne 500.
      const used = await tx.recoveryCode.updateMany({
        where: { id: code.id, usedAt: null },
        data: { usedAt: now },
      });
      if (used.count !== 1) {
        throw invalidRecovery();
      }
      const consumed = await tx.otpChallenge.updateMany({
        where: { id: reset.id, consumedAt: null },
        data: { consumedAt: now },
      });
      if (consumed.count !== 1) {
        throw invalidRecovery();
      }
      await tx.user.update({
        where: { id: reset.userId },
        data: {
          authHash: hashAuthKey(body.newAuthKey, config.SERVER_PEPPER),
          kdfSalt: body.kdfSalt,
          kdfMemoryKiB: body.kdfMemoryKiB,
          kdfIterations: body.kdfIterations,
          kdfParallelism: body.kdfParallelism,
          wrappedVaultKey: body.wrappedVaultKey,
        },
      });
      await tx.session.updateMany({
        where: { userId: reset.userId, revokedAt: null },
        data: { revokedAt: now },
      });
      await tx.otpChallenge.updateMany({
        where: { userId: reset.userId, consumedAt: null },
        data: { consumedAt: now },
      });
    });

    notify(request, email, 'PASSWORD_RESET');
    return reply.code(204).send();
  });
}
