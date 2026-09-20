import { randomUUID } from 'node:crypto';
import { DEFAULT_KDF_PARAMS, assertAcceptableKdfParams } from '@sleepsafe/crypto';
import {
  type ChallengeResponse,
  type PreloginResponse,
  preloginRequestSchema,
  registerRequestSchema,
  verifyCodeRequestSchema,
} from '@sleepsafe/shared';
import type { FastifyInstance } from 'fastify';
import { OTP_TTL_MINUTES, issueChallenge, redeemChallenge } from '../challenges';
import type { Config } from '../config';
import { Prisma, type PrismaClient } from '../db';
import { buildOtpEmail } from '../emails';
import { AppError } from '../errors';
import type { Mailer } from '../mailer';
import { fakeKdfSalt, hashAuthKey } from '../security';

export interface AuthDeps {
  config: Config;
  prisma: PrismaClient;
  mailer: Mailer;
  clock: () => Date;
}

function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

export function registerAuthRoutes(app: FastifyInstance, deps: AuthDeps): void {
  const { config, prisma, mailer, clock } = deps;
  const authLimit = {
    rateLimit: { max: config.AUTH_RATE_LIMIT_PER_MINUTE, timeWindow: '1 minute' },
  };

  app.post('/auth/prelogin', { config: authLimit }, async (request): Promise<PreloginResponse> => {
    const { email } = preloginRequestSchema.parse(request.body);
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        emailVerifiedAt: true,
        kdfSalt: true,
        kdfMemoryKiB: true,
        kdfIterations: true,
        kdfParallelism: true,
      },
    });
    if (user?.emailVerifiedAt) {
      return {
        kdfSalt: user.kdfSalt,
        kdfMemoryKiB: user.kdfMemoryKiB,
        kdfIterations: user.kdfIterations,
        kdfParallelism: user.kdfParallelism,
      };
    }
    return {
      kdfSalt: fakeKdfSalt(email, config.SERVER_PEPPER),
      kdfMemoryKiB: DEFAULT_KDF_PARAMS.memoryKiB,
      kdfIterations: DEFAULT_KDF_PARAMS.iterations,
      kdfParallelism: DEFAULT_KDF_PARAMS.parallelism,
    };
  });

  app.post('/auth/register', { config: authLimit }, async (request, reply) => {
    const body = registerRequestSchema.parse(request.body);

    try {
      assertAcceptableKdfParams({
        memoryKiB: body.kdfMemoryKiB,
        iterations: body.kdfIterations,
        parallelism: body.kdfParallelism,
      });
    } catch {
      throw new AppError(400, 'VALIDATION_ERROR', 'Invalid request');
    }

    const decoy: ChallengeResponse = { challengeId: randomUUID() };
    const existing = await prisma.user.findUnique({ where: { email: body.email } });
    if (existing?.emailVerifiedAt) {
      return reply.code(202).send(decoy);
    }

    const data = {
      authHash: hashAuthKey(body.authKey, config.SERVER_PEPPER),
      kdfSalt: body.kdfSalt,
      kdfMemoryKiB: body.kdfMemoryKiB,
      kdfIterations: body.kdfIterations,
      kdfParallelism: body.kdfParallelism,
      wrappedVaultKey: body.wrappedVaultKey,
    };

    let userId: string;
    try {
      const user = existing
        ? await prisma.user.update({ where: { id: existing.id }, data })
        : await prisma.user.create({ data: { email: body.email, ...data } });
      userId = user.id;
    } catch (error) {
      if (isUniqueViolation(error)) {
        return reply.code(202).send(decoy);
      }
      throw error;
    }

    const { challengeId, code } = await issueChallenge(prisma, config.SERVER_PEPPER, {
      userId,
      purpose: 'EMAIL_VERIFICATION',
      now: clock(),
    });
    void mailer
      .send(buildOtpEmail(body.email, code, 'EMAIL_VERIFICATION', OTP_TTL_MINUTES))
      .catch((error: unknown) => request.log.error(error, 'failed to send verification email'));

    const response: ChallengeResponse = { challengeId };
    return reply.code(202).send(response);
  });

  app.post('/auth/verify-email', { config: authLimit }, async (request, reply) => {
    const { challengeId, code } = verifyCodeRequestSchema.parse(request.body);
    const { userId } = await redeemChallenge(prisma, config.SERVER_PEPPER, {
      challengeId,
      code,
      purpose: 'EMAIL_VERIFICATION',
      now: clock(),
    });
    await prisma.user.update({ where: { id: userId }, data: { emailVerifiedAt: clock() } });
    return reply.code(204).send();
  });
}
