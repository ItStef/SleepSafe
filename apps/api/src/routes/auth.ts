import { randomUUID } from 'node:crypto';
import { DEFAULT_KDF_PARAMS, assertAcceptableKdfParams, toBase64Url } from '@sleepsafe/crypto';
import {
  type AccessTokenResponse,
  type ChallengeResponse,
  type MeResponse,
  type PreloginResponse,
  loginRequestSchema,
  preloginRequestSchema,
  registerRequestSchema,
  verifyCodeRequestSchema,
  wrappedKeyEnvelopeSchema,
} from '@sleepsafe/shared';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { createAuthenticator } from '../authenticate';
import { OTP_TTL_MINUTES, issueChallenge, redeemChallenge } from '../challenges';
import type { Config } from '../config';
import { Prisma, type PrismaClient } from '../db';
import { buildOtpEmail } from '../emails';
import { AppError } from '../errors';
import type { Mailer } from '../mailer';
import { fakeKdfSalt, hashAuthKey, signAccessToken, verifyAuthKey } from '../security';
import { createSession, revokeSession, rotateSession } from '../sessions';
import type { FailureThrottle } from '../throttle';

const REFRESH_COOKIE = 'sleepsafe_refresh';
const REFRESH_COOKIE_PATH = '/auth';
const REFRESH_TOKEN_SHAPE = /^[A-Za-z0-9_-]{43}$/;

export interface AuthDeps {
  config: Config;
  prisma: PrismaClient;
  mailer: Mailer;
  clock: () => Date;
  throttle: FailureThrottle;
}

function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

export function registerAuthRoutes(app: FastifyInstance, deps: AuthDeps): void {
  const { config, prisma, mailer, clock, throttle: loginThrottle } = deps;
  const authLimit = {
    rateLimit: { max: config.AUTH_RATE_LIMIT_PER_MINUTE, timeWindow: '1 minute' },
  };
  const authenticate = createAuthenticator({ config, prisma, clock });

  const sessionTtlMs = config.SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;
  const appOrigin = new URL(config.APP_URL).origin;
  const cookieOptions = {
    httpOnly: true,
    secure: config.NODE_ENV === 'production',
    sameSite: 'strict' as const,
    path: REFRESH_COOKIE_PATH,
  };

  function setRefreshCookie(reply: FastifyReply, token: string): void {
    reply.setCookie(REFRESH_COOKIE, token, {
      ...cookieOptions,
      maxAge: Math.floor(sessionTtlMs / 1000),
    });
  }

  function readRefreshCookie(request: FastifyRequest): string | undefined {
    const value = request.cookies[REFRESH_COOKIE];
    return value !== undefined && REFRESH_TOKEN_SHAPE.test(value) ? value : undefined;
  }

  function assertAppOrigin(request: FastifyRequest): void {
    if (request.headers.origin !== appOrigin) {
      throw new AppError(403, 'FORBIDDEN', 'Forbidden');
    }
  }

  async function issueAccessToken(userId: string, sessionId: string): Promise<AccessTokenResponse> {
    const accessToken = await signAccessToken(
      { userId, sessionId },
      config.JWT_SECRET,
      config.ACCESS_TOKEN_TTL_SECONDS,
      clock(),
    );
    return { accessToken, expiresIn: config.ACCESS_TOKEN_TTL_SECONDS };
  }

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

  app.post('/auth/login', { config: authLimit }, async (request, reply) => {
    const { email, authKey } = loginRequestSchema.parse(request.body);
    const now = clock();

    if (loginThrottle.isBlocked(email, now)) {
      throw new AppError(429, 'TOO_MANY_ATTEMPTS', 'Too many failed attempts, try again later');
    }

    const user = await prisma.user.findUnique({ where: { email } });
    const verified = user !== null && user.emailVerifiedAt !== null;
    const keyMatches = verifyAuthKey(
      authKey,
      verified ? user.authHash : hashAuthKey(toBase64Url(new Uint8Array(32)), config.SERVER_PEPPER),
      config.SERVER_PEPPER,
    );
    if (!verified || !keyMatches) {
      loginThrottle.recordFailure(email, now);
      throw new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
    }

    const { challengeId, code } = await issueChallenge(prisma, config.SERVER_PEPPER, {
      userId: user.id,
      purpose: 'LOGIN',
      now,
    });
    void mailer
      .send(buildOtpEmail(email, code, 'LOGIN', OTP_TTL_MINUTES))
      .catch((error: unknown) => request.log.error(error, 'failed to send login email'));

    const response: ChallengeResponse = { challengeId };
    return reply.code(202).send(response);
  });

  app.post(
    '/auth/verify-otp',
    { config: authLimit },
    async (request, reply): Promise<AccessTokenResponse> => {
      const { challengeId, code } = verifyCodeRequestSchema.parse(request.body);
      const now = clock();
      const { userId } = await redeemChallenge(prisma, config.SERVER_PEPPER, {
        challengeId,
        code,
        purpose: 'LOGIN',
        now,
      });
      const session = await createSession(prisma, config.SERVER_PEPPER, {
        userId,
        userAgent: request.headers['user-agent'],
        now,
        ttlMs: sessionTtlMs,
      });
      setRefreshCookie(reply, session.refreshToken);
      return issueAccessToken(userId, session.sessionId);
    },
  );

  app.post(
    '/auth/refresh',
    { config: authLimit },
    async (request, reply): Promise<AccessTokenResponse> => {
      assertAppOrigin(request);
      const refreshToken = readRefreshCookie(request);
      if (!refreshToken) {
        throw new AppError(401, 'UNAUTHENTICATED', 'Invalid or expired session');
      }
      const result = await rotateSession(prisma, config.SERVER_PEPPER, {
        refreshToken,
        now: clock(),
        ttlMs: sessionTtlMs,
      });
      if (!result.ok) {
        if (result.clearCookie) {
          reply.clearCookie(REFRESH_COOKIE, cookieOptions);
        }
        throw new AppError(401, 'UNAUTHENTICATED', 'Invalid or expired session');
      }
      setRefreshCookie(reply, result.session.refreshToken);
      return issueAccessToken(result.session.userId, result.session.sessionId);
    },
  );

  app.post('/auth/logout', { config: authLimit }, async (request, reply) => {
    assertAppOrigin(request);
    const refreshToken = readRefreshCookie(request);
    if (refreshToken) {
      await revokeSession(prisma, config.SERVER_PEPPER, { refreshToken, now: clock() });
    }
    reply.clearCookie(REFRESH_COOKIE, cookieOptions);
    return reply.code(204).send();
  });

  app.get('/auth/me', async (request): Promise<MeResponse> => {
    const { userId } = await authenticate(request);
    const user = await prisma.user.findUniqueOrThrow({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        kdfSalt: true,
        kdfMemoryKiB: true,
        kdfIterations: true,
        kdfParallelism: true,
        wrappedVaultKey: true,
      },
    });
    return { ...user, wrappedVaultKey: wrappedKeyEnvelopeSchema.parse(user.wrappedVaultKey) };
  });
}
