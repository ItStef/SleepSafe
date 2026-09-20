import type { FastifyRequest } from 'fastify';
import type { Config } from './config';
import type { PrismaClient } from './db';
import { AppError } from './errors';
import { verifyAccessToken } from './security';

export interface AuthContext {
  userId: string;
  sessionId: string;
}

export type Authenticate = (request: FastifyRequest) => Promise<AuthContext>;

const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;

function unauthenticated(): AppError {
  return new AppError(401, 'UNAUTHENTICATED', 'Invalid or expired token');
}

export function createAuthenticator(deps: {
  config: Config;
  prisma: PrismaClient;
  clock: () => Date;
}): Authenticate {
  const { config, prisma, clock } = deps;
  return async (request) => {
    const match = BEARER.exec(request.headers.authorization ?? '');
    if (!match?.[1]) {
      throw unauthenticated();
    }
    const now = clock();
    const claims = await verifyAccessToken(match[1], config.JWT_SECRET, now);
    const session = await prisma.session.findFirst({
      where: {
        id: claims.sessionId,
        userId: claims.userId,
        revokedAt: null,
        expiresAt: { gt: now },
      },
      select: { id: true },
    });
    if (!session) {
      throw unauthenticated();
    }
    return { userId: claims.userId, sessionId: claims.sessionId };
  };
}
