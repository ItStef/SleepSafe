import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance } from 'fastify';
import { ZodError } from 'zod';
import type { Config } from './config';
import type { PrismaClient } from './db';
import { AppError } from './errors';
import type { Mailer } from './mailer';
import { registerAuthRoutes } from './routes/auth';
import { registerHealthRoutes } from './routes/health';
import { registerRecoveryRoutes } from './routes/recovery';
import { registerVaultRoutes } from './routes/vault';
import { registerAccountRoutes } from './routes/account';
import { FailureThrottle } from './throttle';

export interface AppDeps {
  config: Config;
  prisma: PrismaClient;
  mailer: Mailer;
  clock?: () => Date;
}

function errorBody(code: string, message: string) {
  return { error: { code, message } };
}

export async function buildApp({
  config,
  prisma,
  mailer,
  clock = () => new Date(),
}: AppDeps): Promise<FastifyInstance> {
  const app = Fastify({
    logger:
      config.NODE_ENV === 'test'
        ? false
        : {
            level: config.LOG_LEVEL,
            redact: [
              'req.headers.authorization',
              'req.headers.cookie',
              'res.headers["set-cookie"]',
            ],
          },
    trustProxy: config.TRUST_PROXY,
    bodyLimit: 1024 * 1024, // 1 MiB je dovoljno za stavke; veci telo se odbija
  });

  await app.register(helmet, {
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'none'"],
      },
    },
  });

  await app.register(cors, {
    origin: [config.APP_URL],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  });

  await app.register(cookie);

  await app.register(rateLimit, {
    global: true,
    max: config.RATE_LIMIT_PER_MINUTE,
    timeWindow: '1 minute',
    errorResponseBuilder: () => new AppError(429, 'RATE_LIMITED', 'Too many requests'),
  });

  app.addHook('onSend', async (_request, reply) => {
    reply.header('Cache-Control', 'no-store');
  });

  app.setNotFoundHandler((_request, reply) => {
    return reply.code(404).send(errorBody('NOT_FOUND', 'Not found'));
  });

  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ZodError) {
      return reply.code(400).send(errorBody('VALIDATION_ERROR', 'Invalid request'));
    }
    if (error instanceof AppError) {
      return reply.code(error.statusCode).send(errorBody(error.code, error.message));
    }
    const statusCode =
      typeof (error as { statusCode?: unknown }).statusCode === 'number'
        ? (error as { statusCode: number }).statusCode
        : 500;
    if (statusCode >= 400 && statusCode < 500) {
      return reply.code(statusCode).send(errorBody('BAD_REQUEST', 'Bad request'));
    }
    request.log.error(error);
    return reply.code(500).send(errorBody('INTERNAL', 'Internal server error'));
  });

  registerHealthRoutes(app, { prisma });
  registerVaultRoutes(app, { config, prisma, clock });
  const throttle = new FailureThrottle(
    config.LOGIN_MAX_FAILURES,
    config.LOGIN_LOCKOUT_MINUTES * 60_000,
  );
  registerAuthRoutes(app, { config, prisma, mailer, clock, throttle });
  registerAccountRoutes(app, { config, prisma, mailer, clock, throttle });
  registerRecoveryRoutes(app, { config, prisma, mailer, clock, throttle });

  return app;
}
