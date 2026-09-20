import type { FastifyInstance } from 'fastify';
import type { PrismaClient } from '../db';

export function registerHealthRoutes(app: FastifyInstance, deps: { prisma: PrismaClient }): void {
  app.get('/health', { config: { rateLimit: false } }, async (_request, reply) => {
    try {
      await deps.prisma.$queryRaw`SELECT 1`;
      return { status: 'ok' };
    } catch (error) {
      app.log.error(error, 'health check: database unreachable');
      return reply.code(503).send({ status: 'error' });
    }
  });
}
