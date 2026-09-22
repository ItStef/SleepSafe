import type { FastifyRequest } from 'fastify';
import type { PrismaClient } from './db';

export type AuditEventType =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILURE'
  | 'LOGOUT'
  | 'PASSWORD_CHANGED'
  | 'ACCOUNT_DELETED'
  | 'SESSION_REVOKED';

const MAX_USER_AGENT_LENGTH = 255;

export interface AuditEntry {
  userId?: string | null;
  email?: string | null;
  type: AuditEventType;
  request: FastifyRequest;
  now?: Date;
}

export async function recordAuditEvent(prisma: PrismaClient, entry: AuditEntry): Promise<void> {
  try {
    await prisma.auditEvent.create({
      data: {
        userId: entry.userId ?? null,
        email: entry.email ?? null,
        type: entry.type,
        ip: entry.request.ip,
        userAgent: entry.request.headers['user-agent']?.slice(0, MAX_USER_AGENT_LENGTH) ?? null,
        createdAt: entry.now ?? new Date(),
      },
    });
  } catch (error) {
    entry.request.log.error(error, 'failed to record audit event');
  }
}
