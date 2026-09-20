import {
  type ListItemsResponse,
  type PutItemResponse,
  type SyncItem,
  itemEnvelopeSchema,
  itemIdSchema,
  listItemsQuerySchema,
  putItemRequestSchema,
} from '@sleepsafe/shared';
import type { FastifyInstance } from 'fastify';
import { createAuthenticator } from '../authenticate';
import type { Config } from '../config';
import { Prisma, type PrismaClient } from '../db';
import { AppError } from '../errors';

export interface VaultDeps {
  config: Config;
  prisma: PrismaClient;
  clock: () => Date;
}

const notFound = () => new AppError(404, 'NOT_FOUND', 'Not found');
const conflict = () => new AppError(409, 'CONFLICT', 'Item was modified elsewhere');

async function withVaultLock<T>(
  prisma: PrismaClient,
  userId: string,
  work: (tx: Prisma.TransactionClient) => Promise<T>,
): Promise<T> {
  return prisma.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM users WHERE id = ${userId}::uuid FOR UPDATE`;
    return work(tx);
  });
}

async function bumpRevision(tx: Prisma.TransactionClient, userId: string): Promise<number> {
  const user = await tx.user.update({
    where: { id: userId },
    data: { vaultRevision: { increment: 1 } },
    select: { vaultRevision: true },
  });
  return user.vaultRevision;
}

function toSyncItem(row: {
  id: string;
  revision: number;
  envelope: Prisma.JsonValue | null;
  deletedAt: Date | null;
  updatedAt: Date;
}): SyncItem {
  const deleted = row.deletedAt !== null || row.envelope === null;
  return {
    id: row.id,
    revision: row.revision,
    deleted,
    envelope: deleted ? null : itemEnvelopeSchema.parse(row.envelope),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export function registerVaultRoutes(app: FastifyInstance, deps: VaultDeps): void {
  const { config, prisma, clock } = deps;
  const authenticate = createAuthenticator({ config, prisma, clock });

  function itemId(request: { params: unknown }): string {
    return itemIdSchema.parse((request.params as { id?: unknown }).id);
  }

  app.get('/vault/items', async (request): Promise<ListItemsResponse> => {
    const { userId } = await authenticate(request);
    const { since, limit } = listItemsQuerySchema.parse(request.query);

    const rows = await prisma.vaultItem.findMany({
      where: { userId, revision: { gt: since }, ...(since === 0 ? { deletedAt: null } : {}) },
      orderBy: { revision: 'asc' },
      take: limit + 1,
    });
    const page = rows.slice(0, limit);
    return {
      items: page.map(toSyncItem),
      cursor: page.at(-1)?.revision ?? since,
      hasMore: rows.length > limit,
    };
  });

  app.get('/vault/items/:id', async (request): Promise<SyncItem> => {
    const { userId } = await authenticate(request);
    const id = itemId(request);
    const row = await prisma.vaultItem.findUnique({ where: { userId_id: { userId, id } } });
    if (!row || row.deletedAt !== null) {
      throw notFound();
    }
    return toSyncItem(row);
  });

  app.put('/vault/items/:id', async (request, reply) => {
    const { userId } = await authenticate(request);
    const id = itemId(request);
    const { envelope, baseRevision } = putItemRequestSchema.parse(request.body);
    const now = clock();

    const { revision, created } = await withVaultLock(prisma, userId, async (tx) => {
      const existing = await tx.vaultItem.findUnique({ where: { userId_id: { userId, id } } });

      if (baseRevision === null) {
        if (existing) {
          throw conflict();
        }
        const active = await tx.vaultItem.count({ where: { userId, deletedAt: null } });
        if (active >= config.MAX_ITEMS_PER_USER) {
          throw new AppError(422, 'VAULT_FULL', 'Item limit reached');
        }
        const revision = await bumpRevision(tx, userId);
        await tx.vaultItem.create({
          data: { id, userId, envelope, revision, createdAt: now, updatedAt: now },
        });
        return { revision, created: true };
      }

      if (!existing) {
        throw notFound();
      }
      if (existing.deletedAt !== null || existing.revision !== baseRevision) {
        throw conflict();
      }
      const revision = await bumpRevision(tx, userId);
      await tx.vaultItem.update({
        where: { userId_id: { userId, id } },
        data: { envelope, revision, updatedAt: now },
      });
      return { revision, created: false };
    });

    const response: PutItemResponse = { id, revision };
    return reply.code(created ? 201 : 200).send(response);
  });

  app.delete('/vault/items/:id', async (request, reply) => {
    const { userId } = await authenticate(request);
    const id = itemId(request);
    const now = clock();

    await withVaultLock(prisma, userId, async (tx) => {
      const existing = await tx.vaultItem.findUnique({ where: { userId_id: { userId, id } } });
      if (!existing || existing.deletedAt !== null) {
        return;
      }
      const revision = await bumpRevision(tx, userId);
      await tx.vaultItem.update({
        where: { userId_id: { userId, id } },
        data: { envelope: Prisma.DbNull, deletedAt: now, revision, updatedAt: now },
      });
    });

    return reply.code(204).send();
  });
}
