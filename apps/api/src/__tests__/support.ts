import { randomUUID } from 'node:crypto';
import {
  type KdfParams,
  createVault,
  deriveKeys,
  generateSalt,
  toBase64Url,
} from '@sleepsafe/crypto';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app';
import { type Config, loadConfig } from '../config';
import { type PrismaClient, createPrismaClient } from '../db';
import { MemoryMailer, type Mail } from '../mailer';

export const CLIENT_KDF: KdfParams = { memoryKiB: 19456, iterations: 2, parallelism: 1 };

export interface TestEnv {
  app: FastifyInstance;
  prisma: PrismaClient;
  mailer: MemoryMailer;
  config: Config;
  advance(milliseconds: number): void;
  newEmail(): string;
  close(): Promise<void>;
}

export async function createTestEnv(overrides: Record<string, string> = {}): Promise<TestEnv> {
  const databaseUrl = process.env['DATABASE_URL'] as string;
  const prisma = createPrismaClient(databaseUrl);
  const mailer = new MemoryMailer();
  const config = loadConfig({
    NODE_ENV: 'test',
    DATABASE_URL: databaseUrl,
    JWT_SECRET: 'j'.repeat(32),
    SERVER_PEPPER: 'p'.repeat(32),
    RATE_LIMIT_PER_MINUTE: '10000',
    AUTH_RATE_LIMIT_PER_MINUTE: '10000',
    ...overrides,
  });

  let current = new Date();
  const app = await buildApp({ config, prisma, mailer, clock: () => current });
  const emails: string[] = [];

  return {
    app,
    prisma,
    mailer,
    config,
    advance(milliseconds) {
      current = new Date(current.getTime() + milliseconds);
    },
    newEmail() {
      const email = `test-${randomUUID()}@example.com`;
      emails.push(email);
      return email;
    },
    async close() {
      await prisma.user.deleteMany({ where: { email: { in: emails } } });
      await app.close();
      await prisma.$disconnect();
    },
  };
}

export async function prepareRegistration(email: string, password: string) {
  const salt = generateSalt();
  const { authKey, kek } = await deriveKeys(password, salt, CLIENT_KDF);
  const { vaultKey, wrappedVaultKey } = await createVault(kek);
  return {
    body: {
      email,
      authKey: toBase64Url(authKey),
      kdfSalt: toBase64Url(salt),
      kdfMemoryKiB: CLIENT_KDF.memoryKiB,
      kdfIterations: CLIENT_KDF.iterations,
      kdfParallelism: CLIENT_KDF.parallelism,
      wrappedVaultKey,
    },
    salt,
    kek,
    vaultKey,
  };
}

export function codeFrom(mail: Mail | undefined): string {
  const code = /\b(\d{6})\b/.exec(mail?.text ?? '')?.[1];
  if (!code) {
    throw new Error('No code in mail');
  }
  return code;
}
