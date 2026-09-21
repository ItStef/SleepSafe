import { randomUUID } from 'node:crypto';
import {
  type KdfParams,
  createVault,
  deriveKeys,
  generateSalt,
  randomBytes,
  rewrapVaultKey,
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

// Za testove koji ne proveravaju oporavak: oblik je ispravan, a kljuceva ne izvodi iz pravih kodova
// (20 Argon2 izvodjenja po nalogu bi usporila stotine registracija).
export function fakeRecoveryBundle() {
  return {
    kdfSalt: toBase64Url(generateSalt()),
    kdfMemoryKiB: CLIENT_KDF.memoryKiB,
    kdfIterations: CLIENT_KDF.iterations,
    kdfParallelism: CLIENT_KDF.parallelism,
    codes: Array.from({ length: 20 }, () => ({
      authKey: toBase64Url(randomBytes(32)),
      wrappedVaultKey: {
        v: 1 as const,
        iv: toBase64Url(randomBytes(12)),
        ct: toBase64Url(randomBytes(48)),
      },
    })),
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
      recovery: fakeRecoveryBundle(),
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

export const APP_ORIGIN = 'http://localhost:5173';
export const REFRESH_COOKIE = 'sleepsafe_refresh';

type Registration = Awaited<ReturnType<typeof prepareRegistration>>;

export async function registerVerified(
  env: TestEnv,
  email: string,
  password: string,
): Promise<Registration> {
  const registration = await prepareRegistration(email, password);
  const response = await env.app.inject({
    method: 'POST',
    url: '/auth/register',
    payload: registration.body,
  });
  const { challengeId } = response.json<{ challengeId: string }>();
  const verify = await env.app.inject({
    method: 'POST',
    url: '/auth/verify-email',
    payload: { challengeId, code: codeFrom(env.mailer.last) },
  });
  if (verify.statusCode !== 204) {
    throw new Error('Email verification failed in test setup');
  }
  return registration;
}

export interface LoggedIn {
  accessToken: string;
  refreshToken: string;
}

export async function logIn(
  env: TestEnv,
  registration: { body: { email: string; authKey: string } },
): Promise<LoggedIn> {
  const { email, authKey } = registration.body;
  const login = await env.app.inject({
    method: 'POST',
    url: '/auth/login',
    payload: { email, authKey },
  });
  if (login.statusCode !== 202) {
    throw new Error(`Login failed in test setup: ${login.statusCode}`);
  }
  const verify = await env.app.inject({
    method: 'POST',
    url: '/auth/verify-otp',
    payload: {
      challengeId: login.json<{ challengeId: string }>().challengeId,
      code: codeFrom(env.mailer.last),
    },
  });
  const refreshToken = verify.cookies.find((cookie) => cookie.name === REFRESH_COOKIE)?.value;
  if (verify.statusCode !== 200 || !refreshToken) {
    throw new Error('OTP verification failed in test setup');
  }
  return { accessToken: verify.json<{ accessToken: string }>().accessToken, refreshToken };
}

export function bearer(accessToken: string): { authorization: string } {
  return { authorization: `Bearer ${accessToken}` };
}

export function refreshWith(
  env: TestEnv,
  refreshToken: string,
  origin: string | null = APP_ORIGIN,
) {
  return env.app.inject({
    method: 'POST',
    url: '/auth/refresh',
    headers: origin === null ? {} : { origin },
    cookies: { [REFRESH_COOKIE]: refreshToken },
  });
}

export async function prepareNewPassword(registration: Registration, newPassword: string) {
  const newSalt = generateSalt();
  const { authKey, kek } = await deriveKeys(newPassword, newSalt, CLIENT_KDF);
  const wrappedVaultKey = await rewrapVaultKey(
    registration.body.wrappedVaultKey,
    registration.kek,
    kek,
  );
  const newAuthKey = toBase64Url(authKey);
  const kdfSalt = toBase64Url(newSalt);
  return {
    payload: {
      currentAuthKey: registration.body.authKey,
      newAuthKey,
      kdfSalt,
      kdfMemoryKiB: CLIENT_KDF.memoryKiB,
      kdfIterations: CLIENT_KDF.iterations,
      kdfParallelism: CLIENT_KDF.parallelism,
      wrappedVaultKey,
    },
    next: {
      ...registration,
      salt: newSalt,
      kek,
      body: { ...registration.body, authKey: newAuthKey, kdfSalt, wrappedVaultKey },
    },
  };
}
