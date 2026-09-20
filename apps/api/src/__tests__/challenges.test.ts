import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { OTP_MAX_ATTEMPTS, OTP_TTL_MINUTES, issueChallenge, redeemChallenge } from '../challenges';
import { type PrismaClient, createPrismaClient } from '../db';

const databaseUrl = process.env['DATABASE_URL'];
const pepper = 'p'.repeat(32);

describe.skipIf(!databaseUrl)('izazovi (OTP) u bazi', () => {
  let prisma: PrismaClient;
  let userId: string;
  const now = new Date('2030-01-01T12:00:00Z');

  beforeAll(async () => {
    prisma = createPrismaClient(databaseUrl as string);
    const user = await prisma.user.create({
      data: {
        email: `izazovi-${randomUUID()}@example.com`,
        authHash: 'x',
        kdfSalt: 'x',
        kdfMemoryKiB: 19456,
        kdfIterations: 2,
        kdfParallelism: 1,
        wrappedVaultKey: {},
      },
    });
    userId = user.id;
  });

  afterAll(async () => {
    await prisma.user.delete({ where: { id: userId } });
    await prisma.$disconnect();
  });

  const issue = (purpose: 'LOGIN' | 'EMAIL_VERIFICATION' = 'LOGIN') =>
    issueChallenge(prisma, pepper, { userId, purpose, now });

  const redeem = (
    challengeId: string,
    code: string,
    purpose: 'LOGIN' | 'EMAIL_VERIFICATION' = 'LOGIN',
    at: Date = now,
  ) => redeemChallenge(prisma, pepper, { challengeId, code, purpose, now: at });

  const wrongCodeFor = (code: string) => (code === '000000' ? '000001' : '000000');

  it('tacan kod se prihvata i vraca vlasnika izazova', async () => {
    const { challengeId, code } = await issue();
    expect(code).toMatch(/^\d{6}$/);
    expect(await redeem(challengeId, code)).toEqual({ userId });
  });

  it('u bazi nema otvorenog koda, samo njegov heš', async () => {
    const { challengeId, code } = await issue();
    const row = await prisma.otpChallenge.findUniqueOrThrow({ where: { id: challengeId } });
    expect(row.codeHash).not.toContain(code);
    expect(row.codeHash).toHaveLength(43);
    expect(row.expiresAt.getTime()).toBe(now.getTime() + OTP_TTL_MINUTES * 60_000);
  });

  it('pogresan kod se odbija opstom greskom i broji se kao pokusaj', async () => {
    const { challengeId, code } = await issue();
    await expect(redeem(challengeId, wrongCodeFor(code))).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_CODE',
    });
    const row = await prisma.otpChallenge.findUniqueOrThrow({ where: { id: challengeId } });
    expect(row.attempts).toBe(1);
    await expect(redeem(challengeId, code)).resolves.toEqual({ userId });
  });

  it(`posle ${OTP_MAX_ATTEMPTS} pogresnih pokusaja izazov je zakljucan, cak i za tacan kod`, async () => {
    const { challengeId, code } = await issue();
    for (let i = 0; i < OTP_MAX_ATTEMPTS; i++) {
      await expect(redeem(challengeId, wrongCodeFor(code))).rejects.toThrow();
    }
    await expect(redeem(challengeId, code)).rejects.toMatchObject({ code: 'INVALID_CODE' });
  });

  it('istovremeni pokusaji ne mogu da prekorace limit (atomsko brojanje)', async () => {
    const { challengeId, code } = await issue();
    const results = await Promise.allSettled(
      Array.from({ length: 25 }, () => redeem(challengeId, wrongCodeFor(code))),
    );
    expect(results.every((result) => result.status === 'rejected')).toBe(true);

    const row = await prisma.otpChallenge.findUniqueOrThrow({ where: { id: challengeId } });
    expect(row.attempts).toBe(OTP_MAX_ATTEMPTS);
    await expect(redeem(challengeId, code)).rejects.toMatchObject({ code: 'INVALID_CODE' });
  });

  it('istovremeni zahtevi sa tacnim kodom: uspeva tacno jedan', async () => {
    const { challengeId, code } = await issue();
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, () => redeem(challengeId, code)),
    );
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
  });

  it('kod vazi do isteka, a ne posle', async () => {
    const { challengeId, code } = await issue();
    const almostExpired = new Date(now.getTime() + (OTP_TTL_MINUTES * 60_000 - 1000));
    const expired = new Date(now.getTime() + OTP_TTL_MINUTES * 60_000 + 1000);
    await expect(redeem(challengeId, code, 'LOGIN', expired)).rejects.toMatchObject({
      code: 'INVALID_CODE',
    });
    await expect(redeem(challengeId, code, 'LOGIN', almostExpired)).resolves.toEqual({ userId });
  });

  it('kod se moze iskoristiti samo jednom', async () => {
    const { challengeId, code } = await issue();
    await redeem(challengeId, code);
    await expect(redeem(challengeId, code)).rejects.toMatchObject({ code: 'INVALID_CODE' });
  });

  it('kod za jednu namenu ne vazi za drugu', async () => {
    const { challengeId, code } = await issue('LOGIN');
    await expect(redeem(challengeId, code, 'EMAIL_VERIFICATION')).rejects.toMatchObject({
      code: 'INVALID_CODE',
    });
    // Neuspeh zbog namene ne trosi izazov ni pokusaje.
    await expect(redeem(challengeId, code, 'LOGIN')).resolves.toEqual({ userId });
  });

  it('novi izazov ponistava prethodni iste namene, ali ne dira drugu namenu', async () => {
    const first = await issue('LOGIN');
    const other = await issue('EMAIL_VERIFICATION');
    const second = await issue('LOGIN');

    await expect(redeem(first.challengeId, first.code)).rejects.toMatchObject({
      code: 'INVALID_CODE',
    });
    await expect(redeem(second.challengeId, second.code)).resolves.toEqual({ userId });
    await expect(redeem(other.challengeId, other.code, 'EMAIL_VERIFICATION')).resolves.toEqual({
      userId,
    });
  });

  it('nepostojeci izazov daje istu gresku kao pogresan kod', async () => {
    await expect(redeem(randomUUID(), '123456')).rejects.toMatchObject({
      statusCode: 400,
      code: 'INVALID_CODE',
      message: 'Invalid or expired code',
    });
  });
});
