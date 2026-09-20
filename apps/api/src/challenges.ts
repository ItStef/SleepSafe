import { randomUUID } from 'node:crypto';
import type { PrismaClient } from './db';
import type { OtpEmailPurpose } from './emails';
import { AppError } from './errors';
import { generateOtp, hashOtp, verifyOtp } from './security';

export const OTP_TTL_MINUTES = 10;
export const OTP_MAX_ATTEMPTS = 5;

function invalidCode(): AppError {
  return new AppError(400, 'INVALID_CODE', 'Invalid or expired code');
}

export interface IssuedChallenge {
  challengeId: string;
  code: string;
}

export async function issueChallenge(
  prisma: PrismaClient,
  pepper: string,
  params: { userId: string; purpose: OtpEmailPurpose; now: Date },
): Promise<IssuedChallenge> {
  const { userId, purpose, now } = params;
  const code = generateOtp();
  const challengeId = randomUUID();
  await prisma.$transaction([
    prisma.otpChallenge.updateMany({
      where: { userId, purpose, consumedAt: null },
      data: { consumedAt: now },
    }),
    prisma.otpChallenge.create({
      data: {
        id: challengeId,
        userId,
        purpose,
        codeHash: hashOtp(code, challengeId, pepper),
        expiresAt: new Date(now.getTime() + OTP_TTL_MINUTES * 60_000),
      },
    }),
  ]);
  return { challengeId, code };
}

export async function redeemChallenge(
  prisma: PrismaClient,
  pepper: string,
  params: { challengeId: string; code: string; purpose: OtpEmailPurpose; now: Date },
): Promise<{ userId: string }> {
  const { challengeId, code, purpose, now } = params;

  const claimed = await prisma.otpChallenge.updateMany({
    where: {
      id: challengeId,
      purpose,
      consumedAt: null,
      expiresAt: { gt: now },
      attempts: { lt: OTP_MAX_ATTEMPTS },
    },
    data: { attempts: { increment: 1 } },
  });
  if (claimed.count !== 1) {
    throw invalidCode();
  }

  const challenge = await prisma.otpChallenge.findUnique({ where: { id: challengeId } });
  if (!challenge || !verifyOtp(code, challenge.id, challenge.codeHash, pepper)) {
    throw invalidCode();
  }

  const consumed = await prisma.otpChallenge.updateMany({
    where: { id: challengeId, consumedAt: null },
    data: { consumedAt: now },
  });
  if (consumed.count !== 1) {
    throw invalidCode();
  }
  return { userId: challenge.userId };
}
