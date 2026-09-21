import { assertAcceptableKdfParams } from '@sleepsafe/crypto';
import type { RecoveryBundle } from '@sleepsafe/shared';
import type { Prisma } from './db';
import { AppError } from './errors';
import { hashRecoveryAuth } from './security';

export const RESET_TOKEN_TTL_MINUTES = 10;
export const RESET_MAX_ATTEMPTS = 5;

export function invalidRecovery(): AppError {
  return new AppError(400, 'INVALID_RECOVERY', 'Invalid or expired recovery request');
}

// Isti minimum kao za master lozinku: slabi parametri se odbijaju i na serveru.
export function assertAcceptableRecoveryParams(bundle: RecoveryBundle): void {
  try {
    assertAcceptableKdfParams({
      memoryKiB: bundle.kdfMemoryKiB,
      iterations: bundle.kdfIterations,
      parallelism: bundle.kdfParallelism,
    });
  } catch {
    throw new AppError(400, 'VALIDATION_ERROR', 'Invalid request');
  }
}

// Zamenjuje ceo skup kodova (stari, iskorisceni i neiskorisceni, prestaju da vaze).
export async function replaceRecoveryCodes(
  tx: Prisma.TransactionClient,
  params: { userId: string; bundle: RecoveryBundle; pepper: string; now: Date },
): Promise<void> {
  const { userId, bundle, pepper, now } = params;
  await tx.recoveryCode.deleteMany({ where: { userId } });
  await tx.user.update({
    where: { id: userId },
    data: {
      recoverySalt: bundle.kdfSalt,
      recoveryKdfMemoryKiB: bundle.kdfMemoryKiB,
      recoveryKdfIterations: bundle.kdfIterations,
      recoveryKdfParallelism: bundle.kdfParallelism,
    },
  });
  await tx.recoveryCode.createMany({
    data: bundle.codes.map((code) => ({
      userId,
      codeHash: hashRecoveryAuth(code.authKey, pepper),
      wrappedVaultKey: code.wrappedVaultKey,
      createdAt: now,
    })),
  });
}
