import type { KdfParams } from '@sleepsafe/crypto';

export const MIN_MASTER_PASSWORD_LENGTH = 12;

export function strongerKdfParams(current: KdfParams, recommended: KdfParams): KdfParams {
  return {
    memoryKiB: Math.max(current.memoryKiB, recommended.memoryKiB),
    iterations: Math.max(current.iterations, recommended.iterations),
    parallelism: Math.max(current.parallelism, recommended.parallelism),
  };
}
