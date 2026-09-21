import {
  type KdfParams,
  generateRecoveryCodes,
  generateSalt,
  toBase64Url,
  wrapVaultKey,
} from '@sleepsafe/crypto';
import { type RecoveryBundle, wrappedKeyEnvelopeSchema } from '@sleepsafe/shared';
import type { KeyDeriver } from '../crypto/deriver';

// Koliko se Argon2id izvodjenja radi istovremeno (svako trosi ~64 MiB): kompromis izmedju brzine
// i potrosnje memorije, narocito na telefonima.
export const RECOVERY_CONCURRENCY = 3;

export interface BuiltRecovery {
  bundle: RecoveryBundle;
  // Kodovi u kanonskom obliku (10 znakova). Samo klijent ih zna: server dobija izvedene vrednosti.
  codes: string[];
}

// Pravi `count` kodova i za svaki: dokaz posedovanja + Vault Key umotan kljucem izvedenim iz koda.
// `vaultKey` mora biti izvoziv (inace se ne moze umotati).
export async function buildRecoveryBundle(options: {
  deriver: KeyDeriver;
  vaultKey: CryptoKey;
  count: number;
  params: KdfParams;
  concurrency?: number;
}): Promise<BuiltRecovery> {
  const { deriver, vaultKey, count, params } = options;
  const codes = generateRecoveryCodes(count);
  const salt = generateSalt();
  const entries: RecoveryBundle['codes'] = new Array(count);

  let next = 0;
  const worker = async () => {
    for (;;) {
      const index = next++;
      const code = codes[index];
      if (code === undefined) {
        return;
      }
      const keys = await deriver.deriveRecovery(code, salt, params);
      const wrapped = await wrapVaultKey(vaultKey, keys.kek);
      entries[index] = {
        authKey: toBase64Url(keys.authKey),
        wrappedVaultKey: wrappedKeyEnvelopeSchema.parse(wrapped),
      };
      keys.authKey.fill(0);
    }
  };
  const width = Math.max(1, Math.min(options.concurrency ?? RECOVERY_CONCURRENCY, count));
  await Promise.all(Array.from({ length: width }, worker));

  return {
    bundle: {
      kdfSalt: toBase64Url(salt),
      kdfMemoryKiB: params.memoryKiB,
      kdfIterations: params.iterations,
      kdfParallelism: params.parallelism,
      codes: entries,
    },
    codes,
  };
}
