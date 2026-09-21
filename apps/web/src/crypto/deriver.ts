import {
  type KdfParams,
  type RecoveryKeys,
  deriveKeys,
  deriveRecoveryKeys,
} from '@sleepsafe/crypto';

export interface DerivedSecrets {
  authKey: Uint8Array;
  kek: CryptoKey;
}

export interface KeyDeriver {
  derive(password: string, salt: Uint8Array, params: KdfParams): Promise<DerivedSecrets>;
  deriveRecovery(code: string, salt: Uint8Array, params: KdfParams): Promise<RecoveryKeys>;
}

export const inlineDeriver: KeyDeriver = {
  derive: (password, salt, params) => deriveKeys(password, salt, params),
  deriveRecovery: (code, salt, params) => deriveRecoveryKeys(code, salt, params),
};

type WorkerReply =
  { ok: true; authKey: Uint8Array; kek: CryptoKey } | { ok: false; message: string };

// Svako izvodjenje ide u novi Web Worker, da Argon2id (64 MiB) ne blokira ekran, a memorija se
// oslobadja cim se zavrsi.
function runInWorker(
  kind: 'master' | 'recovery',
  secret: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<DerivedSecrets> {
  return new Promise<DerivedSecrets>((resolve, reject) => {
    const worker = new Worker(new URL('./kdf.worker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = (event: MessageEvent<WorkerReply>) => {
      worker.terminate();
      const reply = event.data;
      if (reply.ok) {
        resolve({ authKey: reply.authKey, kek: reply.kek });
      } else {
        reject(new Error(reply.message));
      }
    };
    worker.onerror = () => {
      worker.terminate();
      reject(new Error('Key derivation failed'));
    };
    worker.postMessage({ kind, secret, salt, params });
  });
}

export function createWorkerDeriver(): KeyDeriver {
  return {
    derive: (password, salt, params) => runInWorker('master', password, salt, params),
    deriveRecovery: async (code, salt, params) => {
      const keys = await runInWorker('recovery', code, salt, params);
      return { authKey: new Uint8Array(keys.authKey), kek: keys.kek };
    },
  };
}
