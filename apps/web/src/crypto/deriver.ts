import type { KdfParams } from '@sleepsafe/crypto';

export interface DerivedSecrets {
  authKey: Uint8Array;
  kek: CryptoKey;
}

export interface KeyDeriver {
  derive(password: string, salt: Uint8Array, params: KdfParams): Promise<DerivedSecrets>;
}

type WorkerReply =
  { ok: true; authKey: Uint8Array; kek: CryptoKey } | { ok: false; message: string };

export function createWorkerDeriver(): KeyDeriver {
  return {
    derive: (password, salt, params) =>
      new Promise<DerivedSecrets>((resolve, reject) => {
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
        worker.postMessage({ password, salt, params });
      }),
  };
}
