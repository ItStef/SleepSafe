import { type KdfParams, deriveKeys, deriveRecoveryKeys } from '@sleepsafe/crypto';

interface Job {
  kind: 'master' | 'recovery';
  secret: string;
  salt: Uint8Array;
  params: KdfParams;
}

const scope = self as unknown as {
  onmessage: ((event: MessageEvent<Job>) => void) | null;
  postMessage(message: unknown): void;
};

scope.onmessage = async (event) => {
  try {
    const { kind, secret, salt, params } = event.data;
    const { authKey, kek } =
      kind === 'recovery'
        ? await deriveRecoveryKeys(secret, salt, params)
        : await deriveKeys(secret, salt, params);
    scope.postMessage({ ok: true, authKey, kek });
  } catch (error) {
    scope.postMessage({ ok: false, message: error instanceof Error ? error.message : 'failed' });
  }
};
