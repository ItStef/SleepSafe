import { type KdfParams, deriveKeys } from '@sleepsafe/crypto';

interface Job {
  password: string;
  salt: Uint8Array;
  params: KdfParams;
}

const scope = self as unknown as {
  onmessage: ((event: MessageEvent<Job>) => void) | null;
  postMessage(message: unknown): void;
};

scope.onmessage = async (event) => {
  try {
    const { password, salt, params } = event.data;
    const { authKey, kek } = await deriveKeys(password, salt, params);
    scope.postMessage({ ok: true, authKey, kek });
  } catch (error) {
    scope.postMessage({ ok: false, message: error instanceof Error ? error.message : 'failed' });
  }
};
