import { type Bytes, randomBytes } from './bytes';
import { CryptoError } from './errors';

export const IV_LENGTH = 12; // 96 bita
export const TAG_LENGTH_BYTES = 16; // 128-bitni
const TAG_LENGTH_BITS = TAG_LENGTH_BYTES * 8;

export interface AesGcmResult {
  iv: Bytes;
  ciphertext: Bytes;
}

export async function aesGcmEncryptWithIv(
  key: CryptoKey,
  iv: Bytes,
  plaintext: Bytes,
  aad: Bytes,
): Promise<Bytes> {
  if (iv.length !== IV_LENGTH) {
    throw new CryptoError('INVALID_INPUT', 'Invalid IV length');
  }
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad, tagLength: TAG_LENGTH_BITS },
    key,
    plaintext,
  );
  return new Uint8Array(ciphertext);
}

export async function aesGcmEncrypt(
  key: CryptoKey,
  plaintext: Bytes,
  aad: Bytes,
): Promise<AesGcmResult> {
  const iv = randomBytes(IV_LENGTH);
  const ciphertext = await aesGcmEncryptWithIv(key, iv, plaintext, aad);
  return { iv, ciphertext };
}

export async function aesGcmDecrypt(
  key: CryptoKey,
  iv: Bytes,
  ciphertext: Bytes,
  aad: Bytes,
): Promise<Bytes> {
  if (iv.length !== IV_LENGTH) {
    throw new CryptoError('INVALID_INPUT', 'Invalid IV length');
  }
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: TAG_LENGTH_BITS },
      key,
      ciphertext,
    );
    return new Uint8Array(plaintext);
  } catch {
    throw new CryptoError('DECRYPT_FAILED', 'Decryption failed');
  }
}
