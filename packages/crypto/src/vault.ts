import { IV_LENGTH, TAG_LENGTH_BYTES, aesGcmDecrypt, aesGcmEncrypt } from './aes';
import {
  type Bytes,
  fromBase64Url,
  randomBytes,
  toBase64Url,
  utf8Decode,
  utf8Encode,
} from './bytes';
import { CryptoError } from './errors';

export const ENVELOPE_VERSION = 1;

export interface Envelope {
  v: number;
  iv: string; // base64url
  ct: string; // base64url, sifrat sa tagom na kraju
}

export interface ItemContext {
  userId: string;
  itemId: string;
}

const VAULT_KEY_AAD = utf8Encode('sleepsafe/v1/vault-key');
const TAG_LENGTH_BITS = TAG_LENGTH_BYTES * 8;

function makeEnvelope(iv: Uint8Array, ciphertext: Uint8Array): Envelope {
  return { v: ENVELOPE_VERSION, iv: toBase64Url(iv), ct: toBase64Url(ciphertext) };
}

function parseEnvelope(envelope: Envelope): { iv: Bytes; ct: Bytes } {
  if (envelope.v !== ENVELOPE_VERSION) {
    throw new CryptoError('UNSUPPORTED_VERSION', 'Unsupported envelope version');
  }
  if (typeof envelope.iv !== 'string' || typeof envelope.ct !== 'string') {
    throw new CryptoError('INVALID_INPUT', 'Malformed envelope');
  }
  return { iv: fromBase64Url(envelope.iv), ct: fromBase64Url(envelope.ct) };
}

function itemAad(context: ItemContext): Bytes {
  const { userId, itemId } = context;
  if (typeof userId !== 'string' || userId === '' || typeof itemId !== 'string' || itemId === '') {
    throw new CryptoError('INVALID_INPUT', 'Invalid item context');
  }
  return utf8Encode(JSON.stringify(['sleepsafe/v1/item', userId, itemId]));
}

export async function wrapVaultKey(vaultKey: CryptoKey, kek: CryptoKey): Promise<Envelope> {
  const iv = randomBytes(IV_LENGTH);
  const wrapped = await crypto.subtle.wrapKey('raw', vaultKey, kek, {
    name: 'AES-GCM',
    iv,
    additionalData: VAULT_KEY_AAD,
    tagLength: TAG_LENGTH_BITS,
  });
  return makeEnvelope(iv, new Uint8Array(wrapped));
}

export async function unwrapVaultKey(
  envelope: Envelope,
  kek: CryptoKey,
  options: { extractable?: boolean } = {},
): Promise<CryptoKey> {
  const { iv, ct } = parseEnvelope(envelope);
  try {
    return await crypto.subtle.unwrapKey(
      'raw',
      ct,
      kek,
      { name: 'AES-GCM', iv, additionalData: VAULT_KEY_AAD, tagLength: TAG_LENGTH_BITS },
      { name: 'AES-GCM', length: 256 },
      options.extractable ?? false,
      ['encrypt', 'decrypt'],
    );
  } catch {
    throw new CryptoError('DECRYPT_FAILED', 'Decryption failed');
  }
}

export interface CreatedVault {
  vaultKey: CryptoKey;
  wrappedVaultKey: Envelope;
}

export async function createVault(kek: CryptoKey): Promise<CreatedVault> {
  const fresh = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
  const wrappedVaultKey = await wrapVaultKey(fresh, kek);
  const vaultKey = await unwrapVaultKey(wrappedVaultKey, kek);
  return { vaultKey, wrappedVaultKey };
}

export async function rewrapVaultKey(
  envelope: Envelope,
  oldKek: CryptoKey,
  newKek: CryptoKey,
): Promise<Envelope> {
  const vaultKey = await unwrapVaultKey(envelope, oldKek, { extractable: true });
  return wrapVaultKey(vaultKey, newKek);
}

export async function encryptItem(
  vaultKey: CryptoKey,
  item: unknown,
  context: ItemContext,
): Promise<Envelope> {
  const json = JSON.stringify(item);
  if (json === undefined) {
    throw new CryptoError('INVALID_INPUT', 'Item is not serializable');
  }
  const { iv, ciphertext } = await aesGcmEncrypt(vaultKey, utf8Encode(json), itemAad(context));
  return makeEnvelope(iv, ciphertext);
}

export async function decryptItem(
  vaultKey: CryptoKey,
  envelope: Envelope,
  context: ItemContext,
): Promise<unknown> {
  const { iv, ct } = parseEnvelope(envelope);
  const plaintext = await aesGcmDecrypt(vaultKey, iv, ct, itemAad(context));
  try {
    return JSON.parse(utf8Decode(plaintext));
  } catch {
    throw new CryptoError('INVALID_INPUT', 'Malformed item');
  }
}
