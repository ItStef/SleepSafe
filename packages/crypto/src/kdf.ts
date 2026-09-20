import { argon2id } from 'hash-wasm';
import { type Bytes, randomBytes, utf8Encode } from './bytes';
import { CryptoError } from './errors';

export interface KdfParams {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

export const DEFAULT_KDF_PARAMS: KdfParams = { memoryKiB: 65536, iterations: 3, parallelism: 1 };

export const SALT_LENGTH = 16;
export const KEY_LENGTH = 32;

const MIN_MEMORY_KIB = 19456; // 19 MiB
const MAX_MEMORY_KIB = 1048576; // 1 GiB
const MIN_ITERATIONS = 2;
const MAX_ITERATIONS = 20;
const MAX_PARALLELISM = 16;

const INFO_AUTH_KEY = utf8Encode('sleepsafe/v1/auth-key');
const INFO_KEK = utf8Encode('sleepsafe/v1/kek');

export function generateSalt(): Bytes {
  return randomBytes(SALT_LENGTH);
}

function isPositiveInteger(value: number): boolean {
  return Number.isInteger(value) && value >= 1;
}

function assertValidParams(params: KdfParams): void {
  const { memoryKiB, iterations, parallelism } = params;
  if (
    !isPositiveInteger(memoryKiB) ||
    !isPositiveInteger(iterations) ||
    !isPositiveInteger(parallelism) ||
    memoryKiB < 8 * parallelism
  ) {
    throw new CryptoError('INVALID_INPUT', 'Invalid KDF parameters');
  }
}

export function assertAcceptableKdfParams(params: KdfParams): void {
  assertValidParams(params);
  if (
    params.memoryKiB < MIN_MEMORY_KIB ||
    params.memoryKiB > MAX_MEMORY_KIB ||
    params.iterations < MIN_ITERATIONS ||
    params.iterations > MAX_ITERATIONS ||
    params.parallelism > MAX_PARALLELISM
  ) {
    throw new CryptoError('INVALID_INPUT', 'Unacceptable KDF parameters');
  }
}

export async function argon2idRaw(
  password: Uint8Array,
  salt: Uint8Array,
  params: KdfParams,
): Promise<Bytes> {
  assertValidParams(params);
  const hash = await argon2id({
    password,
    salt,
    memorySize: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: KEY_LENGTH,
    outputType: 'binary',
  });
  return new Uint8Array(hash);
}

export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<Bytes> {
  if (password.length === 0) {
    throw new CryptoError('INVALID_INPUT', 'Empty password');
  }
  if (salt.length < SALT_LENGTH) {
    throw new CryptoError('INVALID_INPUT', 'Salt too short');
  }
  return argon2idRaw(utf8Encode(password.normalize('NFKC')), salt, params);
}

export async function hkdfSha256(
  ikm: Bytes,
  salt: Bytes,
  info: Bytes,
  length: number,
): Promise<Bytes> {
  if (!Number.isInteger(length) || length < 1 || length > 255 * 32) {
    throw new CryptoError('INVALID_INPUT', 'Invalid HKDF length');
  }
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

export interface DerivedKeys {
  authKey: Bytes;
  kek: CryptoKey;
}

export async function deriveKeys(
  password: string,
  salt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<DerivedKeys> {
  const masterKey = await deriveMasterKey(password, salt, params);
  const noSalt = new Uint8Array(0);
  const authKey = await hkdfSha256(masterKey, noSalt, INFO_AUTH_KEY, KEY_LENGTH);
  const kekBytes = await hkdfSha256(masterKey, noSalt, INFO_KEK, KEY_LENGTH);
  const kek = await crypto.subtle.importKey('raw', kekBytes, 'AES-GCM', false, [
    'wrapKey',
    'unwrapKey',
  ]);
  masterKey.fill(0);
  kekBytes.fill(0);
  return { authKey, kek };
}
