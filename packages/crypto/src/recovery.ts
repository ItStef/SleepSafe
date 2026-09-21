import { type Bytes, randomBytes, toBase64Url, utf8Encode } from './bytes';
import { CryptoError } from './errors';
import { KEY_LENGTH, type KdfParams, argon2idRaw, hkdfSha256 } from './kdf';

// 32 znaka = tacno 5 bita po znaku: 24 slova (bez I i O) + cifre 2-9 (bez 0 i 1), da se kod ne
// pogresno procita. 10 znakova = 50 bita entropije po kodu.
export const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const RECOVERY_CODE_LENGTH = 10;
export const RECOVERY_GROUP_LENGTH = 5;

const INFO_RECOVERY_AUTH = utf8Encode('sleepsafe/v1/recovery-auth');
const INFO_RECOVERY_KEK = utf8Encode('sleepsafe/v1/recovery-kek');

// Jedan kod u kanonskom obliku (10 znakova, bez crtice).
export function generateRecoveryCode(): string {
  // 256 je deljivo sa 32, pa je `bajt & 31` ravnomeran izbor (bez pristrasnosti).
  const bytes = randomBytes(RECOVERY_CODE_LENGTH);
  let code = '';
  for (const byte of bytes) {
    code += RECOVERY_ALPHABET[byte & 31];
  }
  return code;
}

export function generateRecoveryCodes(count: number): string[] {
  if (!Number.isInteger(count) || count < 1 || count > 100) {
    throw new CryptoError('INVALID_INPUT', 'Invalid recovery code count');
  }
  const codes = new Set<string>();
  while (codes.size < count) {
    codes.add(generateRecoveryCode());
  }
  return [...codes];
}

// Prihvata malim slovima, sa crticom, razmacima ili bez njih. Baca za sve ostalo.
export function normalizeRecoveryCode(input: string): string {
  const canonical = input.normalize('NFKC').replace(/[\s-]/g, '').toUpperCase();
  if (canonical.length !== RECOVERY_CODE_LENGTH) {
    throw new CryptoError('INVALID_INPUT', 'Invalid recovery code');
  }
  for (const char of canonical) {
    if (!RECOVERY_ALPHABET.includes(char)) {
      throw new CryptoError('INVALID_INPUT', 'Invalid recovery code');
    }
  }
  return canonical;
}

// "ABCDE-FGHJK" za prikaz.
export function formatRecoveryCode(code: string): string {
  const canonical = normalizeRecoveryCode(code);
  return `${canonical.slice(0, RECOVERY_GROUP_LENGTH)}-${canonical.slice(RECOVERY_GROUP_LENGTH)}`;
}

export interface RecoveryKeys {
  authKey: Bytes; // dokaz da znamo kod (server cuva samo njegov HMAC)
  kek: CryptoKey; // umotava Vault Key
}

// Isti postupak kao za master lozinku (Argon2id pa HKDF), ali sa drugim oznakama, pa se kljucevi
// iz koda nikad ne poklope sa kljucevima iz lozinke.
export async function deriveRecoveryKeys(
  code: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<RecoveryKeys> {
  const canonical = normalizeRecoveryCode(code);
  if (salt.length < 16) {
    throw new CryptoError('INVALID_INPUT', 'Salt too short');
  }
  const master = await argon2idRaw(utf8Encode(canonical), salt, params);
  const noSalt = new Uint8Array(0);
  const authKey = await hkdfSha256(master, noSalt, INFO_RECOVERY_AUTH, KEY_LENGTH);
  const kekBytes = await hkdfSha256(master, noSalt, INFO_RECOVERY_KEK, KEY_LENGTH);
  const kek = await crypto.subtle.importKey('raw', kekBytes, 'AES-GCM', false, [
    'wrapKey',
    'unwrapKey',
  ]);
  master.fill(0);
  kekBytes.fill(0);
  return { authKey, kek };
}

export function recoveryAuthToString(authKey: Uint8Array): string {
  return toBase64Url(authKey);
}
