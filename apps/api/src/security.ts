import { createHmac, randomInt } from 'node:crypto';
import { constantTimeEqual, fromBase64Url, randomBytes, toBase64Url } from '@sleepsafe/crypto';
import { SignJWT, jwtVerify } from 'jose';
import { AppError } from './errors';

const AUTH_KEY_BYTES = 32;
const SALT_BYTES = 16;
const ISSUER = 'sleepsafe';
const AUDIENCE = 'sleepsafe-api';

function mac(pepper: string, label: string, ...values: string[]): Buffer {
  return createHmac('sha256', pepper)
    .update(JSON.stringify([`sleepsafe/v1/${label}`, ...values]))
    .digest();
}

// --- Auth kljuc -----------------------------------------------------------------------------

export function hashAuthKey(authKey: string, pepper: string): string {
  if (fromBase64Url(authKey).length !== AUTH_KEY_BYTES) {
    throw new AppError(400, 'VALIDATION_ERROR', 'Invalid request');
  }
  return toBase64Url(mac(pepper, 'auth-key', authKey));
}

export function verifyAuthKey(authKey: string, storedHash: string, pepper: string): boolean {
  try {
    return constantTimeEqual(
      fromBase64Url(hashAuthKey(authKey, pepper)),
      fromBase64Url(storedHash),
    );
  } catch {
    return false;
  }
}

// --- OTP kod (email) -------------------------------------------------------------------------

export function generateOtp(): string {
  return String(randomInt(0, 1_000_000)).padStart(6, '0');
}

export function hashOtp(code: string, challengeId: string, pepper: string): string {
  return toBase64Url(mac(pepper, 'otp', challengeId, code));
}

export function verifyOtp(
  code: string,
  challengeId: string,
  storedHash: string,
  pepper: string,
): boolean {
  if (!/^\d{6}$/.test(code)) {
    return false;
  }
  try {
    return constantTimeEqual(
      fromBase64Url(hashOtp(code, challengeId, pepper)),
      fromBase64Url(storedHash),
    );
  } catch {
    return false;
  }
}

// --- Refresh token ---------------------------------------------------------------------------

export function generateRefreshToken(): string {
  return toBase64Url(randomBytes(32));
}

export function hashRefreshToken(token: string, pepper: string): string {
  return toBase64Url(mac(pepper, 'refresh-token', token));
}

// --- Pristupni token (JWT) -------------------------------------------------------------------

export interface AccessClaims {
  userId: string;
  sessionId: string;
}

function jwtKey(secret: string): Uint8Array {
  return new TextEncoder().encode(secret);
}

export async function signAccessToken(
  claims: AccessClaims,
  secret: string,
  ttlSeconds: number,
  now: Date = new Date(),
): Promise<string> {
  const issuedAt = Math.floor(now.getTime() / 1000);
  return new SignJWT({ sid: claims.sessionId })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(claims.userId)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + ttlSeconds)
    .sign(jwtKey(secret));
}

export async function verifyAccessToken(
  token: string,
  secret: string,
  now: Date = new Date(),
): Promise<AccessClaims> {
  try {
    const { payload } = await jwtVerify(token, jwtKey(secret), {
      algorithms: ['HS256'],
      issuer: ISSUER,
      audience: AUDIENCE,
      currentDate: now,
    });
    if (typeof payload.sub !== 'string' || typeof payload['sid'] !== 'string') {
      throw new Error('missing claims');
    }
    return { userId: payload.sub, sessionId: payload['sid'] };
  } catch {
    throw new AppError(401, 'UNAUTHENTICATED', 'Invalid or expired token');
  }
}

export function fakeKdfSalt(email: string, pepper: string): string {
  return toBase64Url(mac(pepper, 'fake-salt', email).subarray(0, SALT_BYTES));
}
