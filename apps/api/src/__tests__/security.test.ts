import { toBase64Url } from '@sleepsafe/crypto';
import { SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { AppError } from '../errors';
import {
  fakeKdfSalt,
  fakeRecoverySalt,
  generateOtp,
  generateRefreshToken,
  generateResetToken,
  hashAuthKey,
  hashOtp,
  hashRecoveryAuth,
  hashRefreshToken,
  hashResetToken,
  signAccessToken,
  verifyAccessToken,
  verifyAuthKey,
  verifyOtp,
  verifyRecoveryAuth,
  verifyResetToken,
} from '../security';

const pepper = 'p'.repeat(32);
const otherPepper = 'q'.repeat(32);
const secret = 's'.repeat(32);
const authKey = toBase64Url(new Uint8Array(32).fill(7));

describe('Auth kljuc', () => {
  it('je deterministican i ne otkriva ulaz', () => {
    const hash = hashAuthKey(authKey, pepper);
    expect(hashAuthKey(authKey, pepper)).toBe(hash);
    expect(hash).toHaveLength(43); // 32 bajta u base64url
    expect(hash).not.toBe(authKey);
    expect(hash).not.toContain(authKey);
  });

  it('razlicit kljuc ili pepper daje razlicit heš', () => {
    const other = toBase64Url(new Uint8Array(32).fill(8));
    expect(hashAuthKey(other, pepper)).not.toBe(hashAuthKey(authKey, pepper));
    expect(hashAuthKey(authKey, otherPepper)).not.toBe(hashAuthKey(authKey, pepper));
  });

  it('verifikacija prihvata tacan, a odbija pogresan kljuc i pogresan pepper', () => {
    const stored = hashAuthKey(authKey, pepper);
    expect(verifyAuthKey(authKey, stored, pepper)).toBe(true);
    expect(verifyAuthKey(toBase64Url(new Uint8Array(32).fill(8)), stored, pepper)).toBe(false);
    expect(verifyAuthKey(authKey, stored, otherPepper)).toBe(false);
  });

  it('kljuc koji nije tacno 32 bajta ili nije base64url se odbija', () => {
    expect(() => hashAuthKey(toBase64Url(new Uint8Array(16)), pepper)).toThrow(AppError);
    expect(() => hashAuthKey('***', pepper)).toThrow();
    expect(verifyAuthKey('***', hashAuthKey(authKey, pepper), pepper)).toBe(false);
    expect(verifyAuthKey(authKey, 'nije-heš', pepper)).toBe(false);
  });
});

describe('OTP kod', () => {
  it('ima tacno 6 cifara, ukljucujuci vodece nule', () => {
    let leadingZeros = 0;
    for (let i = 0; i < 20000; i++) {
      const code = generateOtp();
      expect(code).toMatch(/^\d{6}$/);
      if (code.startsWith('0')) {
        leadingZeros++;
      }
    }
    expect(leadingZeros).toBeGreaterThan(1400);
    expect(leadingZeros).toBeLessThan(2600);
  });

  it('heš zavisi od koda, izazova i pepper-a', () => {
    const hash = hashOtp('123456', 'izazov-1', pepper);
    expect(hashOtp('123456', 'izazov-1', pepper)).toBe(hash);
    expect(hashOtp('123457', 'izazov-1', pepper)).not.toBe(hash);
    expect(hashOtp('123456', 'izazov-2', pepper)).not.toBe(hash);
    expect(hashOtp('123456', 'izazov-1', otherPepper)).not.toBe(hash);
    expect(hash).not.toContain('123456');
  });

  it('verifikacija prihvata samo tacan kod za taj izazov', () => {
    const stored = hashOtp('123456', 'izazov-1', pepper);
    expect(verifyOtp('123456', 'izazov-1', stored, pepper)).toBe(true);
    expect(verifyOtp('654321', 'izazov-1', stored, pepper)).toBe(false);
    expect(verifyOtp('123456', 'izazov-2', stored, pepper)).toBe(false);
  });

  it('odbija kod neispravnog oblika bez racunanja', () => {
    const stored = hashOtp('123456', 'izazov-1', pepper);
    for (const bad of ['', '12345', '1234567', 'abcdef', '12345 ', ' 123456', '١٢٣٤٥٦']) {
      expect(verifyOtp(bad, 'izazov-1', stored, pepper)).toBe(false);
    }
  });
});

describe('Refresh token', () => {
  it('je 256-bitni, jedinstven i razlicit od svog heša', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      seen.add(generateRefreshToken());
    }
    expect(seen.size).toBe(1000);
    const token = generateRefreshToken();
    expect(token).toHaveLength(43);
    const hash = hashRefreshToken(token, pepper);
    expect(hash).not.toBe(token);
    expect(hashRefreshToken(token, pepper)).toBe(hash);
    expect(hashRefreshToken(token, otherPepper)).not.toBe(hash);
  });

  it('heš tokena i heš OTP-a se ne mogu zameniti (razlicita namena)', () => {
    expect(hashRefreshToken('123456', pepper)).not.toBe(hashOtp('123456', '', pepper));
  });
});

describe('Pristupni token (JWT)', () => {
  const claims = { userId: 'korisnik-1', sessionId: 'sesija-1' };

  it('krug: vraca iste podatke', async () => {
    const token = await signAccessToken(claims, secret, 900);
    expect(await verifyAccessToken(token, secret)).toEqual(claims);
  });

  it('istekao token se odbija', async () => {
    const past = new Date(Date.now() - 3600_000);
    const token = await signAccessToken(claims, secret, 60, past);
    await expect(verifyAccessToken(token, secret)).rejects.toMatchObject({
      statusCode: 401,
      code: 'UNAUTHENTICATED',
    });
  });

  it('token je vazeci do isteka, a ne posle', async () => {
    const issued = new Date('2030-01-01T00:00:00Z');
    const token = await signAccessToken(claims, secret, 60, issued);
    expect(await verifyAccessToken(token, secret, new Date('2030-01-01T00:00:30Z'))).toEqual(
      claims,
    );
    await expect(
      verifyAccessToken(token, secret, new Date('2030-01-01T00:01:30Z')),
    ).rejects.toThrow(AppError);
  });

  it('izmenjen token i pogresna tajna se odbijaju', async () => {
    const token = await signAccessToken(claims, secret, 900);
    const tampered = `${token.slice(0, -2)}${token.endsWith('AA') ? 'BB' : 'AA'}`;
    await expect(verifyAccessToken(tampered, secret)).rejects.toThrow(AppError);
    await expect(verifyAccessToken(token, 'x'.repeat(32))).rejects.toThrow(AppError);
    await expect(verifyAccessToken('nije.token.uopste', secret)).rejects.toThrow(AppError);
    await expect(verifyAccessToken('', secret)).rejects.toThrow(AppError);
  });

  it('token bez potpisa (alg: none) se odbija', async () => {
    const header = toBase64Url(new TextEncoder().encode('{"alg":"none","typ":"JWT"}'));
    const body = toBase64Url(
      new TextEncoder().encode(
        JSON.stringify({
          sub: 'korisnik-1',
          sid: 'sesija-1',
          iss: 'sleepsafe',
          aud: 'sleepsafe-api',
          exp: Math.floor(Date.now() / 1000) + 600,
        }),
      ),
    );
    await expect(verifyAccessToken(`${header}.${body}.`, secret)).rejects.toThrow(AppError);
  });

  it('token potpisan drugim algoritmom istom tajnom se odbija (HS256 je zakucan)', async () => {
    const hs512 = await new SignJWT({ sid: 'sesija-1' })
      .setProtectedHeader({ alg: 'HS512' })
      .setSubject('korisnik-1')
      .setIssuer('sleepsafe')
      .setAudience('sleepsafe-api')
      .setExpirationTime('10m')
      .sign(new TextEncoder().encode(secret));
    await expect(verifyAccessToken(hs512, secret)).rejects.toThrow(AppError);
  });

  it('token sa pogresnim izdavaocem ili publikom se odbija', async () => {
    const key = new TextEncoder().encode(secret);
    const wrongIssuer = await new SignJWT({ sid: 's' })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('u')
      .setIssuer('neko-drugi')
      .setAudience('sleepsafe-api')
      .setExpirationTime('10m')
      .sign(key);
    const wrongAudience = await new SignJWT({ sid: 's' })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('u')
      .setIssuer('sleepsafe')
      .setAudience('druga-usluga')
      .setExpirationTime('10m')
      .sign(key);
    await expect(verifyAccessToken(wrongIssuer, secret)).rejects.toThrow(AppError);
    await expect(verifyAccessToken(wrongAudience, secret)).rejects.toThrow(AppError);
  });

  it('token bez podataka o sesiji se odbija', async () => {
    const key = new TextEncoder().encode(secret);
    const noSession = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('u')
      .setIssuer('sleepsafe')
      .setAudience('sleepsafe-api')
      .setExpirationTime('10m')
      .sign(key);
    await expect(verifyAccessToken(noSession, secret)).rejects.toThrow(AppError);
  });
});

describe('Lazna so za nepostojece naloge', () => {
  it('je stalna za isti email, a razlicita za razlicite', () => {
    const salt = fakeKdfSalt('niko@example.com', pepper);
    expect(fakeKdfSalt('niko@example.com', pepper)).toBe(salt);
    expect(fakeKdfSalt('neko@example.com', pepper)).not.toBe(salt);
    expect(fakeKdfSalt('niko@example.com', otherPepper)).not.toBe(salt);
  });

  it('izgleda isto kao prava so (16 bajtova u base64url)', () => {
    expect(fakeKdfSalt('niko@example.com', pepper)).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });
});

describe('Kodovi za oporavak (server)', () => {
  it('hes dokaza je stalan, zavisi od tajne servera i ima 43 znaka', () => {
    const hash = hashRecoveryAuth(authKey, pepper);
    expect(hash).toBe(hashRecoveryAuth(authKey, pepper));
    expect(hash).not.toBe(hashRecoveryAuth(authKey, otherPepper));
    expect(hash).toHaveLength(43);
    expect(verifyRecoveryAuth(authKey, hash, pepper)).toBe(true);
    expect(verifyRecoveryAuth(authKey, hash, otherPepper)).toBe(false);
    expect(verifyRecoveryAuth(toBase64Url(new Uint8Array(32).fill(8)), hash, pepper)).toBe(false);
  });

  it('razdvajanje domena: isti ulaz daje razlicit hes za lozinku i za kod za oporavak', () => {
    expect(hashRecoveryAuth(authKey, pepper)).not.toBe(hashAuthKey(authKey, pepper));
  });

  it('odbija dokaz pogresne duzine i neispravan hes bez izuzetka pri proveri', () => {
    expect(() => hashRecoveryAuth('kratak', pepper)).toThrow();
    expect(verifyRecoveryAuth('kratak', hashRecoveryAuth(authKey, pepper), pepper)).toBe(false);
    expect(verifyRecoveryAuth(authKey, '!!!', pepper)).toBe(false);
  });

  it('token za promenu lozinke: nasumican, 43 znaka, vezan za svoj id i tajnu servera', () => {
    const token = generateResetToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(generateResetToken()).not.toBe(token);

    const id = '3f2b8c1e-7a44-4d0b-9a55-1c2d3e4f5a6b';
    const otherId = '4f2b8c1e-7a44-4d0b-9a55-1c2d3e4f5a6b';
    const hash = hashResetToken(token, id, pepper);
    expect(verifyResetToken(token, id, hash, pepper)).toBe(true);
    expect(verifyResetToken(token, otherId, hash, pepper)).toBe(false);
    expect(verifyResetToken(token, id, hash, otherPepper)).toBe(false);
    expect(verifyResetToken(generateResetToken(), id, hash, pepper)).toBe(false);
    expect(verifyResetToken(token, id, '!!!', pepper)).toBe(false);
  });

  it('lazna so za oporavak je stalna po adresi, razlicita po adresi i tajni i drugacija od lazne soli za prijavu', () => {
    const salt = fakeRecoverySalt('a@example.com', pepper);
    expect(salt).toBe(fakeRecoverySalt('a@example.com', pepper));
    expect(salt).not.toBe(fakeRecoverySalt('b@example.com', pepper));
    expect(salt).not.toBe(fakeRecoverySalt('a@example.com', otherPepper));
    expect(salt).not.toBe(fakeKdfSalt('a@example.com', pepper));
    expect(salt).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });
});
