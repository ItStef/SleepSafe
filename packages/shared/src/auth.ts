import { z } from 'zod';

export const emailSchema = z.string().trim().toLowerCase().pipe(z.email().max(254));

// Auth kljuc: 32 bajta u base64url = tacno 43 znaka (bez punjenja).
export const authKeySchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

// So za KDF: 16 do 48 bajtova u base64url.
export const kdfSaltSchema = z.string().regex(/^[A-Za-z0-9_-]{22,64}$/);

export const otpCodeSchema = z.string().regex(/^\d{6}$/);

export const challengeIdSchema = z.uuid();

export const wrappedKeyEnvelopeSchema = z.strictObject({
  v: z.literal(1),
  iv: z.string().regex(/^[A-Za-z0-9_-]{16}$/),
  ct: z.string().regex(/^[A-Za-z0-9_-]{64}$/),
});

export const kdfParamsSchema = z.strictObject({
  kdfSalt: kdfSaltSchema,
  kdfMemoryKiB: z.number().int().min(1).max(4_194_304),
  kdfIterations: z.number().int().min(1).max(100),
  kdfParallelism: z.number().int().min(1).max(64),
});

// Kodovi za oporavak: svaki kod (samo klijent ga zna) daje svoj Auth kljuc za dokaz posedovanja i
// svoj KEK kojim je umotan isti Vault Key. Server nikad ne vidi kod, samo ove izvedene vrednosti.
export const RECOVERY_CODE_COUNT = 20;

export const recoveryBundleSchema = z.strictObject({
  ...kdfParamsSchema.shape,
  codes: z
    .array(z.strictObject({ authKey: authKeySchema, wrappedVaultKey: wrappedKeyEnvelopeSchema }))
    .length(RECOVERY_CODE_COUNT)
    .refine((codes) => new Set(codes.map((code) => code.authKey)).size === codes.length, {
      message: 'Recovery codes must be distinct',
    }),
});

export const preloginRequestSchema = z.strictObject({ email: emailSchema });
export const preloginResponseSchema = kdfParamsSchema;

export const registerRequestSchema = z.strictObject({
  email: emailSchema,
  authKey: authKeySchema,
  ...kdfParamsSchema.shape,
  wrappedVaultKey: wrappedKeyEnvelopeSchema,
  recovery: recoveryBundleSchema,
});

export const verifyCodeRequestSchema = z.strictObject({
  challengeId: challengeIdSchema,
  code: otpCodeSchema,
});

export const challengeResponseSchema = z.strictObject({ challengeId: challengeIdSchema });

export const loginRequestSchema = z.strictObject({ email: emailSchema, authKey: authKeySchema });

export const accessTokenResponseSchema = z.strictObject({
  accessToken: z.string().regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/),
  expiresIn: z.number().int().positive(),
});

export const meResponseSchema = z.strictObject({
  id: z.uuid(),
  email: emailSchema,
  ...kdfParamsSchema.shape,
  wrappedVaultKey: wrappedKeyEnvelopeSchema,
});

export type RecoveryBundle = z.infer<typeof recoveryBundleSchema>;
export type PreloginRequest = z.infer<typeof preloginRequestSchema>;
export type PreloginResponse = z.infer<typeof preloginResponseSchema>;
export type RegisterRequest = z.infer<typeof registerRequestSchema>;
export type VerifyCodeRequest = z.infer<typeof verifyCodeRequestSchema>;
export type ChallengeResponse = z.infer<typeof challengeResponseSchema>;

export type LoginRequest = z.infer<typeof loginRequestSchema>;
export type AccessTokenResponse = z.infer<typeof accessTokenResponseSchema>;
export type MeResponse = z.infer<typeof meResponseSchema>;
