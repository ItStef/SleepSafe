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

export const preloginRequestSchema = z.strictObject({ email: emailSchema });
export const preloginResponseSchema = kdfParamsSchema;

export const registerRequestSchema = z.strictObject({
  email: emailSchema,
  authKey: authKeySchema,
  ...kdfParamsSchema.shape,
  wrappedVaultKey: wrappedKeyEnvelopeSchema,
});

export const verifyCodeRequestSchema = z.strictObject({
  challengeId: challengeIdSchema,
  code: otpCodeSchema,
});

export const challengeResponseSchema = z.strictObject({ challengeId: challengeIdSchema });

export type PreloginRequest = z.infer<typeof preloginRequestSchema>;
export type PreloginResponse = z.infer<typeof preloginResponseSchema>;
export type RegisterRequest = z.infer<typeof registerRequestSchema>;
export type VerifyCodeRequest = z.infer<typeof verifyCodeRequestSchema>;
export type ChallengeResponse = z.infer<typeof challengeResponseSchema>;
