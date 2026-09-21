import { z } from 'zod';

export const emailSchema = z.string().trim().toLowerCase().pipe(z.email().max(254));

export const authKeySchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

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

export type PreloginResponse = z.infer<typeof preloginResponseSchema>;
export type RegisterRequest = z.infer<typeof registerRequestSchema>;
export type VerifyCodeRequest = z.infer<typeof verifyCodeRequestSchema>;
export type ChallengeResponse = z.infer<typeof challengeResponseSchema>;

export type LoginRequest = z.infer<typeof loginRequestSchema>;
export type AccessTokenResponse = z.infer<typeof accessTokenResponseSchema>;
export type MeResponse = z.infer<typeof meResponseSchema>;
