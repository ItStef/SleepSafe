import { z } from 'zod';
import {
  RECOVERY_CODE_COUNT,
  authKeySchema,
  challengeIdSchema,
  emailSchema,
  kdfParamsSchema,
  recoveryBundleSchema,
  verifyCodeRequestSchema,
  wrappedKeyEnvelopeSchema,
} from './auth';

const resetTokenSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

// 1. Zahtev za oporavak: server salje kod na email (za nepostojeci nalog odgovor je isti).
export const recoveryStartRequestSchema = z.strictObject({ email: emailSchema });
export const recoveryStartResponseSchema = z.strictObject({
  challengeId: challengeIdSchema,
  ...kdfParamsSchema.shape,
});

// 2. Kod iz emaila: server vraca omotane Vault Key-eve preostalih kodova i jednokratni token.
export const recoveryVerifyRequestSchema = verifyCodeRequestSchema;
export const recoveryVerifyResponseSchema = z.strictObject({
  resetId: z.uuid(),
  resetToken: resetTokenSchema,
  codes: z
    .array(z.strictObject({ id: z.uuid(), wrappedVaultKey: wrappedKeyEnvelopeSchema }))
    .min(1)
    .max(RECOVERY_CODE_COUNT),
});

// 3. Nova master lozinka: dokaz da klijent zna kod (recoveryAuth) + novi kljucevi.
export const recoveryResetRequestSchema = z.strictObject({
  resetId: z.uuid(),
  resetToken: resetTokenSchema,
  codeId: z.uuid(),
  recoveryAuth: authKeySchema,
  newAuthKey: authKeySchema,
  ...kdfParamsSchema.shape,
  wrappedVaultKey: wrappedKeyEnvelopeSchema,
});

// Prijavljen korisnik: koliko kodova je ostalo i pravljenje novog skupa (trazi master lozinku).
export const recoveryStatusSchema = z.strictObject({
  total: z.number().int().min(0),
  remaining: z.number().int().min(0),
  createdAt: z.iso.datetime().nullable(),
});
export const replaceRecoveryCodesRequestSchema = z.strictObject({
  currentAuthKey: authKeySchema,
  recovery: recoveryBundleSchema,
});

export type RecoveryStartRequest = z.infer<typeof recoveryStartRequestSchema>;
export type RecoveryStartResponse = z.infer<typeof recoveryStartResponseSchema>;
export type RecoveryVerifyRequest = z.infer<typeof recoveryVerifyRequestSchema>;
export type RecoveryVerifyResponse = z.infer<typeof recoveryVerifyResponseSchema>;
export type RecoveryResetRequest = z.infer<typeof recoveryResetRequestSchema>;
export type RecoveryStatus = z.infer<typeof recoveryStatusSchema>;
export type ReplaceRecoveryCodesRequest = z.infer<typeof replaceRecoveryCodesRequestSchema>;
