import { z } from 'zod';
import { authKeySchema, kdfParamsSchema, wrappedKeyEnvelopeSchema } from './auth';

export const changePasswordRequestSchema = z.strictObject({
  currentAuthKey: authKeySchema,
  newAuthKey: authKeySchema,
  ...kdfParamsSchema.shape,
  wrappedVaultKey: wrappedKeyEnvelopeSchema,
});

export const deleteAccountRequestSchema = z.strictObject({ authKey: authKeySchema });

export const sessionInfoSchema = z.strictObject({
  id: z.uuid(),
  userAgent: z.string().nullable(),
  createdAt: z.iso.datetime(),
  lastUsedAt: z.iso.datetime(),
  current: z.boolean(),
});

export const listSessionsResponseSchema = z.strictObject({
  sessions: z.array(sessionInfoSchema),
});

export type ChangePasswordRequest = z.infer<typeof changePasswordRequestSchema>;
export type DeleteAccountRequest = z.infer<typeof deleteAccountRequestSchema>;
export type SessionInfo = z.infer<typeof sessionInfoSchema>;
export type ListSessionsResponse = z.infer<typeof listSessionsResponseSchema>;
