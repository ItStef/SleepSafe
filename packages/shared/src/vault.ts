import { z } from 'zod';

export const itemIdSchema = z.uuid();

export const MAX_ITEM_CIPHERTEXT_CHARS = 100_000;

export const itemEnvelopeSchema = z.strictObject({
  v: z.literal(1),
  iv: z.string().regex(/^[A-Za-z0-9_-]{16}$/),
  ct: z
    .string()
    .min(22)
    .max(MAX_ITEM_CIPHERTEXT_CHARS)
    .regex(/^[A-Za-z0-9_-]+$/),
});

export const putItemRequestSchema = z.strictObject({
  envelope: itemEnvelopeSchema,
  baseRevision: z.number().int().min(1).nullable(),
});

export const putItemResponseSchema = z.strictObject({
  id: itemIdSchema,
  revision: z.number().int().min(1),
});

export const syncItemSchema = z.strictObject({
  id: itemIdSchema,
  revision: z.number().int().min(1),
  deleted: z.boolean(),
  envelope: itemEnvelopeSchema.nullable(),
  updatedAt: z.iso.datetime(),
});

export const listItemsQuerySchema = z.strictObject({
  since: z.coerce.number().int().min(0).default(0),
  limit: z.coerce.number().int().min(1).max(500).default(200),
});

export const listItemsResponseSchema = z.strictObject({
  items: z.array(syncItemSchema),
  cursor: z.number().int().min(0),
  hasMore: z.boolean(),
});

export type ItemEnvelope = z.infer<typeof itemEnvelopeSchema>;
export type PutItemRequest = z.infer<typeof putItemRequestSchema>;
export type PutItemResponse = z.infer<typeof putItemResponseSchema>;
export type SyncItem = z.infer<typeof syncItemSchema>;
export type ListItemsQuery = z.infer<typeof listItemsQuerySchema>;
export type ListItemsResponse = z.infer<typeof listItemsResponseSchema>;
