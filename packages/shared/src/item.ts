import { z } from 'zod';

// Sadrzaj stavke pre sifrovanja. Server ga nikad ne vidi (dobija samo omotac iz vault.ts).
// Granice drze najveci moguci sifrat ispod MAX_ITEM_CIPHERTEXT_CHARS u svim realnim slucajevima.
export const ITEM_LIMITS = {
  title: 200,
  username: 500,
  password: 1000,
  url: 2048,
  notes: 10_000,
} as const;

export const itemDataSchema = z.strictObject({
  title: z.string().trim().min(1).max(ITEM_LIMITS.title),
  username: z.string().max(ITEM_LIMITS.username),
  password: z.string().max(ITEM_LIMITS.password),
  url: z.string().max(ITEM_LIMITS.url),
  notes: z.string().max(ITEM_LIMITS.notes),
});

export type ItemData = z.infer<typeof itemDataSchema>;

export function emptyItemData(): ItemData {
  return { title: '', username: '', password: '', url: '', notes: '' };
}
