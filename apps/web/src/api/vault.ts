import {
  type ListItemsResponse,
  type PutItemRequest,
  type PutItemResponse,
  listItemsResponseSchema,
  putItemResponseSchema,
} from '@sleepsafe/shared';
import type { HttpClient } from './http';

export interface VaultApi {
  list(since: number, limit: number): Promise<ListItemsResponse>;
  put(id: string, body: PutItemRequest): Promise<PutItemResponse>;
  remove(id: string): Promise<void>;
}

export function createVaultApi(http: HttpClient): VaultApi {
  return {
    list: (since, limit) =>
      http.request('GET', `/vault/items?since=${since}&limit=${limit}`, {
        schema: listItemsResponseSchema,
      }),
    put: (id, body) =>
      http.request('PUT', `/vault/items/${id}`, { body, schema: putItemResponseSchema }),
    remove: (id) => http.request('DELETE', `/vault/items/${id}`),
  };
}
