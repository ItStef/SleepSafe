import { type ItemData, itemDataSchema } from '@sleepsafe/shared';
import { ApiError } from '../api/http';
import { VaultError, type VaultStore } from './store';

export const EXPORT_FORMAT = 'sleepsafe-export';
export const EXPORT_VERSION = 1;
export const MAX_IMPORT_BYTES = 5 * 1024 * 1024;
export const MAX_IMPORT_ITEMS = 10_000;

export type ImportErrorCode =
  'INVALID_FILE' | 'UNKNOWN_FORMAT' | 'EMPTY' | 'TOO_LARGE' | 'TOO_MANY';

export class ImportError extends Error {
  constructor(readonly code: ImportErrorCode) {
    super(code);
    this.name = 'ImportError';
  }
}

export interface ParsedImport {
  format: 'json' | 'csv';
  items: ItemData[];
  skipped: number;
}

type Exportable = readonly { readonly data: ItemData }[];

export function exportJson(entries: Exportable, now: Date = new Date()): string {
  return JSON.stringify(
    {
      format: EXPORT_FORMAT,
      version: EXPORT_VERSION,
      exportedAt: now.toISOString(),
      items: entries.map((entry) => entry.data),
    },
    null,
    2,
  );
}

const BOM = String.fromCharCode(0xfeff);

const CSV_HEADER = ['title', 'username', 'password', 'url', 'notes'] as const;

function csvCell(value: string): string {
  return /[",\r\n]|^\s|\s$/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}

export function exportCsv(entries: Exportable): string {
  const rows = entries.map(({ data }) => CSV_HEADER.map((column) => csvCell(data[column])));
  return [CSV_HEADER.join(','), ...rows.map((row) => row.join(','))].join('\r\n') + '\r\n';
}

function detectDelimiter(text: string): string {
  const counts: Record<string, number> = { ',': 0, ';': 0, '\t': 0 };
  let quoted = false;
  for (const char of text) {
    if (char === '"') {
      quoted = !quoted;
    } else if (!quoted && (char === '\n' || char === '\r')) {
      break;
    } else if (!quoted && char in counts) {
      counts[char] = (counts[char] ?? 0) + 1;
    }
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? ',';
}

export function parseCsv(input: string): string[][] {
  const text = input.startsWith(BOM) ? input.slice(1) : input;
  const delimiter = detectDelimiter(text);
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const char = text[i] as string;
    if (quoted) {
      if (char === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        field += char;
      }
    } else if (char === '"' && field === '') {
      quoted = true;
    } else if (char === delimiter) {
      row.push(field);
      field = '';
    } else if (char === '\n' || char === '\r') {
      if (char === '\r' && text[i + 1] === '\n') {
        i++;
      }
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += char;
    }
  }
  if (quoted) {
    throw new ImportError('INVALID_FILE');
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

const ALIASES: Record<keyof ItemData, readonly string[]> = {
  title: ['title', 'name', 'naslov', 'account', 'account name', 'item name'],
  username: ['username', 'user name', 'login_username', 'login name', 'user', 'korisničko ime'],
  password: ['password', 'login_password', 'lozinka', 'pass'],
  url: ['url', 'login_uri', 'uri', 'website', 'web site', 'web address', 'adresa'],
  notes: ['notes', 'note', 'extra', 'comments', 'comment', 'beleške', 'napomena'],
};
const FIELDS = ['title', 'username', 'password', 'url', 'notes'] as const;

function mapColumns(header: readonly string[]): Partial<Record<keyof ItemData, number>> {
  const names = header.map((cell) => cell.trim().toLowerCase());
  const mapped: Partial<Record<keyof ItemData, number>> = {};
  const used = new Set<number>();
  for (const field of FIELDS) {
    const index = names.findIndex(
      (name, position) => !used.has(position) && ALIASES[field].includes(name),
    );
    if (index !== -1) {
      mapped[field] = index;
      used.add(index);
    }
  }
  return mapped;
}

function hostOf(url: string): string {
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`).hostname;
  } catch {
    return '';
  }
}

function parseCsvItems(text: string): ParsedImport {
  const rows = parseCsv(text);
  const header = rows[0];
  if (header === undefined) {
    throw new ImportError('EMPTY');
  }
  const columns = mapColumns(header);
  if (columns.password === undefined && columns.title === undefined) {
    throw new ImportError('UNKNOWN_FORMAT');
  }

  const items: ItemData[] = [];
  let skipped = 0;
  for (const row of rows.slice(1)) {
    const cell = (field: keyof ItemData) => {
      const index = columns[field];
      return index === undefined ? '' : (row[index] ?? '');
    };
    if (row.every((value) => value.trim() === '')) {
      continue;
    }
    const url = cell('url').trim();
    const username = cell('username').trim();
    const title = cell('title').trim() || hostOf(url) || username || 'Bez naslova';
    const parsed = itemDataSchema.safeParse({
      title,
      username,
      password: cell('password'),
      url,
      notes: cell('notes'),
    });
    if (parsed.success) {
      items.push(parsed.data);
    } else {
      skipped++;
    }
  }
  return { format: 'csv', items, skipped };
}

function parseJsonItems(text: string): ParsedImport {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    throw new ImportError('INVALID_FILE');
  }
  let list: unknown;
  if (Array.isArray(data)) {
    list = data;
  } else if (typeof data === 'object' && data !== null && 'items' in data) {
    const wrapper = data as { format?: unknown; version?: unknown; items: unknown };
    if (wrapper.format !== EXPORT_FORMAT || wrapper.version !== EXPORT_VERSION) {
      throw new ImportError('UNKNOWN_FORMAT');
    }
    list = wrapper.items;
  } else {
    throw new ImportError('UNKNOWN_FORMAT');
  }
  if (!Array.isArray(list)) {
    throw new ImportError('UNKNOWN_FORMAT');
  }

  const items: ItemData[] = [];
  let skipped = 0;
  for (const entry of list as unknown[]) {
    const parsed = itemDataSchema.safeParse(entry);
    if (parsed.success) {
      items.push(parsed.data);
    } else {
      skipped++;
    }
  }
  return { format: 'json', items, skipped };
}

export function parseImport(text: string, filename: string): ParsedImport {
  if (text.length > MAX_IMPORT_BYTES) {
    throw new ImportError('TOO_LARGE');
  }
  const trimmed = (text.startsWith(BOM) ? text.slice(1) : text).trimStart();
  const isJson =
    filename.toLowerCase().endsWith('.json') || trimmed.startsWith('{') || trimmed.startsWith('[');
  const parsed = isJson ? parseJsonItems(trimmed) : parseCsvItems(text);
  if (parsed.items.length > MAX_IMPORT_ITEMS) {
    throw new ImportError('TOO_MANY');
  }
  if (parsed.items.length === 0) {
    throw new ImportError('EMPTY');
  }
  return parsed;
}

export function itemKey(item: ItemData): string {
  return JSON.stringify([
    item.title.trim().toLowerCase(),
    item.username.trim().toLowerCase(),
    item.url.trim().toLowerCase(),
    item.password,
  ]);
}

export function withoutDuplicates(
  items: readonly ItemData[],
  existing: readonly { readonly data: ItemData }[],
): { items: ItemData[]; duplicates: number } {
  const seen = new Set(existing.map((entry) => itemKey(entry.data)));
  const unique: ItemData[] = [];
  for (const item of items) {
    const key = itemKey(item);
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(item);
    }
  }
  return { items: unique, duplicates: items.length - unique.length };
}

export interface ImportOutcome {
  created: number;
  failed: number;
  stopped: 'FULL' | 'NETWORK' | 'LOCKED' | null;
}

export async function importItems(
  vault: VaultStore,
  items: readonly ItemData[],
  onProgress?: (done: number, total: number) => void,
): Promise<ImportOutcome> {
  let created = 0;
  let failed = 0;
  let stopped: ImportOutcome['stopped'] = null;
  for (const item of items) {
    try {
      await vault.create(item);
      created++;
    } catch (error) {
      if (error instanceof VaultError && error.code === 'VAULT_FULL') {
        stopped = 'FULL';
        break;
      }
      if (error instanceof VaultError && error.code === 'DISPOSED') {
        stopped = 'LOCKED';
        break;
      }
      if (error instanceof ApiError && (error.code === 'NETWORK' || error.status === 401)) {
        stopped = 'NETWORK';
        break;
      }
      failed++;
    }
    onProgress?.(created + failed, items.length);
  }
  return { created, failed, stopped };
}
