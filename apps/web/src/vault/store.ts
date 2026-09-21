import { CryptoError, decryptItem, encryptItem } from '@sleepsafe/crypto';
import {
  type ItemData,
  type PutItemRequest,
  type SyncItem,
  itemDataSchema,
  itemEnvelopeSchema,
} from '@sleepsafe/shared';
import { ApiError } from '../api/http';
import type { VaultApi } from '../api/vault';

export type VaultErrorCode =
  'NOT_FOUND' | 'CONFLICT' | 'INVALID_ITEM' | 'TOO_LARGE' | 'VAULT_FULL' | 'DISPOSED';

export class VaultError extends Error {
  constructor(readonly code: VaultErrorCode) {
    super(code);
    this.name = 'VaultError';
  }
}

export interface VaultEntry {
  readonly id: string;
  readonly revision: number;
  readonly updatedAt: string;
  readonly data: ItemData;
}

export type VaultStatus = 'idle' | 'loading' | 'ready' | 'error' | 'disposed';

export interface VaultState {
  readonly status: VaultStatus;
  // Sortirano po naslovu. Menja se samo kad se stvarno nesto promeni.
  readonly entries: readonly VaultEntry[];
  // Stavke koje su stigle sa servera, ali se ne mogu otvoriti (ostecene ili pogresan kljuc).
  readonly unreadable: number;
  readonly syncing: boolean;
  // Greska poslednje sinhronizacije. Posle prvog ucitavanja stavke ostaju vidljive.
  readonly error: unknown;
}

export interface VaultStoreDeps {
  api: VaultApi;
  vaultKey: CryptoKey;
  userId: string;
  pageSize?: number;
  clock?: () => Date;
}

const DEFAULT_PAGE_SIZE = 200;
const collator = new Intl.Collator('sr-Latn', { sensitivity: 'base', numeric: true });

function byTitle(a: VaultEntry, b: VaultEntry): number {
  return collator.compare(a.data.title, b.data.title) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

export class VaultStore {
  private state: VaultState = {
    status: 'idle',
    entries: [],
    unreadable: 0,
    syncing: false,
    error: null,
  };
  private readonly listeners = new Set<() => void>();
  private readonly entries = new Map<string, VaultEntry>();
  private readonly unreadableIds = new Set<string>();
  private vaultKey: CryptoKey | null;
  private cursor = 0;
  private inflight: Promise<void> | null = null;
  private readonly pageSize: number;
  private readonly clock: () => Date;

  constructor(private readonly deps: VaultStoreDeps) {
    this.vaultKey = deps.vaultKey;
    this.pageSize = deps.pageSize ?? DEFAULT_PAGE_SIZE;
    this.clock = deps.clock ?? (() => new Date());
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getState = (): VaultState => this.state;

  get(id: string): VaultEntry | undefined {
    return this.entries.get(id);
  }

  // Prvo ucitavanje i svako sledece osvezavanje su isto: povuci sve posle poslednjeg kursora.
  // Nikad ne odbija: ishod je u stanju (status i error).
  sync(): Promise<void> {
    if (this.isDisposed()) {
      return Promise.resolve();
    }
    this.inflight ??= this.runSync().finally(() => {
      this.inflight = null;
    });
    return this.inflight;
  }

  async create(input: ItemData): Promise<string> {
    const data = this.validate(input);
    const id = crypto.randomUUID();
    const envelope = await this.seal(id, data);
    const { revision } = await this.write(id, { envelope, baseRevision: null });
    this.remember({ id, revision, updatedAt: this.clock().toISOString(), data });
    return id;
  }

  async update(id: string, input: ItemData): Promise<void> {
    this.assertOpen();
    const current = this.entries.get(id);
    if (!current) {
      throw new VaultError('NOT_FOUND');
    }
    const data = this.validate(input);
    const envelope = await this.seal(id, data);
    const { revision } = await this.write(id, { envelope, baseRevision: current.revision });
    this.remember({ id, revision, updatedAt: this.clock().toISOString(), data });
  }

  async remove(id: string): Promise<void> {
    this.assertOpen();
    await this.deps.api.remove(id);
    if (this.isDisposed()) {
      return;
    }
    this.entries.delete(id);
    this.unreadableIds.delete(id);
    this.publish();
  }

  // Brise sve iz memorije i zaboravlja kljuc. Posle ovoga se store vise ne koristi.
  dispose(): void {
    if (this.isDisposed()) {
      return;
    }
    this.vaultKey = null;
    this.entries.clear();
    this.unreadableIds.clear();
    this.state = { status: 'disposed', entries: [], unreadable: 0, syncing: false, error: null };
    this.notify();
  }

  private async runSync(): Promise<void> {
    const firstLoad = this.state.status !== 'ready';
    this.setState({ status: firstLoad ? 'loading' : 'ready', syncing: true });
    try {
      await this.pull();
    } catch (error) {
      if (!this.isDisposed()) {
        this.setState({ status: firstLoad ? 'error' : 'ready', syncing: false, error });
      }
      return;
    }
    if (!this.isDisposed()) {
      this.setState({ status: 'ready', syncing: false, error: null });
    }
  }

  private async pull(): Promise<void> {
    for (;;) {
      const page = await this.deps.api.list(this.cursor, this.pageSize);
      if (this.isDisposed()) {
        return;
      }
      if (page.hasMore && page.cursor <= this.cursor) {
        // Server tvrdi da ima jos, a kursor ne napreduje: bez ovoga bi petlja bila beskonacna.
        throw new ApiError(200, 'BAD_RESPONSE', 'Cursor did not advance');
      }
      for (const item of page.items) {
        await this.apply(item);
        if (this.isDisposed()) {
          return;
        }
      }
      this.cursor = page.cursor;
      this.publish();
      if (!page.hasMore) {
        return;
      }
    }
  }

  private async apply(item: SyncItem): Promise<void> {
    const current = this.entries.get(item.id);
    if (current && current.revision >= item.revision) {
      return; // Vec imamo isto ili novije (na primer nas sopstveni upis).
    }
    if (item.deleted || item.envelope === null) {
      this.entries.delete(item.id);
      this.unreadableIds.delete(item.id);
      return;
    }
    const key = this.vaultKey;
    if (key === null) {
      return;
    }
    let plain: unknown;
    try {
      plain = await decryptItem(key, item.envelope, {
        userId: this.deps.userId,
        itemId: item.id,
      });
    } catch (error) {
      if (!(error instanceof CryptoError)) {
        throw error;
      }
      this.markUnreadable(item.id);
      return;
    }
    const parsed = itemDataSchema.safeParse(plain);
    if (!parsed.success) {
      this.markUnreadable(item.id);
      return;
    }
    this.unreadableIds.delete(item.id);
    this.entries.set(item.id, {
      id: item.id,
      revision: item.revision,
      updatedAt: item.updatedAt,
      data: parsed.data,
    });
  }

  private markUnreadable(id: string): void {
    this.entries.delete(id);
    this.unreadableIds.add(id);
  }

  private validate(input: ItemData): ItemData {
    const parsed = itemDataSchema.safeParse(input);
    if (!parsed.success) {
      throw new VaultError('INVALID_ITEM');
    }
    return parsed.data;
  }

  // Metoda, a ne poredjenje polja: TypeScript inace "pamti" stanje posle prve provere, iako
  // se ono moze promeniti dok se ceka odgovor servera.
  private isDisposed(): boolean {
    return this.state.status === 'disposed';
  }

  private assertOpen(): void {
    if (this.isDisposed()) {
      throw new VaultError('DISPOSED');
    }
  }

  private async seal(id: string, data: ItemData) {
    this.assertOpen();
    const key = this.vaultKey;
    if (key === null) {
      throw new VaultError('DISPOSED');
    }
    const sealed = await encryptItem(key, data, { userId: this.deps.userId, itemId: id });
    // Zakljucavanje moze da stigne dok traje sifrovanje: tada se nista ne salje.
    this.assertOpen();
    const envelope = itemEnvelopeSchema.safeParse(sealed);
    if (!envelope.success) {
      // Omotac ne prolazi semu samo kad sifrat prelazi granicu koju server prihvata.
      throw new VaultError('TOO_LARGE');
    }
    return envelope.data;
  }

  private async write(id: string, body: PutItemRequest): Promise<{ revision: number }> {
    try {
      return await this.deps.api.put(id, body);
    } catch (error) {
      if (!(error instanceof ApiError)) {
        throw error;
      }
      if (error.status === 409 || error.status === 404) {
        await this.resync();
        throw new VaultError(error.status === 409 ? 'CONFLICT' : 'NOT_FOUND');
      }
      if (error.code === 'VAULT_FULL') {
        throw new VaultError('VAULT_FULL');
      }
      throw error;
    }
  }

  // Posle konflikta treba stanje koje je sigurno novije od zahteva: sacekaj tekucu
  // sinhronizaciju (mozda je krenula pre izmene na drugom uredjaju) pa pokreni novu.
  private async resync(): Promise<void> {
    if (this.inflight) {
      await this.inflight;
    }
    await this.sync();
  }

  private remember(entry: VaultEntry): void {
    if (this.isDisposed()) {
      return;
    }
    const current = this.entries.get(entry.id);
    if (current && current.revision >= entry.revision) {
      return;
    }
    this.unreadableIds.delete(entry.id);
    this.entries.set(entry.id, entry);
    this.publish();
  }

  private publish(): void {
    this.state = {
      ...this.state,
      entries: [...this.entries.values()].sort(byTitle),
      unreadable: this.unreadableIds.size,
    };
    this.notify();
  }

  private setState(patch: Partial<Pick<VaultState, 'status' | 'syncing' | 'error'>>): void {
    this.state = { ...this.state, ...patch };
    this.notify();
  }

  private notify(): void {
    for (const listener of this.listeners) {
      listener();
    }
  }
}
