import {
  type KdfParams,
  createVault,
  deriveKeys,
  generateSalt,
  toBase64Url,
} from '@sleepsafe/crypto';
import type {
  ChallengeResponse,
  ItemEnvelope,
  ListItemsResponse,
  LoginRequest,
  MeResponse,
  PreloginResponse,
  PutItemRequest,
  PutItemResponse,
  RegisterRequest,
  SyncItem,
  VerifyCodeRequest,
} from '@sleepsafe/shared';
import type { AuthApi } from '../api/auth';
import { ApiError, type RefreshResult } from '../api/http';
import type { VaultApi } from '../api/vault';

export const TEST_KDF: KdfParams = { memoryKiB: 19456, iterations: 2, parallelism: 1 };
export const CODE = '123456';

interface StoredUser {
  id: string;
  request: RegisterRequest;
  verified: boolean;
}

interface StoredItem {
  revision: number;
  envelope: ItemEnvelope | null;
  updatedAt: string;
}

interface StoredVault {
  revision: number;
  items: Map<string, StoredItem>;
}

// Ponasa se kao pravi server (routes/vault.ts): isti kursori, tombstone zapisi, 409/404/422.
export class FakeServer implements AuthApi, VaultApi {
  readonly users = new Map<string, StoredUser>();
  readonly calls: { name: string; args: unknown }[] = [];
  private readonly challenges = new Map<string, { email: string; purpose: 'verify' | 'login' }>();
  private sessionEmail: string | null = null;
  private token = false;
  private readonly vaults = new Map<string, StoredVault>();
  private listGate: Promise<void> | null = null;
  down = false;
  // Nazivi poziva koji trenutno padaju (na primer 'vault.list'), dok ostali rade.
  readonly failing = new Set<string>();
  preloginOverride: Partial<PreloginResponse> | null = null;
  failLogout = false;
  itemLimit = 10_000;

  private record(name: string, args: unknown): void {
    this.calls.push({ name, args });
    if (this.down || this.failing.has(name)) {
      throw new ApiError(0, 'NETWORK', 'Network error');
    }
  }

  callsTo(name: string) {
    return this.calls.filter((call) => call.name === name);
  }

  async seedUser(email: string, password: string, params: KdfParams = TEST_KDF) {
    const salt = generateSalt();
    const { authKey, kek } = await deriveKeys(password, salt, params);
    const { vaultKey, wrappedVaultKey } = await createVault(kek);
    const id = crypto.randomUUID();
    this.users.set(email, {
      id,
      verified: true,
      request: {
        email,
        authKey: toBase64Url(authKey),
        kdfSalt: toBase64Url(salt),
        kdfMemoryKiB: params.memoryKiB,
        kdfIterations: params.iterations,
        kdfParallelism: params.parallelism,
        wrappedVaultKey: wrappedVaultKey as RegisterRequest['wrappedVaultKey'],
      },
    });
    return { id, vaultKey };
  }

  startSession(email: string): void {
    this.sessionEmail = email;
  }

  async changePasswordElsewhere(email: string, newPassword: string) {
    const user = this.users.get(email);
    if (!user) throw new Error('unknown user');
    const salt = generateSalt();
    const { authKey, kek } = await deriveKeys(newPassword, salt, TEST_KDF);
    const { wrappedVaultKey } = await createVault(kek);
    user.request = {
      ...user.request,
      authKey: toBase64Url(authKey),
      kdfSalt: toBase64Url(salt),
      wrappedVaultKey: wrappedVaultKey as RegisterRequest['wrappedVaultKey'],
    };
  }

  async prelogin(email: string): Promise<PreloginResponse> {
    this.record('prelogin', { email });
    const user = this.users.get(email);
    const base: PreloginResponse =
      user?.verified === true
        ? {
            kdfSalt: user.request.kdfSalt,
            kdfMemoryKiB: user.request.kdfMemoryKiB,
            kdfIterations: user.request.kdfIterations,
            kdfParallelism: user.request.kdfParallelism,
          }
        : {
            kdfSalt: 'A'.repeat(22),
            kdfMemoryKiB: TEST_KDF.memoryKiB,
            kdfIterations: TEST_KDF.iterations,
            kdfParallelism: TEST_KDF.parallelism,
          };
    return { ...base, ...this.preloginOverride };
  }

  async register(body: RegisterRequest): Promise<ChallengeResponse> {
    this.record('register', body);
    const existing = this.users.get(body.email);
    if (existing?.verified) {
      return { challengeId: crypto.randomUUID() };
    }
    this.users.set(body.email, {
      id: existing?.id ?? crypto.randomUUID(),
      request: body,
      verified: false,
    });
    return { challengeId: this.newChallenge(body.email, 'verify') };
  }

  async verifyEmail(body: VerifyCodeRequest): Promise<void> {
    this.record('verifyEmail', body);
    const challenge = this.takeChallenge(body, 'verify');
    const user = this.users.get(challenge.email);
    if (user) user.verified = true;
  }

  async login(body: LoginRequest): Promise<ChallengeResponse> {
    this.record('login', body);
    const user = this.users.get(body.email);
    if (!user?.verified || user.request.authKey !== body.authKey) {
      throw new ApiError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');
    }
    return { challengeId: this.newChallenge(body.email, 'login') };
  }

  async verifyOtp(body: VerifyCodeRequest): Promise<void> {
    this.record('verifyOtp', body);
    const challenge = this.takeChallenge(body, 'login');
    this.sessionEmail = challenge.email;
    this.token = true;
  }

  async refresh(): Promise<RefreshResult> {
    this.calls.push({ name: 'refresh', args: null });
    if (this.down) return 'unavailable';
    if (this.sessionEmail === null) return 'rejected';
    this.token = true;
    return 'ok';
  }

  async logout(): Promise<void> {
    this.calls.push({ name: 'logout', args: null });
    if (this.failLogout) throw new ApiError(0, 'NETWORK', 'Network error');
    this.sessionEmail = null;
    this.token = false;
  }

  async me(): Promise<MeResponse> {
    this.record('me', null);
    const user = this.sessionEmail === null ? undefined : this.users.get(this.sessionEmail);
    if (!this.token || !user) {
      throw new ApiError(401, 'UNAUTHENTICATED', 'Invalid or expired token');
    }
    const { request } = user;
    return {
      id: user.id,
      email: request.email,
      kdfSalt: request.kdfSalt,
      kdfMemoryKiB: request.kdfMemoryKiB,
      kdfIterations: request.kdfIterations,
      kdfParallelism: request.kdfParallelism,
      wrappedVaultKey: request.wrappedVaultKey,
    };
  }

  // Zadrzi odgovore na list() dok se ne pozove vracena funkcija (zahtev je vec obradjen).
  holdList(): () => void {
    let release!: () => void;
    this.listGate = new Promise<void>((resolve) => (release = resolve));
    return () => {
      this.listGate = null;
      release();
    };
  }

  private currentUserId(): string {
    const user = this.sessionEmail === null ? undefined : this.users.get(this.sessionEmail);
    if (!this.token || !user) {
      throw new ApiError(401, 'UNAUTHENTICATED', 'Invalid or expired token');
    }
    return user.id;
  }

  private vaultOf(userId: string): StoredVault {
    let vault = this.vaults.get(userId);
    if (!vault) {
      vault = { revision: 0, items: new Map() };
      this.vaults.set(userId, vault);
    }
    return vault;
  }

  // Upis "sa drugog uredjaja": zaobilazi sesiju ovog klijenta, a pravila su ista kao na serveru.
  putAsOtherDevice(userId: string, id: string, body: PutItemRequest): PutItemResponse {
    const vault = this.vaultOf(userId);
    const existing = vault.items.get(id);
    if (body.baseRevision === null) {
      if (existing) throw new ApiError(409, 'CONFLICT', 'Item was modified elsewhere');
      const active = [...vault.items.values()].filter((item) => item.envelope !== null).length;
      if (active >= this.itemLimit) throw new ApiError(422, 'VAULT_FULL', 'Item limit reached');
    } else {
      if (!existing) throw new ApiError(404, 'NOT_FOUND', 'Not found');
      if (existing.envelope === null || existing.revision !== body.baseRevision) {
        throw new ApiError(409, 'CONFLICT', 'Item was modified elsewhere');
      }
    }
    vault.revision += 1;
    vault.items.set(id, {
      revision: vault.revision,
      envelope: body.envelope,
      updatedAt: new Date().toISOString(),
    });
    return { id, revision: vault.revision };
  }

  removeAsOtherDevice(userId: string, id: string): void {
    const vault = this.vaultOf(userId);
    const existing = vault.items.get(id);
    if (!existing || existing.envelope === null) return;
    vault.revision += 1;
    vault.items.set(id, {
      revision: vault.revision,
      envelope: null,
      updatedAt: new Date().toISOString(),
    });
  }

  async list(since: number, limit: number): Promise<ListItemsResponse> {
    this.record('vault.list', { since, limit });
    const userId = this.currentUserId();
    const rows = [...this.vaultOf(userId).items.entries()]
      .filter(([, item]) => item.revision > since && (since !== 0 || item.envelope !== null))
      .sort(([, a], [, b]) => a.revision - b.revision)
      .slice(0, limit + 1);
    const page = rows.slice(0, limit);
    const items: SyncItem[] = page.map(([id, item]) => ({
      id,
      revision: item.revision,
      deleted: item.envelope === null,
      envelope: item.envelope,
      updatedAt: item.updatedAt,
    }));
    const response = {
      items,
      cursor: page.at(-1)?.[1].revision ?? since,
      hasMore: rows.length > limit,
    };
    if (this.listGate) await this.listGate;
    return response;
  }

  async put(id: string, body: PutItemRequest): Promise<PutItemResponse> {
    this.record('vault.put', { id, body });
    return this.putAsOtherDevice(this.currentUserId(), id, body);
  }

  async remove(id: string): Promise<void> {
    this.record('vault.remove', { id });
    this.removeAsOtherDevice(this.currentUserId(), id);
  }

  private newChallenge(email: string, purpose: 'verify' | 'login'): string {
    for (const [id, challenge] of this.challenges) {
      if (challenge.email === email && challenge.purpose === purpose) this.challenges.delete(id);
    }
    const id = crypto.randomUUID();
    this.challenges.set(id, { email, purpose });
    return id;
  }

  private takeChallenge(body: VerifyCodeRequest, purpose: 'verify' | 'login') {
    const challenge = this.challenges.get(body.challengeId);
    if (!challenge || challenge.purpose !== purpose || body.code !== CODE) {
      throw new ApiError(400, 'INVALID_CODE', 'Invalid or expired code');
    }
    this.challenges.delete(body.challengeId);
    return challenge;
  }
}
