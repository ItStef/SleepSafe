import {
  CryptoError,
  DEFAULT_KDF_PARAMS,
  type Envelope,
  type KdfParams,
  assertAcceptableKdfParams,
  createVault,
  fromBase64Url,
  generateSalt,
  rewrapVaultKey,
  toBase64Url,
  unwrapVaultKey,
} from '@sleepsafe/crypto';
import {
  type ListSessionsResponse,
  type MeResponse,
  type RegisterRequest,
  emailSchema,
  wrappedKeyEnvelopeSchema,
} from '@sleepsafe/shared';
import type { AuthApi } from '../api/auth';
import { ApiError } from '../api/http';
import type { VaultApi } from '../api/vault';
import type { KeyDeriver } from '../crypto/deriver';
import { VaultStore } from '../vault/store';
import { ClientError, type ClientErrorCode } from './errors';
import { strongerKdfParams } from './policy';

export type Notice = 'emailVerified' | 'sessionExpired' | 'serverUnavailable' | 'accountDeleted';

export interface SessionUser {
  id: string;
  email: string;
}

export type AuthState =
  | { status: 'booting' }
  | { status: 'signedOut'; notice?: Notice }
  | { status: 'verifyingEmail'; email: string }
  | { status: 'loginCode'; email: string }
  | { status: 'locked'; email: string }
  | { status: 'unlocked'; user: SessionUser; vaultKey: CryptoKey; vault: VaultStore };

export interface AuthStoreDeps {
  api: AuthApi;
  vaultApi: VaultApi;
  deriver: KeyDeriver;
  kdfParams?: KdfParams;
}

interface PendingLogin {
  email: string;
  authKey: string;
  kek: CryptoKey;
}

export class AuthStore {
  private state: AuthState = { status: 'booting' };
  private readonly listeners = new Set<() => void>();
  private profile: MeResponse | null = null;
  private challengeId: string | null = null;
  private pendingRegistration: RegisterRequest | null = null;
  private pendingLogin: PendingLogin | null = null;
  private vault: VaultStore | null = null;

  constructor(private readonly deps: AuthStoreDeps) {}

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getState = (): AuthState => this.state;

  private setState(next: AuthState): void {
    // Dekriptovane stavke postoje samo dok je vault otkljucan, ma kojim putem se to stanje napusti.
    if (next.status !== 'unlocked') {
      this.closeVault();
    }
    this.state = next;
    for (const listener of this.listeners) {
      listener();
    }
  }

  private clearSecrets(): void {
    this.profile = null;
    this.challengeId = null;
    this.pendingRegistration = null;
    this.pendingLogin = null;
  }

  private closeVault(): void {
    this.vault?.dispose();
    this.vault = null;
  }

  private open(profile: MeResponse, vaultKey: CryptoKey): void {
    const vault = new VaultStore({
      api: this.deps.vaultApi,
      vaultKey,
      userId: profile.id,
    });
    this.vault = vault;
    this.setState({
      status: 'unlocked',
      user: { id: profile.id, email: profile.email },
      vaultKey,
      vault,
    });
  }

  private require(status: AuthState['status']): void {
    if (this.state.status !== status) {
      throw new ClientError('BAD_STATE');
    }
  }

  async boot(): Promise<void> {
    const result = await this.deps.api.refresh();
    if (result === 'unavailable') {
      this.setState({ status: 'signedOut', notice: 'serverUnavailable' });
      return;
    }
    if (result === 'rejected') {
      this.setState({ status: 'signedOut' });
      return;
    }
    try {
      this.profile = await this.deps.api.me();
      this.setState({ status: 'locked', email: this.profile.email });
    } catch {
      this.clearSecrets();
      this.setState({ status: 'signedOut' });
    }
  }

  async register(rawEmail: string, password: string): Promise<void> {
    const email = normalizeEmail(rawEmail);
    const params = this.deps.kdfParams ?? DEFAULT_KDF_PARAMS;
    const salt = generateSalt();
    const { authKey, kek } = await this.deps.deriver.derive(password, salt, params);
    const { wrappedVaultKey } = await createVault(kek);
    const request: RegisterRequest = {
      email,
      authKey: toBase64Url(authKey),
      kdfSalt: toBase64Url(salt),
      kdfMemoryKiB: params.memoryKiB,
      kdfIterations: params.iterations,
      kdfParallelism: params.parallelism,
      wrappedVaultKey: wrappedKeyEnvelopeSchema.parse(wrappedVaultKey),
    };
    authKey.fill(0);

    const { challengeId } = await this.deps.api.register(request);
    this.pendingRegistration = request;
    this.challengeId = challengeId;
    this.setState({ status: 'verifyingEmail', email });
  }

  async verifyEmail(code: string): Promise<void> {
    this.require('verifyingEmail');
    if (this.challengeId === null) {
      throw new ClientError('BAD_STATE');
    }
    await this.deps.api.verifyEmail({ challengeId: this.challengeId, code: code.trim() });
    this.clearSecrets();
    this.setState({ status: 'signedOut', notice: 'emailVerified' });
  }

  async resendVerification(): Promise<void> {
    this.require('verifyingEmail');
    if (this.pendingRegistration === null) {
      throw new ClientError('BAD_STATE');
    }
    const { challengeId } = await this.deps.api.register(this.pendingRegistration);
    this.challengeId = challengeId;
  }

  async login(rawEmail: string, password: string): Promise<void> {
    const email = normalizeEmail(rawEmail);
    const kdf = await this.deps.api.prelogin(email);
    const params = assertSafeParams({
      memoryKiB: kdf.kdfMemoryKiB,
      iterations: kdf.kdfIterations,
      parallelism: kdf.kdfParallelism,
    });
    const { authKey, kek } = await this.deps.deriver.derive(
      password,
      fromBase64Url(kdf.kdfSalt),
      params,
    );
    const authKeyText = toBase64Url(authKey);
    authKey.fill(0);

    const { challengeId } = await this.deps.api.login({ email, authKey: authKeyText });
    this.pendingLogin = { email, authKey: authKeyText, kek };
    this.challengeId = challengeId;
    this.setState({ status: 'loginCode', email });
  }

  async verifyLoginCode(code: string): Promise<void> {
    this.require('loginCode');
    const pending = this.pendingLogin;
    if (pending === null || this.challengeId === null) {
      throw new ClientError('BAD_STATE');
    }
    await this.deps.api.verifyOtp({ challengeId: this.challengeId, code: code.trim() });
    const profile = await this.deps.api.me();
    const vaultKey = await openVault(profile, pending.kek, 'VAULT_CORRUPT');
    this.profile = profile;
    this.pendingLogin = null;
    this.challengeId = null;
    this.open(profile, vaultKey);
  }

  async resendLoginCode(): Promise<void> {
    this.require('loginCode');
    if (this.pendingLogin === null) {
      throw new ClientError('BAD_STATE');
    }
    const { challengeId } = await this.deps.api.login({
      email: this.pendingLogin.email,
      authKey: this.pendingLogin.authKey,
    });
    this.challengeId = challengeId;
  }

  cancelPending(): void {
    if (this.state.status === 'verifyingEmail' || this.state.status === 'loginCode') {
      this.clearSecrets();
      this.setState({ status: 'signedOut' });
    }
  }

  async unlock(password: string): Promise<void> {
    this.require('locked');
    const profile = await this.deps.api.me();
    this.profile = profile;
    const params = assertSafeParams({
      memoryKiB: profile.kdfMemoryKiB,
      iterations: profile.kdfIterations,
      parallelism: profile.kdfParallelism,
    });
    const { authKey, kek } = await this.deps.deriver.derive(
      password,
      fromBase64Url(profile.kdfSalt),
      params,
    );
    authKey.fill(0);
    const vaultKey = await openVault(profile, kek, 'WRONG_PASSWORD');
    this.open(profile, vaultKey);
  }
  // --- Nalog: sesije, promena master lozinke, brisanje naloga ---------------------------------

  listSessions(): Promise<ListSessionsResponse> {
    this.require('unlocked');
    return this.deps.api.listSessions();
  }

  revokeSession(id: string): Promise<void> {
    this.require('unlocked');
    return this.deps.api.revokeSession(id);
  }

  revokeOtherSessions(): Promise<void> {
    this.require('unlocked');
    return this.deps.api.revokeOtherSessions();
  }

  // Master lozinka se proverava lokalno (otvara se Vault Key), pa pogresna lozinka ne stize do
  // servera i ne trosi pokusaje. Profil se uzima svez, jer je lozinka mozda promenjena drugde.
  private async openWithPassword(password: string) {
    this.require('unlocked');
    const profile = await this.deps.api.me();
    const params = assertSafeParams({
      memoryKiB: profile.kdfMemoryKiB,
      iterations: profile.kdfIterations,
      parallelism: profile.kdfParallelism,
    });
    const { authKey, kek } = await this.deps.deriver.derive(
      password,
      fromBase64Url(profile.kdfSalt),
      params,
    );
    try {
      await unwrapVaultKey(profile.wrappedVaultKey, kek);
    } catch (error) {
      authKey.fill(0);
      if (error instanceof CryptoError) {
        throw new ClientError('WRONG_PASSWORD');
      }
      throw error;
    }
    return { profile, params, authKey, kek };
  }

  async confirmPassword(password: string): Promise<void> {
    const { authKey } = await this.openWithPassword(password);
    authKey.fill(0);
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    const { profile, params, authKey, kek } = await this.openWithPassword(currentPassword);
    const nextParams = strongerKdfParams(params, this.deps.kdfParams ?? DEFAULT_KDF_PARAMS);
    const salt = generateSalt();
    const next = await this.deps.deriver.derive(newPassword, salt, nextParams);

    let wrapped: Envelope;
    try {
      wrapped = await rewrapVaultKey(profile.wrappedVaultKey, kek, next.kek);
      await unwrapVaultKey(wrapped, next.kek);
    } catch (error) {
      authKey.fill(0);
      next.authKey.fill(0);
      if (error instanceof CryptoError) {
        throw new ClientError('VAULT_CORRUPT');
      }
      throw error;
    }
    try {
      await this.deps.api.changePassword({
        currentAuthKey: toBase64Url(authKey),
        newAuthKey: toBase64Url(next.authKey),
        kdfSalt: toBase64Url(salt),
        kdfMemoryKiB: nextParams.memoryKiB,
        kdfIterations: nextParams.iterations,
        kdfParallelism: nextParams.parallelism,
        wrappedVaultKey: wrappedKeyEnvelopeSchema.parse(wrapped),
      });
    } catch (error) {
      if (error instanceof ApiError && error.code === 'INVALID_PASSWORD') {
        throw new ClientError('WRONG_PASSWORD');
      }
      throw error;
    } finally {
      authKey.fill(0);
      next.authKey.fill(0);
    }
  }

  async deleteAccount(password: string): Promise<void> {
    const { authKey } = await this.openWithPassword(password);
    try {
      await this.deps.api.deleteAccount({ authKey: toBase64Url(authKey) });
    } catch (error) {
      if (error instanceof ApiError && error.code === 'INVALID_PASSWORD') {
        throw new ClientError('WRONG_PASSWORD');
      }
      throw error;
    } finally {
      authKey.fill(0);
    }
    try {
      await this.deps.api.logout();
    } catch {
      // Sesija je vec obrisana na serveru: lokalno se svejedno sve brise.
    }
    this.clearSecrets();
    this.setState({ status: 'signedOut', notice: 'accountDeleted' });
  }

  lock(): void {
    if (this.state.status === 'unlocked') {
      this.setState({ status: 'locked', email: this.state.user.email });
    }
  }

  async logout(): Promise<void> {
    try {
      await this.deps.api.logout();
    } catch {
      // Server nije dostupan: lokalno se svejedno sve brise.
    }
    this.clearSecrets();
    this.setState({ status: 'signedOut' });
  }

  sessionExpired(): void {
    const hadSession = this.state.status === 'locked' || this.state.status === 'unlocked';
    this.clearSecrets();
    this.setState(
      hadSession ? { status: 'signedOut', notice: 'sessionExpired' } : { status: 'signedOut' },
    );
  }
}

function normalizeEmail(raw: string): string {
  const parsed = emailSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ClientError('INVALID_EMAIL');
  }
  return parsed.data;
}

function assertSafeParams(params: KdfParams): KdfParams {
  try {
    assertAcceptableKdfParams(params);
  } catch {
    throw new ClientError('WEAK_KDF');
  }
  return params;
}

async function openVault(
  profile: MeResponse,
  kek: CryptoKey,
  onFailure: ClientErrorCode,
): Promise<CryptoKey> {
  try {
    return await unwrapVaultKey(profile.wrappedVaultKey, kek);
  } catch (error) {
    if (error instanceof CryptoError) {
      throw new ClientError(onFailure);
    }
    throw error;
  }
}
