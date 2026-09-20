import {
  CryptoError,
  DEFAULT_KDF_PARAMS,
  type KdfParams,
  assertAcceptableKdfParams,
  createVault,
  fromBase64Url,
  generateSalt,
  toBase64Url,
  unwrapVaultKey,
} from '@sleepsafe/crypto';
import {
  type MeResponse,
  type RegisterRequest,
  emailSchema,
  wrappedKeyEnvelopeSchema,
} from '@sleepsafe/shared';
import type { AuthApi } from '../api/auth';
import type { KeyDeriver } from '../crypto/deriver';
import { ClientError, type ClientErrorCode } from './errors';

export type Notice = 'emailVerified' | 'sessionExpired' | 'serverUnavailable';

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
  | { status: 'unlocked'; user: SessionUser; vaultKey: CryptoKey };

export interface AuthStoreDeps {
  api: AuthApi;
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

  constructor(private readonly deps: AuthStoreDeps) {}

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  getState = (): AuthState => this.state;

  private setState(next: AuthState): void {
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
    this.setState({
      status: 'unlocked',
      user: { id: profile.id, email: profile.email },
      vaultKey,
    });
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
    this.setState({
      status: 'unlocked',
      user: { id: profile.id, email: profile.email },
      vaultKey,
    });
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
