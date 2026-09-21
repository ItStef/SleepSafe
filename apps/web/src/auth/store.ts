import {
  CryptoError,
  DEFAULT_KDF_PARAMS,
  type Envelope,
  type KdfParams,
  assertAcceptableKdfParams,
  createVault,
  formatRecoveryCode,
  fromBase64Url,
  generateSalt,
  normalizeRecoveryCode,
  rewrapVaultKey,
  toBase64Url,
  unwrapVaultKey,
} from '@sleepsafe/crypto';
import {
  type MeResponse,
  RECOVERY_CODE_COUNT,
  type RecoveryStatus,
  type RecoveryVerifyResponse,
  type RegisterRequest,
  emailSchema,
  wrappedKeyEnvelopeSchema,
} from '@sleepsafe/shared';
import type { AuthApi } from '../api/auth';
import type { VaultApi } from '../api/vault';
import type { KeyDeriver } from '../crypto/deriver';
import { VaultStore } from '../vault/store';
import { ApiError } from '../api/http';
import { ClientError, type ClientErrorCode } from './errors';
import { buildRecoveryBundle } from './recovery';

export type Notice = 'emailVerified' | 'sessionExpired' | 'serverUnavailable' | 'passwordReset';

export interface SessionUser {
  id: string;
  email: string;
}

export type AuthState =
  | { status: 'booting' }
  | { status: 'signedOut'; notice?: Notice }
  | { status: 'recoveryCodes'; email: string; codes: readonly string[] }
  | { status: 'verifyingEmail'; email: string }
  | { status: 'recoveryOtp'; email: string }
  | { status: 'recoveryCode'; email: string }
  | { status: 'recoveryPassword'; email: string }
  | { status: 'loginCode'; email: string }
  | { status: 'locked'; email: string }
  | { status: 'unlocked'; user: SessionUser; vaultKey: CryptoKey; vault: VaultStore };

export interface AuthStoreDeps {
  api: AuthApi;
  vaultApi: VaultApi;
  deriver: KeyDeriver;
  kdfParams?: KdfParams;
  // Koliko kodova za oporavak se pravi pri registraciji (server trazi tacno RECOVERY_CODE_COUNT).
  recoveryCodeCount?: number;
}

interface RecoverySession {
  email: string;
  challengeId: string;
  salt: Uint8Array;
  params: KdfParams;
  reset?: Pick<RecoveryVerifyResponse, 'resetId' | 'resetToken' | 'codes'>;
  opened?: { codeId: string; recoveryAuth: string; envelope: Envelope; kek: CryptoKey };
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
  private pendingCodes: readonly string[] | null = null;
  private recovery: RecoverySession | null = null;

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
    this.pendingCodes = null;
    this.recovery = null;
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
    // Izvoziv Vault Key postoji samo u ovoj funkciji: sluzi da se umota za svaki kod za oporavak.
    const exportable = await unwrapVaultKey(wrappedVaultKey, kek, { extractable: true });
    const { bundle, codes } = await buildRecoveryBundle({
      deriver: this.deps.deriver,
      vaultKey: exportable,
      count: this.deps.recoveryCodeCount ?? RECOVERY_CODE_COUNT,
      params,
    });
    const request: RegisterRequest = {
      email,
      authKey: toBase64Url(authKey),
      kdfSalt: toBase64Url(salt),
      kdfMemoryKiB: params.memoryKiB,
      kdfIterations: params.iterations,
      kdfParallelism: params.parallelism,
      wrappedVaultKey: wrappedKeyEnvelopeSchema.parse(wrappedVaultKey),
      recovery: bundle,
    };
    authKey.fill(0);

    const { challengeId } = await this.deps.api.register(request);
    this.pendingRegistration = request;
    this.challengeId = challengeId;
    const shown = codes.map(formatRecoveryCode);
    this.pendingCodes = shown;
    this.setState({ status: 'recoveryCodes', email, codes: shown });
  }

  // Korisnik potvrdjuje da je sacuvao kodove: od tog trenutka se brisu iz memorije.
  acknowledgeRecoveryCodes(): void {
    this.require('recoveryCodes');
    const email = this.state.status === 'recoveryCodes' ? this.state.email : '';
    this.pendingCodes = null;
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
    const status = this.state.status;
    if (
      status === 'verifyingEmail' ||
      status === 'loginCode' ||
      status === 'recoveryCodes' ||
      status === 'recoveryOtp' ||
      status === 'recoveryCode' ||
      status === 'recoveryPassword'
    ) {
      this.clearSecrets();
      this.setState({ status: 'signedOut' });
    }
  }

  // --- Oporavak master lozinke pomocu koda za oporavak ------------------------------------------

  async startRecovery(rawEmail: string): Promise<void> {
    const email = normalizeEmail(rawEmail);
    const started = await this.deps.api.recoveryStart(email);
    const params = assertSafeParams({
      memoryKiB: started.kdfMemoryKiB,
      iterations: started.kdfIterations,
      parallelism: started.kdfParallelism,
    });
    this.recovery = {
      email,
      challengeId: started.challengeId,
      salt: fromBase64Url(started.kdfSalt),
      params,
    };
    this.setState({ status: 'recoveryOtp', email });
  }

  async resendRecoveryOtp(): Promise<void> {
    this.require('recoveryOtp');
    const recovery = this.recovery;
    if (recovery === null) {
      throw new ClientError('BAD_STATE');
    }
    const started = await this.deps.api.recoveryStart(recovery.email);
    recovery.challengeId = started.challengeId;
  }

  async submitRecoveryOtp(code: string): Promise<void> {
    this.require('recoveryOtp');
    const recovery = this.recovery;
    if (recovery === null) {
      throw new ClientError('BAD_STATE');
    }
    const { resetId, resetToken, codes } = await this.deps.api.recoveryVerify({
      challengeId: recovery.challengeId,
      code: code.trim(),
    });
    recovery.reset = { resetId, resetToken, codes };
    this.setState({ status: 'recoveryCode', email: recovery.email });
  }

  // Kod se proverava na klijentu: pravi kod otvara tacno jedan od omotanih kljuceva. Pogresan unos
  // ne trosi nista na serveru, pa se moze ponavljati dok token ne istekne.
  async submitRecoveryCode(input: string): Promise<void> {
    this.require('recoveryCode');
    const recovery = this.recovery;
    if (recovery?.reset === undefined) {
      throw new ClientError('BAD_STATE');
    }
    let code: string;
    try {
      code = normalizeRecoveryCode(input);
    } catch {
      throw new ClientError('INVALID_RECOVERY_CODE');
    }
    const keys = await this.deps.deriver.deriveRecovery(code, recovery.salt, recovery.params);
    for (const candidate of recovery.reset.codes) {
      try {
        await unwrapVaultKey(candidate.wrappedVaultKey, keys.kek);
      } catch (error) {
        if (error instanceof CryptoError) {
          continue;
        }
        throw error;
      }
      recovery.opened = {
        codeId: candidate.id,
        recoveryAuth: toBase64Url(keys.authKey),
        envelope: candidate.wrappedVaultKey,
        kek: keys.kek,
      };
      keys.authKey.fill(0);
      this.setState({ status: 'recoveryPassword', email: recovery.email });
      return;
    }
    keys.authKey.fill(0);
    throw new ClientError('WRONG_RECOVERY_CODE');
  }

  async resetWithRecovery(newPassword: string): Promise<void> {
    this.require('recoveryPassword');
    const recovery = this.recovery;
    if (recovery?.reset === undefined || recovery.opened === undefined) {
      throw new ClientError('BAD_STATE');
    }
    const { reset, opened } = recovery;
    const params = this.deps.kdfParams ?? DEFAULT_KDF_PARAMS;
    const salt = generateSalt();
    const next = await this.deps.deriver.derive(newPassword, salt, params);

    // Isti Vault Key, umotan novom lozinkom. Pre slanja se proverava da se stvarno otvara.
    let wrapped: Envelope;
    try {
      wrapped = await rewrapVaultKey(opened.envelope, opened.kek, next.kek);
      await unwrapVaultKey(wrapped, next.kek);
    } catch (error) {
      if (error instanceof CryptoError) {
        throw new ClientError('VAULT_CORRUPT');
      }
      throw error;
    }
    await this.deps.api.recoveryReset({
      resetId: reset.resetId,
      resetToken: reset.resetToken,
      codeId: opened.codeId,
      recoveryAuth: opened.recoveryAuth,
      newAuthKey: toBase64Url(next.authKey),
      kdfSalt: toBase64Url(salt),
      kdfMemoryKiB: params.memoryKiB,
      kdfIterations: params.iterations,
      kdfParallelism: params.parallelism,
      wrappedVaultKey: wrappedKeyEnvelopeSchema.parse(wrapped),
    });
    next.authKey.fill(0);
    this.clearSecrets();
    this.setState({ status: 'signedOut', notice: 'passwordReset' });
  }

  // --- Kodovi za oporavak prijavljenog korisnika -----------------------------------------------

  recoveryStatus(): Promise<RecoveryStatus> {
    this.require('unlocked');
    return this.deps.api.recoveryStatus();
  }

  // Novi skup kodova (svi stari prestaju da vaze). Trazi master lozinku: proverava se lokalno, pa
  // pogresna lozinka ne stize do servera.
  async regenerateRecoveryCodes(password: string): Promise<string[]> {
    this.require('unlocked');
    const profile = this.profile ?? (await this.deps.api.me());
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
    let exportable: CryptoKey;
    try {
      exportable = await unwrapVaultKey(profile.wrappedVaultKey, kek, { extractable: true });
    } catch (error) {
      authKey.fill(0);
      if (error instanceof CryptoError) {
        throw new ClientError('WRONG_PASSWORD');
      }
      throw error;
    }
    const { bundle, codes } = await buildRecoveryBundle({
      deriver: this.deps.deriver,
      vaultKey: exportable,
      count: this.deps.recoveryCodeCount ?? RECOVERY_CODE_COUNT,
      params,
    });
    try {
      await this.deps.api.replaceRecoveryCodes({
        currentAuthKey: toBase64Url(authKey),
        recovery: bundle,
      });
    } catch (error) {
      if (error instanceof ApiError && error.code === 'INVALID_PASSWORD') {
        throw new ClientError('WRONG_PASSWORD');
      }
      throw error;
    } finally {
      authKey.fill(0);
    }
    return codes.map(formatRecoveryCode);
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
