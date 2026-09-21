import { ApiError } from './api/http';
import { ClientError } from './auth/errors';
import { VaultError } from './vault/store';
import { t } from './strings';

export function describeError(error: unknown): string {
  if (error instanceof ClientError) {
    switch (error.code) {
      case 'INVALID_EMAIL':
        return t.errors.invalidEmail;
      case 'WRONG_PASSWORD':
        return t.errors.wrongPassword;
      case 'WEAK_KDF':
        return t.errors.weakKdf;
      case 'VAULT_CORRUPT':
        return t.errors.vaultCorrupt;
      default:
        return t.errors.generic;
    }
  }
  if (error instanceof VaultError) {
    switch (error.code) {
      case 'CONFLICT':
        return t.errors.itemConflict;
      case 'NOT_FOUND':
        return t.errors.itemNotFound;
      case 'INVALID_ITEM':
        return t.errors.itemInvalid;
      case 'TOO_LARGE':
        return t.errors.itemTooLarge;
      case 'VAULT_FULL':
        return t.errors.vaultFull;
      default:
        return t.errors.generic;
    }
  }
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'INVALID_CREDENTIALS':
        return t.errors.invalidCredentials;
      case 'INVALID_CODE':
        return t.errors.invalidCode;
      case 'TOO_MANY_ATTEMPTS':
        return t.errors.tooManyAttempts;
      case 'RATE_LIMITED':
        return t.errors.rateLimited;
      case 'VALIDATION_ERROR':
        return t.errors.validation;
      case 'NETWORK':
        return t.errors.network;
      default:
        return t.errors.generic;
    }
  }
  return t.errors.generic;
}
