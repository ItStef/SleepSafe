export type ClientErrorCode =
  | 'INVALID_EMAIL'
  | 'WRONG_PASSWORD'
  | 'WEAK_KDF'
  | 'VAULT_CORRUPT'
  | 'BAD_STATE'
  | 'INVALID_RECOVERY_CODE'
  | 'WRONG_RECOVERY_CODE';

export class ClientError extends Error {
  constructor(readonly code: ClientErrorCode) {
    super(code);
    this.name = 'ClientError';
  }
}
