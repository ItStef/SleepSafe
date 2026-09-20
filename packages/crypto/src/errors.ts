export type CryptoErrorCode = 'INVALID_INPUT' | 'DECRYPT_FAILED' | 'UNSUPPORTED_VERSION';

export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(code: CryptoErrorCode, message: string) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
  }
}
