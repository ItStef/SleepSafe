import {
  type ChallengeResponse,
  type LoginRequest,
  type MeResponse,
  type PreloginResponse,
  type RegisterRequest,
  type VerifyCodeRequest,
  accessTokenResponseSchema,
  challengeResponseSchema,
  meResponseSchema,
  preloginResponseSchema,
} from '@sleepsafe/shared';
import type { HttpClient, RefreshResult } from './http';

export interface AuthApi {
  prelogin(email: string): Promise<PreloginResponse>;
  register(body: RegisterRequest): Promise<ChallengeResponse>;
  verifyEmail(body: VerifyCodeRequest): Promise<void>;
  login(body: LoginRequest): Promise<ChallengeResponse>;
  verifyOtp(body: VerifyCodeRequest): Promise<void>;
  refresh(): Promise<RefreshResult>;
  logout(): Promise<void>;
  me(): Promise<MeResponse>;
}

export function createAuthApi(http: HttpClient): AuthApi {
  return {
    prelogin: (email) =>
      http.request('POST', '/auth/prelogin', {
        auth: false,
        body: { email },
        schema: preloginResponseSchema,
      }),
    register: (body) =>
      http.request('POST', '/auth/register', {
        auth: false,
        body,
        schema: challengeResponseSchema,
      }),
    verifyEmail: (body) => http.request('POST', '/auth/verify-email', { auth: false, body }),
    login: (body) =>
      http.request('POST', '/auth/login', { auth: false, body, schema: challengeResponseSchema }),
    verifyOtp: async (body) => {
      const { accessToken } = await http.request('POST', '/auth/verify-otp', {
        auth: false,
        body,
        schema: accessTokenResponseSchema,
      });
      http.setAccessToken(accessToken);
    },
    refresh: () => http.refreshSession(),
    logout: async () => {
      try {
        await http.request('POST', '/auth/logout', { auth: false });
      } finally {
        http.setAccessToken(null);
      }
    },
    me: () => http.request('GET', '/auth/me', { schema: meResponseSchema }),
  };
}
