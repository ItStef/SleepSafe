import { z } from 'zod';

// Prazna vrednost u .env (na primer "SMTP_USER=") znaci "nije podeseno".
const optionalText = z.preprocess(
  (value) => (value === '' ? undefined : value),
  z.string().min(1).optional(),
);

const booleanFromEnv = z
  .enum(['true', 'false'])
  .default('false')
  .transform((value) => value === 'true');

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().min(1).default('127.0.0.1'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_URL: z.string().min(1),
  APP_URL: z.url().default('http://localhost:5173'),
  JWT_SECRET: z.string().min(32),
  SERVER_PEPPER: z.string().min(32),
  TRUST_PROXY: booleanFromEnv,
  RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).default(120),
  AUTH_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).default(10),

  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
  SESSION_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),
  LOGIN_MAX_FAILURES: z.coerce.number().int().min(1).default(10),
  LOGIN_LOCKOUT_MINUTES: z.coerce.number().int().min(1).default(15),

  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  MAX_ITEMS_PER_USER: z.coerce.number().int().min(1).default(10_000),

  // Email server. Podrazumevano je lokalni Mailpit (docker-compose), koji ne trazi ni sifrovanje ni lozinku.
  SMTP_HOST: z.string().min(1).default('127.0.0.1'),
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(1025),
  SMTP_TLS: z.enum(['none', 'starttls', 'tls']).default('none'),
  SMTP_USER: optionalText,
  SMTP_PASS: optionalText,
  SMTP_FROM: z.string().min(3).default('SleepSafe <no-reply@sleepsafe.local>'),
});

export type Config = z.infer<typeof schema>;

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const config = schema.parse(env);

  if (config.JWT_SECRET === config.SERVER_PEPPER) {
    throw new Error('JWT_SECRET and SERVER_PEPPER must be different');
  }
  if (
    config.NODE_ENV === 'production' &&
    (config.JWT_SECRET.includes('promeni-me') || config.SERVER_PEPPER.includes('promeni-me'))
  ) {
    throw new Error('Secrets must be changed from the example values');
  }
  if ((config.SMTP_USER === undefined) !== (config.SMTP_PASS === undefined)) {
    throw new Error('SMTP_USER and SMTP_PASS must be set together');
  }
  if (config.NODE_ENV === 'production' && config.SMTP_TLS === 'none') {
    throw new Error('SMTP_TLS must be starttls or tls in production');
  }

  return config;
}
