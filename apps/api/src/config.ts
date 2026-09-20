import { z } from 'zod';

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
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
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
  return config;
}
