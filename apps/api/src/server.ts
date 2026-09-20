import { fileURLToPath } from 'node:url';
import { config as loadDotenv } from 'dotenv';
import { ZodError } from 'zod';
import { buildApp } from './app';
import { loadConfig } from './config';
import { createPrismaClient } from './db';
import { createSmtpMailer } from './mailer';

loadDotenv({ path: fileURLToPath(new URL('../../../.env', import.meta.url)), quiet: true });

function readConfig() {
  try {
    return loadConfig();
  } catch (error) {
    if (error instanceof ZodError) {
      for (const issue of error.issues) {
        console.error(`Neispravna podesavanja: ${issue.path.join('.')}: ${issue.message}`);
      }
    } else {
      console.error(error instanceof Error ? error.message : error);
    }
    process.exit(1);
  }
}

const config = readConfig();
const prisma = createPrismaClient(config.DATABASE_URL);
const app = await buildApp({ config, prisma, mailer: createSmtpMailer(config) });

async function shutdown(signal: string) {
  app.log.info({ signal }, 'shutting down');
  await app.close();
  await prisma.$disconnect();
  process.exit(0);
}
process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));

await app.listen({ host: config.HOST, port: config.PORT });
