// Provera okruzenja pre pokretanja: radi isto na Windows-u, macOS-u i Linux-u (samo Node, bez
// zavisnosti). Pokretanje: pnpm check:env
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';

const results = [];
const add = (level, text) => results.push({ level, text });
const ok = (text) => add('OK', text);
const warn = (text) => add('UPOZORENJE', text);
const fail = (text) => add('GRESKA', text);
const info = (text) => add('INFO', text);

function run(command, args) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    shell: process.platform === 'win32',
  });
  return { ok: result.status === 0, out: `${result.stdout ?? ''}${result.stderr ?? ''}`.trim() };
}

function parseEnv(text) {
  const values = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const index = line.indexOf('=');
    if (index < 1) continue;
    values[line.slice(0, index).trim()] = line
      .slice(index + 1)
      .trim()
      .replace(/^['"]|['"]$/g, '');
  }
  return values;
}

// Prvo se pokusa povezivanje (uhvati i port koji drzi Docker samo na 127.0.0.1, sto Windows ne
// prijavljuje pri slusanju), a tek onda slusanje.
function portFree(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host: '127.0.0.1' });
    socket.setTimeout(500);
    const finish = (inUse) => {
      socket.destroy();
      if (inUse) {
        resolve(false);
        return;
      }
      const server = net.createServer();
      server.once('error', () => resolve(false));
      server.once('listening', () => server.close(() => resolve(true)));
      server.listen(port, '0.0.0.0');
    };
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.once('timeout', () => finish(false));
  });
}

async function main() {
  ok(`Sistem: ${os.platform()} ${os.arch()} (${os.release()})`);

  const nodeMajor = Number(process.versions.node.split('.')[0]);
  if (nodeMajor >= 22) ok(`Node ${process.versions.node}`);
  else fail(`Node ${process.versions.node}: potreban je Node 22 ili noviji`);

  const pnpm = run('pnpm', ['--version']);
  if (!pnpm.ok) fail('pnpm nije instaliran (npm install -g pnpm)');
  else if (pnpm.out.startsWith('12.')) ok(`pnpm ${pnpm.out}`);
  else warn(`pnpm ${pnpm.out}: projekat koristi pnpm 12 (menja se sam po "packageManager")`);

  const docker = run('docker', ['--version']);
  if (!docker.ok) {
    fail('Docker nije instaliran (Docker Desktop za Windows ili macOS)');
  } else {
    ok(docker.out);
    const info = run('docker', ['info', '--format={{.ServerVersion}}/{{.Architecture}}']);
    if (info.ok) ok(`Docker servis radi (${info.out})`);
    else
      fail(
        'Docker je instaliran, ali servis ne radi: pokrenite Docker Desktop i sacekajte "Engine running"',
      );
    if (run('docker', ['compose', 'version']).ok) ok('docker compose je dostupan');
    else fail('docker compose nije dostupan (potreban je Docker Compose v2)');
  }

  let env = {};
  if (!existsSync('.env')) {
    fail('Fajl .env ne postoji: kopirajte .env.example u .env i promenite tajne vrednosti');
  } else {
    env = parseEnv(readFileSync('.env', 'utf8'));
    ok('Fajl .env postoji');
    for (const key of ['POSTGRES_PASSWORD', 'JWT_SECRET', 'SERVER_PEPPER']) {
      const value = env[key] ?? '';
      if (value === '') fail(`${key} nije podesen u .env`);
      else if (value.includes('promeni-me'))
        warn(`${key} je jos uvek primer iz .env.example: promenite ga`);
      else ok(`${key} je podesen`);
    }
    for (const key of ['JWT_SECRET', 'SERVER_PEPPER']) {
      const value = env[key] ?? '';
      if (value !== '' && value.length < 32)
        fail(`${key} mora imati najmanje 32 znaka (ima ${value.length})`);
    }
    if (env.JWT_SECRET && env.JWT_SECRET === env.SERVER_PEPPER)
      fail('JWT_SECRET i SERVER_PEPPER moraju biti razliciti');
    if ((env.SMTP_HOST ?? '') === '') {
      info(
        'SMTP nije podesen: pnpm stack:demo salje kodove u Mailpit (probni rezim), a pnpm stack:up trazi pravi SMTP u .env',
      );
    } else if (env.NODE_ENV === 'production' && (env.SMTP_TLS ?? 'none') === 'none') {
      fail('NODE_ENV je production, a SMTP_TLS mora biti starttls ili tls');
    }
    const stackUrl = env.STACK_APP_URL;
    if (stackUrl !== undefined && !stackUrl.startsWith('https://')) {
      warn(
        `STACK_APP_URL (${stackUrl}) nije https: Web Crypto radi samo na https ili na localhost`,
      );
    }
    if (env.HTTPS_PORT !== undefined && env.HTTPS_PORT !== '443' && stackUrl === undefined) {
      warn('HTTPS_PORT nije 443: podesite i STACK_APP_URL (na primer https://localhost:8443)');
    }
  }

  const ports = [
    ['HTTP_PORT', Number(env.HTTP_PORT ?? 80)],
    ['HTTPS_PORT', Number(env.HTTPS_PORT ?? 443)],
    ['POSTGRES_PORT', Number(env.POSTGRES_PORT ?? 5432)],
    ['MAILPIT_UI_PORT', Number(env.MAILPIT_UI_PORT ?? 8025)],
  ];
  for (const [name, port] of ports) {
    if (await portFree(port)) ok(`Port ${port} (${name}) je slobodan`);
    else
      warn(
        `Port ${port} (${name}) je zauzet: ako je to SleepSafe, sve je u redu; inace promenite ${name} u .env`,
      );
  }

  const width = Math.max(...results.map((r) => r.level.length));
  for (const { level, text } of results) console.log(`${level.padEnd(width)}  ${text}`);
  const failures = results.filter((r) => r.level === 'GRESKA').length;
  const warnings = results.filter((r) => r.level === 'UPOZORENJE').length;
  console.log(`\n${failures} gresaka, ${warnings} upozorenja.`);
  process.exit(failures > 0 ? 1 : 0);
}

await main();
