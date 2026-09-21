# SleepSafe

Menadžer lozinki otvorenog koda. Sve se šifruje na uređaju korisnika (zero-knowledge): server čuva samo šifrovane podatke i ne može da ih pročita. Prijava traži master lozinku i kod iz emaila, a za zaboravljenu lozinku postoji 20 kodova za oporavak.

## Šta je potrebno

- **Docker Desktop** (Windows ili macOS; na Mac-u radi i sa Apple Silicon čipom)
- **Node.js 22** i **pnpm 12** (samo za razvoj i za `pnpm` komande ispod)

Provera okruženja na bilo kom sistemu:

```bash
pnpm install
pnpm check:env
```

## Pokretanje celog sistema (baza, API, veb, HTTPS)

1. Napravite podešavanja i promenite tajne vrednosti:

   ```bash
   cp .env.example .env        # Windows PowerShell: Copy-Item .env.example .env
   ```

2. **Probni režim** (kodovi za prijavu stižu u Mailpit, nije za pravo korišćenje):

   ```bash
   pnpm stack:demo
   ```

   Otvorite `https://localhost` (pregledač će upozoriti na sertifikat dok ne dodate poverenje, vidi ispod). Kodove čitate na `http://localhost:8025`.

3. **Pravo korišćenje** traži pravi SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_TLS=starttls|tls`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` u `.env`) i jake tajne:

   ```bash
   pnpm stack:up
   ```

Ostale komande: `pnpm stack:logs` (dnevnik), `pnpm stack:down` (zaustavljanje; podaci ostaju u Docker volumenima).

## Pristup sa drugog uređaja (na primer sa Mac-a)

Web Crypto radi samo na HTTPS adresi, pa aplikacija mora da se otvara preko `https://`.

1. U `.env` na računaru-domaćinu podesite adresu tog računara: `SITE_ADDRESS=192.168.1.20` (ili ime računara).
2. Pokrenite `pnpm stack:up` (ili `stack:demo`).
3. Na uređaju sa kog pristupate dodajte poverenje u Caddy-jev lokalni sertifikat. Prvo ga izvucite na domaćinu:

   ```bash
   docker compose --env-file .env -f infra/docker-compose.yml --profile app cp web:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
   ```

   Zatim ga instalirajte:

   - **macOS:** `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain caddy-root.crt`
   - **Windows (administrator):** `certutil -addstore -f "ROOT" caddy-root.crt`

4. Otvorite `https://192.168.1.20` na drugom uređaju.

Firewall na domaćinu mora da propušta portove 80 i 443.

## Razvoj

```bash
pnpm install
pnpm db:up          # baza i Mailpit u Docker-u
pnpm dev:api        # API na http://localhost:3000
pnpm dev:web        # klijent na http://localhost:5173
pnpm test           # svi testovi (traže pokrenutu bazu)
```

## macOS

Sve komande su iste kao na Windows-u i ne koriste skripte specifične za sistem. Docker slike se grade i za `amd64` i za `arm64`, a CI proverava instalaciju, lint, tipove i testove i na macOS-u. Ako nešto ne radi, prvo pokrenite `pnpm check:env`: ispisuje šta nedostaje (Docker servis, `.env`, zauzete portove).
