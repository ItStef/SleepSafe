# syntax=docker/dockerfile:1
# Gradi se iz korena projekta: docker build -f infra/api.Dockerfile .
# Osnova je Debian (slim), a ne Alpine: Prisma alati traze glibc i OpenSSL. Slika je visearhitekturna
# (amd64 i arm64), pa radi i na Apple Silicon Mac-u.
FROM node:22-slim AS base
ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    CI=true \
    DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global pnpm@12.5.1
WORKDIR /app

FROM base AS build
# Prvo samo opisi paketa, da se zavisnosti kesiraju dok se kod ne menja.
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/shared/package.json packages/shared/
COPY apps/api/package.json apps/api/
RUN pnpm install --frozen-lockfile --filter "@sleepsafe/api..."
COPY tsconfig.base.json ./
COPY packages packages
COPY apps/api apps/api
# `prisma generate` trazi samo da DATABASE_URL postoji (baza se ne dodiruje).
RUN DATABASE_URL=postgresql://build:build@localhost:5432/build pnpm --filter @sleepsafe/api db:generate

FROM base AS runtime
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000
COPY --from=build --chown=node:node /app /app
USER node
WORKDIR /app/apps/api
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD node -e "fetch('http://127.0.0.1:3000/health').then((r)=>process.exit(r.ok?0:1),()=>process.exit(1))"
# Migracije se primenjuju pri svakom pokretanju (bezbedno je ponavljati), pa server. `exec` da
# SIGTERM stigne pravo do servera i on se ugasi uredno.
CMD ["sh", "-c", "./node_modules/.bin/prisma migrate deploy && exec ./node_modules/.bin/tsx src/server.ts"]
