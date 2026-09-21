# syntax=docker/dockerfile:1
# Veb klijent (statican build) + Caddy, koji sluzi fajlove, radi HTTPS i prosledjuje /auth, /vault i
# /health ka API-ju. Gradi se iz korena projekta: docker build -f infra/web.Dockerfile .
FROM node:22-slim AS build
ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    CI=true
RUN npm install --global pnpm@12.5.1
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/shared/package.json packages/shared/
COPY apps/web/package.json apps/web/
RUN pnpm install --frozen-lockfile --filter "@sleepsafe/web..."
COPY tsconfig.base.json ./
COPY packages packages
COPY apps/web apps/web
RUN pnpm --filter @sleepsafe/web build

FROM caddy:2-alpine
COPY infra/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/apps/web/dist /srv
EXPOSE 80 443
