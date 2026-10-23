# __APP_NAME__ app image: the ONE opt2 app Dockerfile pattern (SDK-API §15, C53). Base pinned by digest: node:24.22.1-bookworm-slim
# (multi-arch index digest). Bump the tag and the digest together; CI pins the built image by digest in the release record.

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS build
WORKDIR /app
ENV CI=true COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --ignore-scripts
COPY tealbrick.manifest.json tsconfig.json tsconfig.build.json ./
COPY skills ./skills
COPY scripts ./scripts
COPY src ./src
# build = `tb-gen kit` (op ids + I/O types from the manifest, to dist/kit) -> tsc (dist/) -> UI (dist/ui)
RUN pnpm run build && pnpm prune --prod

FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
WORKDIR /app
# TB_DATA_DIR/TB_BACKUP_DIR defaults match the deploy recipe: one data volume at /data, backups in /data/backup (C28).
ENV NODE_ENV=production TB_DATA_DIR=/data TB_BACKUP_DIR=/data/backup
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json tealbrick.manifest.json ./
COPY migrations ./migrations
# Standard manifest location in every opt2 image (tb-exec default --manifest path).
COPY tealbrick.manifest.json /opt/tb/tealbrick.manifest.json
RUN mkdir -p /data/backup && chown -R node:node /data
# Non-root by default. Started as root (Railway volumes, C38) the SDK chowns TB_DATA_DIR and drops to uid 1000 itself.
USER node
EXPOSE 8080
CMD ["node", "dist/main.js"]
