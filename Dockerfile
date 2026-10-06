FROM node:24.15.0-bookworm-slim@sha256:4e6b70dd6cbfc88c8157ba19aa3d9f9cce6ba4703576d55459e45efcbc9c5f5d
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8080
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY --chown=1000:1000 src/ ./src/
COPY --chown=1000:1000 public/ ./public/
COPY --chown=1000:1000 data/ ./data/
COPY --chown=1000:1000 roles/ ./roles/
COPY --chown=1000:1000 scripts/k8s-load.mjs ./scripts/k8s-load.mjs
COPY --chown=1000:1000 scripts/k8s-distribution.mjs ./scripts/k8s-distribution.mjs
USER 1000:1000
EXPOSE 8080
STOPSIGNAL SIGTERM
CMD ["node", "src/server.mjs"]
