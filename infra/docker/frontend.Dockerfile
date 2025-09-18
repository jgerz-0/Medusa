# syntax=docker/dockerfile:1
# Next.js frontend image for local Compose development.
FROM node:20-bullseye-slim AS base

ENV NODE_ENV=development \
    NEXT_TELEMETRY_DISABLED=1

WORKDIR /app/frontend

# Enable pnpm via Corepack and install dependencies.
RUN corepack enable \
    && corepack prepare pnpm@8.15.4 --activate

COPY frontend/package.json ./package.json
# Install dependencies upfront to leverage Docker layer caching.
RUN pnpm install

# Copy the remaining frontend source files and ensure the non-root user owns them.
COPY frontend/ ./
RUN chown -R node:node /app/frontend

EXPOSE 3000

CMD ["pnpm", "dev", "--hostname", "0.0.0.0", "--port", "3000"]
