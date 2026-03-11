# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context

runostty is the terminal server that powers RunOS workspaces. Each user in a RunOS cluster gets their own dedicated pod running this container — an Ubuntu 24.04 environment with pre-installed AI coding agents (Claude Code, Codex, Gemini, OpenCode) and DevOps tools (kubectl, k9s). It serves WebSocket terminals and HTTP file management on port 7681. PSKs are rotated frequently by the RunOS control plane and all traffic is served over TLS. Docker images are pushed to `ghcr.io/runos-official/runostty` via GitHub Actions.

## Build & Development Commands

```bash
npm run build          # Compile TypeScript (tsc) → dist/
npm run check          # Full quality gate: tsc --noEmit && eslint && prettier --check
npm run lint           # ESLint only
npm run lint:fix       # ESLint with auto-fix
npm run format         # Prettier write
npm run format:check   # Prettier check only
npm test               # Unit tests (vitest, fast, no Docker)
npm run test:integration  # Integration tests (testcontainers, requires Docker)
```

Unit tests (`npm test`) cover pathguard, auth, users, file routes, and download routes using temp directories. Integration tests (`npm run test:integration`) spin up a real container via `Dockerfile.test` (lightweight, no CLI tools) and test HTTP endpoints, WebSocket auth, terminal sessions, and file operations end-to-end. Pre-build the test image with `docker build -f Dockerfile.test -t runostty-test .` to speed up first runs.

### CI/CD

GitHub Actions handles CI and deployment (`.github/workflows/`):
- **ci.yml** — lint, type check, unit tests, integration tests on every push/PR
- **deploy.yml** — builds and pushes to `ghcr.io/runos-official/runostty` on push to `main` or version tags (`v*`)

The `RUNOS_ENV` build arg (set via GitHub repo variable) controls which RunOS CLI environment gets baked into the image.

## Architecture

runostty is a terminal server that exposes both **WebSocket** (PTY terminals) and **HTTP** (file management) on a single port (7681), using Hono with `@hono/node-server`.

### Request flow

```
Port 7681
  ├─ HTTP → Hono app
  │    ├─ GET /files          → directory listing (JSON)
  │    ├─ GET /files/content  → file content (with MIME type)
  │    ├─ GET /download       → streaming tar.gz of a project dir
  │    └─ GET /health         → health check
  └─ WS upgrade → ws library
       └─ PTY shell (node-pty) with uid/gid isolation
```

All endpoints authenticate via `?token=<PSK>` validated against `/etc/runostty/psk`.

### Key modules (`src/lib/`)

- **auth.ts** — PSK loading with timing-safe comparison (`crypto.timingSafeEqual`), Hono `authMiddleware` (sets `userCfg` on context), `authenticateWs()` for WebSocket
- **terminal.ts** — `handleConnection()`: spawns PTY as the target user, sanitised env (allowlist only), validated resize messages (clamped to 500x200), 1MB message size limit, kills process group on close
- **files.ts** — directory listing and file content endpoints, scoped to user's home dir, proper error handling on fs operations
- **download.ts** — streams `tar czf` of `/home/<user>/project/<name>` directly to response, 60s tar timeout, sanitised Content-Disposition
- **pathguard.ts** — `safePath()` validates paths stay within allowed base (resolves symlinks)
- **users.ts** — user config: `dev` (uid 1001) and `devops` (uid 1002)
- **types.ts** — Hono `AppEnv` type for typed context variables
- **logger.ts** — pino structured JSON logger, configurable via `LOG_LEVEL` env
- **middleware.ts** — HTTP request logging (method, path, status, duration)

### Container lifecycle

The Dockerfile builds TS during `docker build`, then prunes devDeps. At runtime, `entrypoint.sh` restores skeleton home directories from `/opt/runostty-skel*` onto PVC mounts (handles fresh PVCs and image upgrades), sets up RunOS CLI auth, generates kubeconfig for devops, then execs `node /app/dist/server.js`.

## Code Style

- **TypeScript strict mode**, ES2022 target, CommonJS modules
- **Prettier**: single quotes, trailing commas, 100 char width, semicolons
- **ESLint**: typescript-eslint recommended; `no-explicit-any` is warn, unused vars prefixed with `_` are allowed
- Use `createMiddleware<AppEnv>()` from `hono/factory` for typed Hono middleware
- Hono sub-apps use `new Hono<AppEnv>()` to get typed `c.get('userCfg')` without casts
