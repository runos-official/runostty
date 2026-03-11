# runostty

[![CI](https://github.com/runos-official/runostty/actions/workflows/ci.yml/badge.svg)](https://github.com/runos-official/runostty/actions/workflows/ci.yml)
[![Deploy](https://github.com/runos-official/runostty/actions/workflows/deploy.yml/badge.svg)](https://github.com/runos-official/runostty/actions/workflows/deploy.yml)

The terminal server that powers RunOS workspaces. Each user in a RunOS cluster gets their own dedicated pod running runostty — a containerised Ubuntu environment with a WebSocket-based terminal and HTTP file management API, all on a single port.

## What it does

runostty gives every RunOS user an isolated, persistent workspace where they can:

- **Run AI coding agents** — Claude Code, OpenAI Codex, Google Gemini CLI, and OpenCode are pre-installed and ready to go. Connect to a terminal, pick your agent, and start building.
- **Monitor infrastructure** — DevOps users get k9s and kubectl for cluster visibility, scoped to their permissions.
- **Browse and download files** — HTTP endpoints let you list directories, read file contents, and download entire project directories as `.tar.gz` archives without needing a terminal session.

## Architecture

```
┌─────────────────────────────────────────────┐
│  runostty pod (per user)                    │
│                                             │
│  Ubuntu 24.04 + Node.js 22                  │
│  ┌─────────────────────────────────────┐    │
│  │  Hono HTTP server — port 7681       │    │
│  │  ├─ WS  /          → PTY terminal   │    │
│  │  ├─ GET /files      → dir listing   │    │
│  │  ├─ GET /files/content → file read  │    │
│  │  ├─ GET /download   → tar.gz stream │    │
│  │  └─ GET /health     → health check  │    │
│  └─────────────────────────────────────┘    │
│                                             │
│  Pre-installed tools:                       │
│  claude, codex, gemini, opencode, runos cli │
│  kubectl, k9s, git, vim, curl, jq ...       │
│                                             │
│  Users:                                     │
│  dev (1001) — coding agents, projects       │
│  devops (1002) — k9s, kubectl, cluster ops  │
│                                             │
│  /home/dev/project/  ← PVC-backed storage   │
└─────────────────────────────────────────────┘
```

## How it works in RunOS

When you launch a workspace through RunOS, the platform:

1. **Spins up your pod** with a runostty container and a persistent volume for your home directory.
2. **Injects a pre-shared key (PSK)** into the pod for authentication. PSKs are rotated frequently and all traffic is served over TLS — the token never travels in the clear.
3. **Connects you** via the RunOS frontend, which opens a WebSocket to your pod's terminal server.

From there you can open terminal sessions as the `dev` user (for coding) or `devops` user (for cluster operations). The client can pass a base64-encoded init command via `?cmd=` to automatically launch the right tool on connect.

### Persistent storage

Home directories are backed by PVCs. On first boot (or after an image upgrade), runostty restores a skeleton home directory with pre-installed CLI tools so everything works out of the box. Your projects, configs, and shell history persist across pod restarts.

### File management API

Beyond the terminal, runostty exposes HTTP endpoints for programmatic file access:

| Endpoint | Description |
|---|---|
| `GET /files?dir=...` | List directory contents (name, type, size, modified) |
| `GET /files/content?path=...` | Read a file with proper MIME type |
| `GET /download?project=...` | Stream a project directory as a `.tar.gz` archive |

All endpoints require `&token=<PSK>` and scope file access to the authenticated user's home directory. Path traversal is blocked.

## Security

- **PSK authentication** on every WebSocket and HTTP request. Tokens are validated with timing-safe comparison to prevent timing attacks. Rotated frequently by the RunOS control plane.
- **TLS termination** at the ingress layer — all connections to runostty are encrypted in transit.
- **Path traversal protection** — all file operations are validated to stay within the user's home directory, with symlink resolution.
- **User isolation** — terminal sessions and file operations run with the target user's UID/GID, not as root. Only a minimal set of environment variables (`PATH`, `LANG`, `TERM`, etc.) are passed to spawned shells.
- **Process cleanup** — when a terminal session closes, the entire process group is killed (SIGTERM → SIGKILL after 2s) to prevent orphaned agents.
- **Input validation** — WebSocket messages are capped at 1MB, terminal resize dimensions are validated and clamped, and project names are strictly sanitised.
- **Security headers** — all HTTP responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Cache-Control: no-store`.

## Observability

runostty uses [pino](https://getpino.io/) for structured JSON logging. Every HTTP request is logged with method, path, status code, and duration. Terminal session lifecycle (start/end with PID, user, exit code), authentication failures, and errors are all captured as structured log entries. Log level is configurable via the `LOG_LEVEL` environment variable (default: `info`).

## CI/CD

Automated via GitHub Actions:

- **CI** — runs on every push and PR: type checking, linting, formatting, unit tests, and Docker-based integration tests
- **Deploy** — pushes to `ghcr.io/runos-official/runostty` on every push to `main` and on version tags (`v*`)

Images are tagged by branch (`main`), semver (`0.1.0`, `0.1`), and commit SHA. The `RUNOS_ENV` build arg is set via the `RUNOS_ENV` repository variable (defaults to `dev`).
