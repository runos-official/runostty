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
2. **Mounts the session gate's PUBLIC key** into the pod. There is no shared secret: the pod verifies a signed, single-use session pass that the RunOS control plane minted for one person and this workspace.
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

All endpoints require `Authorization: Bearer <session pass>` and scope file access to the authenticated user's home directory. Path traversal is blocked. The websocket carries the pass as a `runos.pass.<token>` entry in `Sec-WebSocket-Protocol`. A token in the query string is refused on both, so a live credential never reaches an access log or a browser's history.

## Security

- **Session-pass authentication** on every WebSocket and HTTP request. An Ed25519 signature is checked against the gate's public key, and the pass must name THIS workspace: the raw, case-sensitive owner uid is compared, never the lowercased service name. A pass lasts about a minute and opens one session.
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

- **CI** (`ci.yml`) runs on every push and PR to `main` and `dev`: type checking, linting, formatting, unit tests, and Docker-based integration tests.
- **Leak gate** (`leakcheck.yml`) runs on every push and PR: it keeps credentials and internal identifiers out of this public repo.
- **Image on push** (`deploy.yml`) pushes `ghcr.io/runos-official/runostty` with the commit SHA as tag, plus `dev` for the `dev` branch and `latest` for the `main` branch.
- **Release** (`release.yml`) runs when a version tag is pushed. It builds the image, attests its provenance, and publishes the GitHub release.

### Releases

A release is cut from `dev` by `scripts/release.sh`. It runs every gate (the leak gate, the package version, `npm run check`, `npm test`, and a green CI run on the exact commit), tags the commit, waits for the release workflow, and verifies the image and its attestation:

```sh
scripts/release.sh v0.1.0-rc.1 --check   # every gate, no tag, no push
scripts/release.sh v0.1.0-rc.1           # gates, tag, push, watch, verify
```

`package.json` holds the version of the next final, and a candidate of it shares that number. A tag with a `-rc.N` suffix is a pre-release: the image is tagged with its exact version and with `dev`, and never with `latest`. A final is cut from the exact commit that shipped as a release candidate. It is a new build, tagged with its version, its minor version and `latest`. The `RUNOS_ENV` build argument is `dev` for a candidate and `beta` for a final. `deployed` records the last commit that shipped.
