import * as pty from 'node-pty';
import fs from 'fs';
import type { WebSocket } from 'ws';
import type { IncomingMessage } from 'http';
import { resolveUser } from './users';
import { safePath } from './pathguard';
import { logger } from './logger';

/** Maximum allowed WebSocket message size (1MB). */
const MAX_MESSAGE_SIZE = 1024 * 1024;

/** Maximum terminal dimensions to prevent resource abuse. */
const MAX_COLS = 500;
const MAX_ROWS = 200;

/** Environment variables safe to pass to spawned shells. */
const ALLOWED_ENV_KEYS = ['PATH', 'LANG', 'LC_ALL', 'TERM', 'SHELL', 'TZ'];

/** Builds a sanitized environment for the spawned PTY process. */
function buildEnv(userHome: string, userName: string): Record<string, string> {
  const env: Record<string, string> = {
    HOME: userHome,
    USER: userName,
    TERM: 'xterm-256color',
  };
  for (const key of ALLOWED_ENV_KEYS) {
    if (process.env[key]) {
      env[key] = process.env[key]!;
    }
  }
  return env;
}

/** Validates and clamps terminal resize dimensions. */
function validateResize(cols: unknown, rows: unknown): { cols: number; rows: number } | null {
  const c = Number(cols);
  const r = Number(rows);
  if (!Number.isFinite(c) || !Number.isFinite(r) || c < 1 || r < 1) return null;
  return {
    cols: Math.min(Math.floor(c), MAX_COLS),
    rows: Math.min(Math.floor(r), MAX_ROWS),
  };
}

/**
 * Handles a new WebSocket terminal connection.
 * Spawns a PTY shell for the authenticated user with optional working directory
 * and init command support. Manages bidirectional data flow and cleanup.
 */
export function handleConnection(ws: WebSocket, req: IncomingMessage): void {
  const params = new URL(req.url || '', 'http://localhost').searchParams;
  const userParam = params.get('user') || 'dev';
  const userCfg = resolveUser(userParam);

  const requestedDir = params.get('dir') || userCfg.home;
  const cmdParam = params.get('cmd');

  // Validate the working directory stays within the user's home
  const dir = safePath(requestedDir, userCfg.home) || userCfg.home;

  // Auto-create the directory if it doesn't exist (safe: no shell injection)
  if (!fs.existsSync(dir)) {
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.chownSync(dir, userCfg.uid, userCfg.gid);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      logger.error({ dir, error: message }, 'Failed to create working directory');
    }
  }

  const shellCmd = 'bash';
  let shellArgs = ['--login'];

  // Client can pass a base64-encoded command to run on session start
  if (cmdParam) {
    const cmd = Buffer.from(cmdParam, 'base64').toString('utf8');
    logger.info({ user: userParam, cmd }, 'Init command received');
    shellArgs = ['--login', '-c', `${cmd}; exec bash --login`];
  }

  const shell = pty.spawn(shellCmd, shellArgs, {
    name: 'xterm-256color',
    cwd: dir,
    env: buildEnv(userCfg.home, userParam),
    cols: 80,
    rows: 24,
    uid: userCfg.uid,
    gid: userCfg.gid,
  });

  logger.info({ user: userParam, pid: shell.pid, cwd: dir }, 'Terminal session started');

  shell.onData((data) => ws.send(data));
  shell.onExit(({ exitCode }) => {
    logger.info({ user: userParam, pid: shell.pid, exitCode }, 'Terminal session ended');
    ws.close();
  });

  ws.on('message', (msg) => {
    const raw = msg instanceof Buffer ? msg : Buffer.from(msg as ArrayBuffer);
    if (raw.length > MAX_MESSAGE_SIZE) {
      logger.warn({ size: raw.length }, 'WebSocket message exceeds size limit');
      return;
    }

    const parsed = raw.toString();
    try {
      const json = JSON.parse(parsed);
      if (json.cols !== undefined && json.rows !== undefined) {
        const dims = validateResize(json.cols, json.rows);
        if (dims) {
          shell.resize(dims.cols, dims.rows);
        }
        return;
      }
    } catch {
      // Not JSON — treat as terminal input
    }
    shell.write(parsed);
  });

  ws.on('close', () => {
    const pid = shell.pid;
    try {
      process.kill(-pid, 'SIGTERM');
    } catch {
      // Process already exited
    }
    // Force kill after 2s if anything survives
    setTimeout(() => {
      try {
        process.kill(-pid, 'SIGKILL');
      } catch {
        // Process already exited
      }
    }, 2000);
  });
}
