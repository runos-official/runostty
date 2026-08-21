import crypto from 'crypto';
import fs from 'fs';
import type { IncomingMessage } from 'http';
import { createMiddleware } from 'hono/factory';
import { resolveUser } from './users';
import { logger } from './logger';
import type { AppEnv } from './types';
import { authenticatePass } from './sessionPass';

const PSK_FILE = process.env.PSK_FILE || '/etc/runostty/psk';

/** Loads pre-shared keys from the PSK file. Returns an empty array on failure. */
export function loadPSKs(): string[] {
  try {
    const content = fs.readFileSync(PSK_FILE, 'utf8').trim();
    return content
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error({ pskFile: PSK_FILE, error: message }, 'Failed to read PSK file');
    return [];
  }
}

/** Timing-safe comparison of two strings. Prevents timing attacks on token validation. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // Compare against self to keep constant time regardless of length mismatch
    const buf = Buffer.from(a);
    crypto.timingSafeEqual(buf, buf);
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** Validates a token against the loaded PSKs using timing-safe comparison. */
function validateToken(token: string): boolean {
  const validPSKs = loadPSKs();
  if (validPSKs.length === 0) {
    logger.error('No PSKs loaded — rejecting connection');
    return false;
  }
  return validPSKs.some((psk) => timingSafeEqual(token, psk));
}

/**
 * Where the PSK travels.
 *
 * A secret in a query string is written down in several places nobody thinks about at the time:
 * the ingress access log, the browser's own history, and any `Referer` a page leaks. So the
 * token rides a header on both transports: `Sec-WebSocket-Protocol` for the websocket (the only
 * header a browser's WebSocket constructor can influence) and `Authorization: Bearer` for the
 * HTTP endpoints.
 *
 * The query form was accepted for exactly one release, so runostty could ship before the console
 * without breaking every terminal in between. Both are deployed and no client sends one, so it is
 * now REFUSED: while it stood it was the whole of the remaining exposure, since nothing stopped a
 * new caller being written that way.
 */

/** The subprotocol that carries the PSK. Offered by the client, never echoed back. */
const PSK_PROTOCOL_PREFIX = 'runos.psk.';

/** The subprotocol the server selects, so the browser sees its offer accepted. */
const TTY_PROTOCOL = 'runos.tty.v1';

/**
 * Pull the PSK out of a websocket upgrade.
 *
 * The offered subprotocol list is the only place it may be. A token in the URL is ignored
 * entirely rather than tried as a second chance, so nothing can put a live credential back into
 * an access log by reverting a client.
 */
function extractWsToken(req: IncomingMessage): string | null {
  const offered = req.headers?.['sec-websocket-protocol'];
  const list = (Array.isArray(offered) ? offered.join(',') : offered || '')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);

  const psk = list.find((p) => p.startsWith(PSK_PROTOCOL_PREFIX));
  return psk ? psk.slice(PSK_PROTOCOL_PREFIX.length) || null : null;
}

/**
 * Authenticates a WebSocket upgrade request.
 *
 * THE PSK IS GONE FROM THIS PATH. A workspace used to be reached at its own public hostname behind
 * a shared secret that rotated hourly; it is now reached only through the in-cluster session gate,
 * which forwards the caller's signed session pass. The pass is better than the PSK in the ways that
 * matter: it names ONE person and ONE workspace, it lives for sixty seconds rather than an hour,
 * and it cannot be replayed, so a copy taken from a log is worth nothing a minute later.
 *
 * It is verified HERE as well as at the gate because this is the only party that knows whose
 * workspace this is. A signature proves the control plane issued the pass; only this process can
 * say whether it was issued for THIS workspace. See sessionPass.ts.
 */
export function authenticateWs(req: IncomingMessage): boolean {
  const result = authenticatePass(offeredSubprotocols(req), Math.floor(Date.now() / 1000));
  if (!result.ok) {
    // The reason stays in the workspace's own log. The client gets a close code and nothing else:
    // distinct messages would tell a prober which guess was closer.
    logger.warn({ reason: result.reason }, 'Session pass refused');
    return false;
  }
  return true;
}

/** Every subprotocol the client offered, from either header form. */
function offeredSubprotocols(req: IncomingMessage): string[] {
  const offered = req.headers?.['sec-websocket-protocol'];
  return (Array.isArray(offered) ? offered.join(',') : offered || '')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
}

/**
 * The verified pass for a connection, so the terminal can take its parameters from SIGNED bytes.
 *
 * Re-verifying rather than threading state from authenticateWs: two functions that must be called
 * in the right order, where the second trusts the first, is how a later refactor produces a handler
 * that runs without the check.
 */
export function verifiedPassFor(req: IncomingMessage) {
  return authenticatePass(offeredSubprotocols(req), Math.floor(Date.now() / 1000));
}

/**
 * Choose the subprotocol to answer with.
 *
 * The server MUST select one when the client offered any, or the browser aborts the connection
 * with "Server sent no subprotocol" and it never opens. It selects the plain protocol and NEVER
 * the psk one, because the selection is echoed in a response header and that is precisely the
 * place this change exists to keep the secret out of.
 */
export function selectWsSubprotocol(offered: Set<string>): string | false {
  return offered.has(TTY_PROTOCOL) ? TTY_PROTOCOL : false;
}

/** The PSK for an HTTP request. The bearer header is the only place it may be. */
export function extractHttpToken(authorization: string | undefined): string | null {
  const bearer = /^bearer\s+(.+)$/i.exec(authorization?.trim() || '');
  return bearer ? bearer[1].trim() || null : null;
}

/** Hono middleware that validates the PSK token and resolves the user context. */
export const authMiddleware = createMiddleware<AppEnv>(async (c, next) => {
  const token = extractHttpToken(c.req.header('authorization'));
  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  if (!validateToken(token)) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const userParam = c.req.query('user') || 'dev';
  c.set('userCfg', resolveUser(userParam));
  c.set('userName', userParam);
  await next();
});
