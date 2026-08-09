import crypto from 'crypto';
import fs from 'fs';
import type { IncomingMessage } from 'http';
import { createMiddleware } from 'hono/factory';
import { resolveUser } from './users';
import { logger } from './logger';
import type { AppEnv } from './types';

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
 * token now rides a header on both transports: `Sec-WebSocket-Protocol` for the websocket
 * (the only header a browser's WebSocket constructor can influence) and `Authorization: Bearer`
 * for the HTTP endpoints.
 *
 * The query form is still ACCEPTED, deliberately and temporarily, so a console built against the
 * old contract keeps working while runostty rolls. It is scheduled for removal once no client
 * sends it; until then the header always WINS, so a stale URL cannot re-authorise a request
 * whose header was rejected.
 */

/** The subprotocol that carries the PSK. Offered by the client, never echoed back. */
const PSK_PROTOCOL_PREFIX = 'runos.psk.';

/** The subprotocol the server selects, so the browser sees its offer accepted. */
const TTY_PROTOCOL = 'runos.tty.v1';

/**
 * Pull the PSK out of a websocket upgrade.
 *
 * Returns null rather than falling through to the query when a psk subprotocol is present but
 * wrong: a client that speaks the new contract has said which token it means, and quietly
 * trying an older one from the URL would make the header impossible to trust.
 */
function extractWsToken(req: IncomingMessage): string | null {
  const offered = req.headers?.['sec-websocket-protocol'];
  const list = (Array.isArray(offered) ? offered.join(',') : offered || '')
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);

  const psk = list.find((p) => p.startsWith(PSK_PROTOCOL_PREFIX));
  if (psk) return psk.slice(PSK_PROTOCOL_PREFIX.length) || null;
  if (list.length > 0 && list.includes(TTY_PROTOCOL)) {
    // Speaks the new contract but offered no token: an explicit refusal, not a fallback.
    return null;
  }

  return new URL(req.url || '', 'http://localhost').searchParams.get('token');
}

/** Authenticates a WebSocket upgrade request. */
export function authenticateWs(req: IncomingMessage): boolean {
  const token = extractWsToken(req);
  if (!token) return false;
  return validateToken(token);
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

/** The PSK for an HTTP request: the bearer header if present, else the legacy query token. */
export function extractHttpToken(
  authorization: string | undefined,
  queryToken: string | undefined,
): string | null {
  const bearer = /^bearer\s+(.+)$/i.exec(authorization?.trim() || '');
  if (bearer) return bearer[1].trim() || null;
  return queryToken || null;
}

/** Hono middleware that validates the PSK token and resolves the user context. */
export const authMiddleware = createMiddleware<AppEnv>(async (c, next) => {
  const token = extractHttpToken(c.req.header('authorization'), c.req.query('token'));
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
