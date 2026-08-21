import type { IncomingMessage } from 'http';
import { createMiddleware } from 'hono/factory';
import { resolveUser } from './users';
import { logger } from './logger';
import type { AppEnv } from './types';
import { authenticatePass } from './sessionPass';

/**
 * The subprotocol the server selects, so the browser sees its offer accepted.
 *
 * THE PRE-SHARED KEY IS GONE FROM THIS FILE ENTIRELY. loadPSKs, validateToken, the timing-safe
 * comparison and the psk subprotocol reader were all removed with it: a workspace is reached only
 * through the session gate now, which forwards a signed pass, and dead code that reads like a live
 * authentication path is worse than no code, because the next person to touch this file has to work
 * out which of the two is real.
 */
const TTY_PROTOCOL = 'runos.tty.v1';

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
/**
 * The HTTP file endpoints, authenticated by a SESSION PASS rather than a shared key.
 *
 * Same reasoning as the websocket path: the pre-shared key opened one workspace for an hour to
 * whoever held it, and it had to be readable by whatever wanted to reach the workspace. A pass names
 * one person and one workspace, lives five minutes for this kind, and is verified HERE because this
 * is the only party that knows whose workspace this is.
 *
 * THE LOGIN COMES FROM THE SIGNED PASS, not from ?user=. It used to come from the query string,
 * which meant anything that could reach this port could read another login's home directory even
 * though it could not have minted the pass.
 */
export const authMiddleware = createMiddleware<AppEnv>(async (c, next) => {
  const token = extractHttpToken(c.req.header('authorization'));
  if (!token) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const result = authenticatePass([`runos.pass.${token}`], Math.floor(Date.now() / 1000));
  if (!result.ok) {
    // The reason stays in the workspace's own log. The caller gets 401 and nothing else: distinct
    // messages would tell a prober which guess was closer.
    logger.warn({ reason: result.reason }, 'Session pass refused on a file request');
    return c.json({ error: 'Unauthorized' }, 401);
  }
  if (result.payload?.kind !== 'ws.files') {
    // A terminal pass must not read files. Both are workspace kinds and both name this workspace,
    // but they are different grants with different lifetimes, and the gate serves them at different
    // doors.
    logger.warn({ kind: result.payload?.kind }, 'A non-file pass was presented to a file endpoint');
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const userParam = result.payload.ws?.user || 'dev';
  c.set('userCfg', resolveUser(userParam));
  c.set('userName', userParam);
  await next();
});
