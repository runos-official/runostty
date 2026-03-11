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

/** Authenticates a WebSocket upgrade request by checking the token query parameter. */
export function authenticateWs(req: IncomingMessage): boolean {
  const params = new URL(req.url || '', 'http://localhost').searchParams;
  const token = params.get('token');
  if (!token) return false;
  return validateToken(token);
}

/** Hono middleware that validates the PSK token and resolves the user context. */
export const authMiddleware = createMiddleware<AppEnv>(async (c, next) => {
  const token = c.req.query('token');
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
