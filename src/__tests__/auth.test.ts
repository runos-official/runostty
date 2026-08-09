import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { IncomingMessage } from 'http';

describe('auth', () => {
  let tmpDir: string;
  let pskFile: string;

  beforeAll(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'auth-')));
    pskFile = path.join(tmpDir, 'psk');
    fs.writeFileSync(pskFile, 'valid-token-1\nvalid-token-2\n');
    process.env.PSK_FILE = pskFile;
  });

  afterAll(() => {
    delete process.env.PSK_FILE;
    fs.rmSync(tmpDir, { recursive: true });
  });

  // Dynamic import so PSK_FILE env var is picked up
  async function getAuth() {
    // Clear module cache to pick up env var changes
    vi.resetModules();
    return await import('../lib/auth');
  }

  describe('loadPSKs', () => {
    it('loads tokens from file', async () => {
      const { loadPSKs } = await getAuth();
      const psks = loadPSKs();
      expect(psks).toEqual(['valid-token-1', 'valid-token-2']);
    });

    it('trims whitespace and skips empty lines', async () => {
      fs.writeFileSync(pskFile, '  token-a  \n\n  token-b  \n\n');
      const { loadPSKs } = await getAuth();
      const psks = loadPSKs();
      expect(psks).toEqual(['token-a', 'token-b']);
      // Restore
      fs.writeFileSync(pskFile, 'valid-token-1\nvalid-token-2\n');
    });

    it('returns empty array when file is missing', async () => {
      process.env.PSK_FILE = path.join(tmpDir, 'nonexistent');
      const { loadPSKs } = await getAuth();
      const psks = loadPSKs();
      expect(psks).toEqual([]);
      process.env.PSK_FILE = pskFile;
    });
  });

  describe('authenticateWs', () => {
    function mockReq(url: string, headers: Record<string, string> = {}): IncomingMessage {
      return { url, headers } as unknown as IncomingMessage;
    }

    it('accepts a valid token', async () => {
      const { authenticateWs } = await getAuth();
      expect(authenticateWs(mockReq('/?token=valid-token-1'))).toBe(true);
    });

    it('accepts the second valid token', async () => {
      const { authenticateWs } = await getAuth();
      expect(authenticateWs(mockReq('/?token=valid-token-2'))).toBe(true);
    });

    it('rejects an invalid token', async () => {
      const { authenticateWs } = await getAuth();
      expect(authenticateWs(mockReq('/?token=wrong-token'))).toBe(false);
    });

    it('rejects when no token is provided', async () => {
      const { authenticateWs } = await getAuth();
      expect(authenticateWs(mockReq('/'))).toBe(false);
    });

    it('rejects when URL is empty', async () => {
      const { authenticateWs } = await getAuth();
      expect(authenticateWs(mockReq(''))).toBe(false);
    });

    // A PSK in the query string is written to the ingress access log, the browser's history and
    // any Referer that leaks out, so the token now rides the Sec-WebSocket-Protocol header
    // instead. The query form still works for one release so an older console keeps connecting
    // while runostty rolls; it is scheduled for removal.
    it('accepts a token offered as a websocket subprotocol', async () => {
      const { authenticateWs } = await getAuth();
      expect(
        authenticateWs(
          mockReq('/', { 'sec-websocket-protocol': 'runos.tty.v1, runos.psk.valid-token-1' }),
        ),
      ).toBe(true);
    });

    it('accepts the subprotocol token whatever order it is offered in', async () => {
      const { authenticateWs } = await getAuth();
      expect(
        authenticateWs(
          mockReq('/', { 'sec-websocket-protocol': 'runos.psk.valid-token-1,runos.tty.v1' }),
        ),
      ).toBe(true);
    });

    it('rejects a wrong token offered as a subprotocol', async () => {
      const { authenticateWs } = await getAuth();
      expect(
        authenticateWs(mockReq('/', { 'sec-websocket-protocol': 'runos.psk.wrong-token' })),
      ).toBe(false);
    });

    it('rejects when the subprotocol list carries no psk entry', async () => {
      const { authenticateWs } = await getAuth();
      expect(authenticateWs(mockReq('/', { 'sec-websocket-protocol': 'runos.tty.v1' }))).toBe(
        false,
      );
    });

    it('prefers the subprotocol token over a query one, so a stale URL cannot re-authorise', async () => {
      const { authenticateWs } = await getAuth();
      expect(
        authenticateWs(
          mockReq('/?token=valid-token-1', { 'sec-websocket-protocol': 'runos.psk.wrong-token' }),
        ),
      ).toBe(false);
    });
  });

  describe('selectWsSubprotocol', () => {
    // The browser aborts a websocket whose server answers with no subprotocol when the client
    // offered one, so the server MUST choose. Learned the hard way against a different server:
    // "Server sent no subprotocol" and the connection never opens.
    it('selects the plain protocol so the handshake completes', async () => {
      const { selectWsSubprotocol } = await getAuth();
      expect(selectWsSubprotocol(new Set(['runos.tty.v1', 'runos.psk.valid-token-1']))).toBe(
        'runos.tty.v1',
      );
    });

    it('NEVER echoes the psk back, which would put it in a response header', async () => {
      const { selectWsSubprotocol } = await getAuth();
      expect(selectWsSubprotocol(new Set(['runos.psk.valid-token-1']))).toBe(false);
    });

    it('selects nothing when the client offered nothing, which is the legacy query path', async () => {
      const { selectWsSubprotocol } = await getAuth();
      expect(selectWsSubprotocol(new Set())).toBe(false);
    });
  });

  describe('authMiddleware token sources', () => {
    it('reads a bearer token from the Authorization header', async () => {
      const { extractHttpToken } = await getAuth();
      expect(extractHttpToken('Bearer valid-token-1', undefined)).toBe('valid-token-1');
    });

    it('is case-insensitive about the Bearer scheme', async () => {
      const { extractHttpToken } = await getAuth();
      expect(extractHttpToken('bearer valid-token-1', undefined)).toBe('valid-token-1');
    });

    it('falls back to the query token for one release', async () => {
      const { extractHttpToken } = await getAuth();
      expect(extractHttpToken(undefined, 'valid-token-1')).toBe('valid-token-1');
    });

    it('prefers the header, so a stale query token cannot override it', async () => {
      const { extractHttpToken } = await getAuth();
      expect(extractHttpToken('Bearer from-header', 'from-query')).toBe('from-header');
    });

    it('ignores an Authorization header that is not a bearer token', async () => {
      const { extractHttpToken } = await getAuth();
      expect(extractHttpToken('Basic abc123', undefined)).toBeNull();
    });

    it('returns null when neither source carries one', async () => {
      const { extractHttpToken } = await getAuth();
      expect(extractHttpToken(undefined, undefined)).toBeNull();
    });
  });
});
