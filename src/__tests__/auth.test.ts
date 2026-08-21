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
    /*
     * THE PSK IS GONE FROM THIS PATH, so these tests changed shape rather than being deleted.
     *
     * A workspace used to be reached at its own public hostname behind a shared secret that rotated
     * hourly. It is now reached only through the in-cluster session gate, which forwards the
     * caller's signed session pass. Every assertion below that used to prove "this PSK opens a
     * session" now proves the stronger thing: a PSK does NOT, and only a pass minted for THIS
     * workspace does.
     *
     * The verification itself is covered in src/lib/sessionPass.test.ts and by the 67 shared golden
     * vectors in src/lib/pass/vectors.test.ts. These are about the wiring.
     */
    function mockReq(url: string, headers: Record<string, string> = {}): IncomingMessage {
      return { url, headers } as unknown as IncomingMessage;
    }

    it('REFUSES a pre-shared key, which used to be the way in', async () => {
      const { authenticateWs } = await getAuth();
      for (const offered of [
        'runos.psk.valid-token-1',
        'runos.psk.valid-token-2',
        'runos.tty.v1, runos.psk.valid-token-1',
        'runos.psk.valid-token-1,runos.tty.v1',
      ]) {
        expect(
          authenticateWs(mockReq('/', { 'sec-websocket-protocol': offered })),
          `a PSK must no longer open a session: ${offered}`,
        ).toBe(false);
      }
    });

    it('rejects an invalid token', async () => {
      const { authenticateWs } = await getAuth();
      expect(
        authenticateWs(mockReq('/', { 'sec-websocket-protocol': 'runos.psk.wrong-token' })),
      ).toBe(false);
    });

    it('rejects when nothing is offered', async () => {
      const { authenticateWs } = await getAuth();
      expect(authenticateWs(mockReq('/'))).toBe(false);
      expect(authenticateWs(mockReq(''))).toBe(false);
      expect(authenticateWs(mockReq('/', { 'sec-websocket-protocol': 'runos.tty.v1' }))).toBe(false);
    });

    it('rejects a pass-shaped subprotocol carrying nothing verifiable', async () => {
      const { authenticateWs } = await getAuth();
      for (const offered of [
        'runos.pass.',
        'runos.pass.not-a-pass',
        'runos.pass.runos_pass_v1.bm90anNvbg.AAAA',
      ]) {
        expect(
          authenticateWs(mockReq('/', { 'sec-websocket-protocol': offered })),
          offered,
        ).toBe(false);
      }
    });

    /*
     * A TOKEN IN THE URL IS STILL IGNORED ENTIRELY, and this outlives the PSK it was written for.
     * Nothing may put a live credential back into an access log by reverting a client.
     */
    it('never reads a credential from the query string', async () => {
      const { authenticateWs } = await getAuth();
      expect(authenticateWs(mockReq('/?token=valid-token-1'))).toBe(false);
      expect(authenticateWs(mockReq('/?pass=runos_pass_v1.x.y'))).toBe(false);
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

    it('selects nothing when the client offered nothing, so a tokenless client cannot open', async () => {
      const { selectWsSubprotocol } = await getAuth();
      expect(selectWsSubprotocol(new Set())).toBe(false);
    });
  });

  describe('authMiddleware token sources', () => {
    it('reads a bearer token from the Authorization header', async () => {
      const { extractHttpToken } = await getAuth();
      expect(extractHttpToken('Bearer valid-token-1')).toBe('valid-token-1');
    });

    it('is case-insensitive about the Bearer scheme', async () => {
      const { extractHttpToken } = await getAuth();
      expect(extractHttpToken('bearer valid-token-1')).toBe('valid-token-1');
    });

    it('ignores an Authorization header that is not a bearer token', async () => {
      const { extractHttpToken } = await getAuth();
      expect(extractHttpToken('Basic abc123')).toBeNull();
    });

    it('returns null when the header is absent, with no query fallback left to try', async () => {
      const { extractHttpToken } = await getAuth();
      expect(extractHttpToken(undefined)).toBeNull();
    });
  });
});
