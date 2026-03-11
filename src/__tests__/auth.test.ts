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
    function mockReq(url: string): IncomingMessage {
      return { url } as IncomingMessage;
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
  });
});
