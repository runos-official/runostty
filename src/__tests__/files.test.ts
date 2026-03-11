import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Hono } from 'hono';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { AppEnv } from '../lib/types';
import { safePath } from '../lib/pathguard';

// Build a test app that bypasses PSK auth but mirrors the real route logic.
// This lets us test the file endpoints without needing a PSK file.
function createTestApp(baseDir: string) {
  const app = new Hono<AppEnv>();

  // Fake auth middleware — sets userCfg with home = baseDir
  app.use('*', async (c, next) => {
    c.set('userCfg', { uid: 1001, gid: 1001, home: baseDir });
    c.set('userName', 'dev');
    await next();
  });

  // List directory — same logic as files.ts
  app.get('/files', (c) => {
    const userCfg = c.get('userCfg');
    const dir = c.req.query('dir') || userCfg.home;

    const resolved = safePath(dir, userCfg.home);
    if (!resolved) return c.json({ error: 'Forbidden: path outside allowed directory' }, 403);
    if (!fs.existsSync(resolved)) return c.json({ error: 'Directory not found' }, 404);
    const stat = fs.statSync(resolved);
    if (!stat.isDirectory()) return c.json({ error: 'Path is not a directory' }, 400);

    const entries = fs.readdirSync(resolved, { withFileTypes: true });
    const items = entries.map((entry) => {
      const fullPath = path.join(resolved, entry.name);
      try {
        const entryStat = fs.statSync(fullPath);
        return {
          name: entry.name,
          type: entry.isDirectory() ? ('dir' as const) : ('file' as const),
          size: entryStat.size,
          modified: entryStat.mtime.toISOString(),
        };
      } catch {
        return { name: entry.name, type: 'file' as const, size: 0, modified: null };
      }
    });
    return c.json(items);
  });

  // Read file content — same logic as files.ts
  app.get('/files/content', (c) => {
    const userCfg = c.get('userCfg');
    const filePath = c.req.query('path');
    if (!filePath) return c.json({ error: 'Missing path parameter' }, 400);

    const resolved = safePath(filePath, userCfg.home);
    if (!resolved) return c.json({ error: 'Forbidden: path outside allowed directory' }, 403);
    if (!fs.existsSync(resolved)) return c.json({ error: 'File not found' }, 404);
    const stat = fs.statSync(resolved);
    if (stat.isDirectory())
      return c.json({ error: 'Path is a directory, use /files endpoint' }, 400);

    const content = fs.readFileSync(resolved);
    return new Response(content, {
      headers: { 'Content-Type': 'application/octet-stream' },
    });
  });

  return app;
}

describe('files routes', () => {
  let tmpDir: string;
  let app: Hono<AppEnv>;

  beforeAll(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'files-')));
    fs.writeFileSync(path.join(tmpDir, 'hello.txt'), 'Hello, World!');
    fs.writeFileSync(path.join(tmpDir, 'data.json'), '{"key":"value"}');
    fs.mkdirSync(path.join(tmpDir, 'subdir'));
    fs.writeFileSync(path.join(tmpDir, 'subdir', 'nested.txt'), 'nested content');
    app = createTestApp(tmpDir);
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true });
  });

  describe('GET /files', () => {
    it('lists the home directory by default', async () => {
      const res = await app.request('/files');
      expect(res.status).toBe(200);
      const body = await res.json();
      const names = body.map((e: { name: string }) => e.name).sort();
      expect(names).toEqual(['data.json', 'hello.txt', 'subdir']);
    });

    it('returns type and size for each entry', async () => {
      const res = await app.request('/files');
      const body = await res.json();
      const file = body.find((e: { name: string }) => e.name === 'hello.txt');
      expect(file.type).toBe('file');
      expect(file.size).toBe(13); // "Hello, World!" = 13 bytes
      expect(file.modified).toBeTruthy();

      const dir = body.find((e: { name: string }) => e.name === 'subdir');
      expect(dir.type).toBe('dir');
    });

    it('lists a subdirectory', async () => {
      const res = await app.request(`/files?dir=${tmpDir}/subdir`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body).toHaveLength(1);
      expect(body[0].name).toBe('nested.txt');
    });

    it('returns 404 for non-existent directory', async () => {
      const res = await app.request(`/files?dir=${tmpDir}/nope`);
      expect(res.status).toBe(404);
    });

    it('returns 403 for path traversal attempt', async () => {
      const res = await app.request(`/files?dir=${tmpDir}/../../etc`);
      expect(res.status).toBe(403);
    });

    it('returns 400 when dir is a file', async () => {
      const res = await app.request(`/files?dir=${tmpDir}/hello.txt`);
      expect(res.status).toBe(400);
    });
  });

  describe('GET /files/content', () => {
    it('returns file contents', async () => {
      const res = await app.request(`/files/content?path=${tmpDir}/hello.txt`);
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(text).toBe('Hello, World!');
    });

    it('returns 400 when path is missing', async () => {
      const res = await app.request('/files/content');
      expect(res.status).toBe(400);
    });

    it('returns 404 for non-existent file', async () => {
      const res = await app.request(`/files/content?path=${tmpDir}/nope.txt`);
      expect(res.status).toBe(404);
    });

    it('returns 403 for path traversal attempt', async () => {
      const res = await app.request(`/files/content?path=${tmpDir}/../../etc/passwd`);
      expect(res.status).toBe(403);
    });

    it('returns 400 when path is a directory', async () => {
      const res = await app.request(`/files/content?path=${tmpDir}/subdir`);
      expect(res.status).toBe(400);
    });
  });
});
