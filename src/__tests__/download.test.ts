import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Hono } from 'hono';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawn } from 'child_process';
import type { AppEnv } from '../lib/types';
import { safePath } from '../lib/pathguard';

// Test app that mirrors download.ts logic but uses current uid/gid (not 1001)
function createTestApp(baseDir: string) {
  const app = new Hono<AppEnv>();

  app.use('*', async (c, next) => {
    c.set('userCfg', { uid: process.getuid!(), gid: process.getgid!(), home: baseDir });
    c.set('userName', 'dev');
    await next();
  });

  app.get('/download', (c) => {
    const userCfg = c.get('userCfg');
    const project = c.req.query('project');

    if (!project || !/^[\w.-]+$/.test(project)) {
      return c.json({ error: 'Invalid or missing project name' }, 400);
    }

    const projectBaseDir = `${userCfg.home}/project`;
    const projectDir = `${projectBaseDir}/${project}`;

    const resolved = safePath(projectDir, projectBaseDir);
    if (!resolved) return c.json({ error: 'Forbidden: path outside allowed directory' }, 403);
    if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
      return c.json({ error: 'Project not found' }, 404);
    }

    const tar = spawn('tar', ['czf', '-', '-C', projectBaseDir, project]);

    const stream = new ReadableStream({
      start(controller) {
        tar.stdout.on('data', (chunk: Buffer) => controller.enqueue(chunk));
        tar.stdout.on('end', () => controller.close());
        tar.stderr.on('data', (data: Buffer) => console.error('tar stderr:', data.toString()));
        tar.on('error', (err) => controller.error(err));
      },
      cancel() {
        tar.kill();
      },
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'application/gzip',
        'Content-Disposition': `attachment; filename="${project}.tar.gz"`,
      },
    });
  });

  return app;
}

describe('download route', () => {
  let tmpDir: string;
  let app: Hono<AppEnv>;

  beforeAll(() => {
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'download-')));
    // Create project structure: <tmpDir>/project/myapp/
    fs.mkdirSync(path.join(tmpDir, 'project', 'myapp'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'project', 'myapp', 'index.ts'), 'console.log("hi")');
    fs.writeFileSync(path.join(tmpDir, 'project', 'myapp', 'README.md'), '# MyApp');
    app = createTestApp(tmpDir);
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('returns a tar.gz archive for a valid project', async () => {
    const res = await app.request('/download?project=myapp');
    expect(res.status).toBe(200);
    expect(res.headers.get('Content-Type')).toBe('application/gzip');
    expect(res.headers.get('Content-Disposition')).toBe('attachment; filename="myapp.tar.gz"');

    // Verify the response body is non-empty gzip data
    const buffer = await res.arrayBuffer();
    expect(buffer.byteLength).toBeGreaterThan(0);
    // Gzip magic bytes: 1f 8b
    const bytes = new Uint8Array(buffer);
    expect(bytes[0]).toBe(0x1f);
    expect(bytes[1]).toBe(0x8b);
  });

  it('returns 400 for missing project name', async () => {
    const res = await app.request('/download');
    expect(res.status).toBe(400);
  });

  it('returns 400 for invalid project name with path traversal', async () => {
    const res = await app.request('/download?project=../../../etc');
    expect(res.status).toBe(400);
  });

  it('returns 400 for project name with spaces', async () => {
    const res = await app.request('/download?project=my%20app');
    expect(res.status).toBe(400);
  });

  it('returns 404 for non-existent project', async () => {
    const res = await app.request('/download?project=nonexistent');
    expect(res.status).toBe(404);
  });

  it('accepts project names with dots, dashes, underscores', async () => {
    fs.mkdirSync(path.join(tmpDir, 'project', 'my-app_v1.0'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'project', 'my-app_v1.0', 'f.txt'), 'x');

    const res = await app.request('/download?project=my-app_v1.0');
    expect(res.status).toBe(200);
  });
});
