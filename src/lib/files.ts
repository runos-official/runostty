import { Hono } from 'hono';
import fs from 'fs';
import path from 'path';
import { authMiddleware } from './auth';
import { safePath } from './pathguard';
import { logger } from './logger';
import type { AppEnv } from './types';

/** Maximum file size for content reads (50MB). */
const MAX_FILE_SIZE = 50 * 1024 * 1024;

/** Extension-to-MIME-type mapping for common file types. */
const MIME_TYPES: Record<string, string> = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.ts': 'application/typescript',
  '.json': 'application/json',
  '.xml': 'application/xml',
  '.txt': 'text/plain',
  '.md': 'text/markdown',
  '.yaml': 'text/yaml',
  '.yml': 'text/yaml',
  '.sh': 'text/x-shellscript',
  '.py': 'text/x-python',
  '.go': 'text/x-go',
  '.rs': 'text/x-rust',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.pdf': 'application/pdf',
  '.zip': 'application/zip',
};

/** Returns the MIME type for a file based on its extension, defaulting to octet-stream. */
function getMimeType(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  return MIME_TYPES[ext] || 'application/octet-stream';
}

const app = new Hono<AppEnv>();

/**
 * GET /files — Lists directory contents within the user's home directory.
 * Returns JSON array of entries with name, type, size, and modified timestamp.
 */
app.get('/files', authMiddleware, (c) => {
  const userCfg = c.get('userCfg');
  const dir = c.req.query('dir') || userCfg.home;

  const resolved = safePath(dir, userCfg.home);
  if (!resolved) {
    return c.json({ error: 'Forbidden: path outside allowed directory' }, 403);
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved);
  } catch {
    return c.json({ error: 'Directory not found' }, 404);
  }

  if (!stat.isDirectory()) {
    return c.json({ error: 'Path is not a directory' }, 400);
  }

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(resolved, { withFileTypes: true });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error({ dir: resolved, error: message }, 'Failed to read directory');
    return c.json({ error: 'Failed to read directory' }, 500);
  }

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
      return {
        name: entry.name,
        type: entry.isDirectory() ? ('dir' as const) : ('file' as const),
        size: 0,
        modified: null,
      };
    }
  });

  return c.json(items);
});

/**
 * GET /files/content — Returns the content of a file within the user's home directory.
 * Sets appropriate Content-Type based on file extension. Rejects files over 50MB.
 */
app.get('/files/content', authMiddleware, (c) => {
  const userCfg = c.get('userCfg');
  const filePath = c.req.query('path');

  if (!filePath) {
    return c.json({ error: 'Missing path parameter' }, 400);
  }

  const resolved = safePath(filePath, userCfg.home);
  if (!resolved) {
    return c.json({ error: 'Forbidden: path outside allowed directory' }, 403);
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved);
  } catch {
    return c.json({ error: 'File not found' }, 404);
  }

  if (stat.isDirectory()) {
    return c.json({ error: 'Path is a directory, use /files endpoint' }, 400);
  }

  if (stat.size > MAX_FILE_SIZE) {
    return c.json({ error: 'File too large (max 50MB)' }, 413);
  }

  let content: Buffer;
  try {
    content = fs.readFileSync(resolved);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error({ path: resolved, error: message }, 'Failed to read file');
    return c.json({ error: 'Failed to read file' }, 500);
  }

  const mimeType = getMimeType(resolved);

  return new Response(new Uint8Array(content), {
    headers: {
      'Content-Type': mimeType,
      'Content-Length': stat.size.toString(),
    },
  });
});

export default app;
