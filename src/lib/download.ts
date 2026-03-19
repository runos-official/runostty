import path from 'path';
import { Hono } from 'hono';
import { spawn } from 'child_process';
import fs from 'fs';
import { authMiddleware } from './auth';
import { safePath } from './pathguard';
import { logger } from './logger';
import type { AppEnv } from './types';

/** Timeout for tar process in milliseconds (60 seconds). */
const TAR_TIMEOUT_MS = 60_000;

const app = new Hono<AppEnv>();

/**
 * GET /download — Streams a tar.gz archive of a directory.
 *   ?project=MyProject           → /home/<user>/MyProject
 *   ?project=MyFolder/MyProject  → /home/<user>/MyFolder/MyProject
 * Path is validated to stay within the user's home directory.
 */
app.get('/download', authMiddleware, (c) => {
  const userCfg = c.get('userCfg');
  const project = c.req.query('project');

  if (!project) {
    return c.json({ error: 'Missing project parameter' }, 400);
  }

  const targetDir = path.join(userCfg.home, project);

  const resolved = safePath(targetDir, userCfg.home);
  if (!resolved) {
    return c.json({ error: 'Forbidden: path outside allowed directory' }, 403);
  }

  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
    return c.json({ error: 'Directory not found' }, 404);
  }

  const parentDir = path.dirname(resolved);
  const dirName = path.basename(resolved);

  const tar = spawn('tar', ['czf', '-', '-C', parentDir, dirName], {
    uid: userCfg.uid,
    gid: userCfg.gid,
  });

  // Kill tar if it exceeds the timeout
  const timeout = setTimeout(() => {
    logger.warn({ project }, 'Tar process timed out');
    tar.kill('SIGKILL');
  }, TAR_TIMEOUT_MS);

  const stream = new ReadableStream({
    start(controller) {
      tar.stdout.on('data', (chunk: Buffer) => controller.enqueue(chunk));
      tar.stdout.on('end', () => {
        clearTimeout(timeout);
        controller.close();
      });
      tar.stderr.on('data', (data: Buffer) => {
        logger.error({ project, stderr: data.toString() }, 'tar error output');
      });
      tar.on('error', (err) => {
        clearTimeout(timeout);
        controller.error(err);
      });
    },
    cancel() {
      clearTimeout(timeout);
      tar.kill();
    },
  });

  const safeFilename = dirName.replace(/[^\w.-]/g, '_');
  const timestamp = new Date().toISOString().replace(/[:.\-]/g, '');

  return new Response(stream, {
    headers: {
      'Content-Type': 'application/gzip',
      'Content-Disposition': `attachment; filename="${safeFilename}_${timestamp}.tar.gz"`,
    },
  });
});

export default app;
