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
 * GET /download — Streams a tar.gz archive of a project directory.
 * Validates project name, checks path safety, and spawns tar with the user's uid/gid.
 */
app.get('/download', authMiddleware, (c) => {
  const userCfg = c.get('userCfg');
  const project = c.req.query('project');

  if (!project || !/^[\w.-]+$/.test(project)) {
    return c.json({ error: 'Invalid or missing project name' }, 400);
  }

  const baseDir = `${userCfg.home}/project`;
  const projectDir = `${baseDir}/${project}`;

  const resolved = safePath(projectDir, baseDir);
  if (!resolved) {
    return c.json({ error: 'Forbidden: path outside allowed directory' }, 403);
  }

  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
    return c.json({ error: 'Project not found' }, 404);
  }

  const tar = spawn('tar', ['czf', '-', '-C', baseDir, project], {
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

  // Sanitize project name for Content-Disposition (already validated by regex above)
  const safeFilename = project.replace(/[^\w.-]/g, '_');

  return new Response(stream, {
    headers: {
      'Content-Type': 'application/gzip',
      'Content-Disposition': `attachment; filename="${safeFilename}.tar.gz"`,
    },
  });
});

export default app;
