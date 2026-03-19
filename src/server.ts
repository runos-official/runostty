import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { WebSocketServer } from 'ws';
import type { Server } from 'http';
import { authenticateWs } from './lib/auth';
import { handleConnection } from './lib/terminal';
import { logger } from './lib/logger';
import { requestLogger } from './lib/middleware';
import filesApp from './lib/files';
import downloadApp from './lib/download';

const app = new Hono();

// CORS — safe with PSK auth (no cookie/session auth)
app.use('*', cors());

// Request logging middleware
app.use('*', requestLogger);

// Security headers
app.use('*', async (c, next) => {
  await next();
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('X-XSS-Protection', '0');
  c.header('Cache-Control', 'no-store');
});

// Mount HTTP routes
app.route('/', filesApp);
app.route('/', downloadApp);

// Health check (no auth required)
app.get('/health', (c) => c.json({ status: 'ok' }));

const PORT = parseInt(process.env.PORT || '7681', 10);

const server = serve({ fetch: app.fetch, port: PORT }, (info) => {
  logger.info({ port: info.port }, 'RunOS TTY server listening');
});

// Attach WebSocket server to the same HTTP server
const wss = new WebSocketServer({ server: server as unknown as Server });

wss.on('connection', (ws, req) => {
  if (!authenticateWs(req)) {
    logger.warn({ url: req.url }, 'WebSocket auth rejected');
    ws.close(4401, 'Unauthorized');
    return;
  }
  handleConnection(ws, req);
});

// Graceful shutdown
function shutdown(signal: string) {
  logger.info({ signal }, 'Shutting down');
  wss.close(() => {
    server.close(() => {
      logger.info('Server closed');
      process.exit(0);
    });
  });
  // Force exit after 10s
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
