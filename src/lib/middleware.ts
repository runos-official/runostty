import { createMiddleware } from 'hono/factory';
import { logger } from './logger';

/** HTTP request logging middleware. Logs method, path, status, and duration. */
export const requestLogger = createMiddleware(async (c, next) => {
  const start = Date.now();
  await next();
  const duration = Date.now() - start;

  const logData = {
    method: c.req.method,
    path: c.req.path,
    status: c.res.status,
    duration,
  };

  if (c.res.status >= 500) {
    logger.error(logData, 'request error');
  } else if (c.res.status >= 400) {
    logger.warn(logData, 'request warning');
  } else {
    logger.info(logData, 'request');
  }
});
