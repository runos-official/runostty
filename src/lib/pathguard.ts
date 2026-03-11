import path from 'path';
import fs from 'fs';

/**
 * Resolves a requested path and ensures it stays within the allowed base directory.
 * Guards against path traversal attacks using both `path.resolve()` and `fs.realpathSync()`
 * (to follow symlinks). Returns the resolved path if safe, or `null` if it escapes the base.
 */
export function safePath(requestedPath: string, allowedBase: string): string | null {
  const resolved = path.resolve(allowedBase, requestedPath);

  if (resolved !== allowedBase && !resolved.startsWith(allowedBase + '/')) {
    return null;
  }

  // If the path exists, verify the real path (resolves symlinks)
  try {
    const real = fs.realpathSync(resolved);
    if (real !== allowedBase && !real.startsWith(allowedBase + '/')) {
      return null;
    }
    return real;
  } catch {
    // Path doesn't exist yet — the resolve check above is sufficient
    return resolved;
  }
}
