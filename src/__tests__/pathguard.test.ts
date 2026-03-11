import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { safePath } from '../lib/pathguard';

describe('safePath', () => {
  let tmpDir: string;

  beforeAll(() => {
    // Use realpathSync to resolve macOS /var → /private/var symlink
    tmpDir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'pathguard-')));
    fs.mkdirSync(path.join(tmpDir, 'subdir'));
    fs.writeFileSync(path.join(tmpDir, 'file.txt'), 'hello');
    fs.writeFileSync(path.join(tmpDir, 'subdir', 'nested.txt'), 'nested');
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('allows paths within the base directory', () => {
    const result = safePath(path.join(tmpDir, 'file.txt'), tmpDir);
    expect(result).toBe(path.join(tmpDir, 'file.txt'));
  });

  it('allows nested paths within the base directory', () => {
    const result = safePath(path.join(tmpDir, 'subdir', 'nested.txt'), tmpDir);
    expect(result).toBe(path.join(tmpDir, 'subdir', 'nested.txt'));
  });

  it('allows the base directory itself', () => {
    const result = safePath(tmpDir, tmpDir);
    expect(result).toBe(tmpDir);
  });

  it('blocks simple ../ traversal', () => {
    const result = safePath(path.join(tmpDir, '..', 'etc', 'passwd'), tmpDir);
    expect(result).toBeNull();
  });

  it('blocks deep ../ traversal', () => {
    const result = safePath(path.join(tmpDir, 'subdir', '..', '..', '..', 'etc', 'passwd'), tmpDir);
    expect(result).toBeNull();
  });

  it('blocks absolute path outside base', () => {
    const result = safePath('/etc/passwd', tmpDir);
    expect(result).toBeNull();
  });

  it('returns resolved path for non-existent files within base', () => {
    const result = safePath(path.join(tmpDir, 'does-not-exist.txt'), tmpDir);
    expect(result).toBe(path.join(tmpDir, 'does-not-exist.txt'));
  });

  it('blocks symlinks pointing outside base', () => {
    const linkPath = path.join(tmpDir, 'evil-link');
    fs.symlinkSync('/etc/passwd', linkPath);

    const result = safePath(linkPath, tmpDir);
    expect(result).toBeNull();

    fs.unlinkSync(linkPath);
  });

  it('allows symlinks pointing within base', () => {
    const linkPath = path.join(tmpDir, 'good-link');
    fs.symlinkSync(path.join(tmpDir, 'file.txt'), linkPath);

    const result = safePath(linkPath, tmpDir);
    expect(result).toBe(path.join(tmpDir, 'file.txt'));

    fs.unlinkSync(linkPath);
  });
});
