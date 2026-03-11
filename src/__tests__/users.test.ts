import { describe, it, expect } from 'vitest';
import { resolveUser } from '../lib/users';

describe('resolveUser', () => {
  it('returns dev config for "dev"', () => {
    const user = resolveUser('dev');
    expect(user).toEqual({ uid: 1001, gid: 1001, home: '/home/dev' });
  });

  it('returns devops config for "devops"', () => {
    const user = resolveUser('devops');
    expect(user).toEqual({ uid: 1002, gid: 1002, home: '/home/devops' });
  });

  it('defaults to dev for unknown user', () => {
    const user = resolveUser('admin');
    expect(user).toEqual({ uid: 1001, gid: 1001, home: '/home/dev' });
  });

  it('defaults to dev for empty string', () => {
    const user = resolveUser('');
    expect(user).toEqual({ uid: 1001, gid: 1001, home: '/home/dev' });
  });
});
