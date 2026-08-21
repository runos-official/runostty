import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createPrivateKey, generateKeyPairSync } from 'node:crypto';
import { authenticatePass, loadGateKeys } from './sessionPass';
import { signPass, type PassPayload } from './pass/pass';

/**
 * The workspace's own admission check.
 *
 * A signature proves the control plane issued the pass. It does NOT prove the pass was issued for
 * this workspace, and this process is the only party that knows whose workspace it is. Without the
 * identity comparison, any valid pass on the cluster would open a session here and the only thing in
 * the way would be the gate's routing.
 */

const file = JSON.parse(
  readFileSync(resolve(__dirname, 'pass/testdata/passes.json'), 'utf8')
) as { kid: string; publicKeyB64url: string; privateKeySeedB64url: string; nowUnix: number };

const seed = Buffer.from(file.privateKeySeedB64url, 'base64url');
const privateKeyPem = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
  format: 'der',
  type: 'pkcs8',
}).export({ format: 'pem', type: 'pkcs8' }).toString();

const keys = new Map([[file.kid, Buffer.from(file.publicKeyB64url, 'base64url')]]);
const IDENTITY = { svc: 'runostty-gk2xq7m', uid: 'GK2xQ7mUeZbN4hVt0pLrYcSd3fA1' };

function pass(mutate?: (p: PassPayload) => void): string {
  const p: PassPayload = {
    v: 1, kid: file.kid, jti: '0123456789abcdef0123456789abcdef',
    iat: file.nowUnix - 10, exp: file.nowUnix + 50,
    aid: 'rjwrn', cid: 'v6b', sub: IDENTITY.uid, kind: 'ws.terminal',
    org: 'https://console.runos.com',
    ws: { svc: IDENTITY.svc, uid: IDENTITY.uid, user: 'dev', dir: '/home/dev', cmd: '' },
  };
  mutate?.(p);
  return signPass(p, privateKeyPem);
}

const offer = (token: string) => ['runos.session.v1', `runos.pass.${token}`];

describe('authenticatePass', () => {
  it('admits a pass minted for this workspace', () => {
    const r = authenticatePass(offer(pass()), file.nowUnix, IDENTITY, keys);
    expect(r.ok, r.reason).toBe(true);
    expect(r.payload?.ws?.user).toBe('dev');
  });

  /** THE ONE THAT MATTERS: a perfectly valid pass for someone else's workspace. */
  it('refuses a valid pass minted for ANOTHER workspace', () => {
    const other = authenticatePass(
      offer(pass((p) => { p.ws!.svc = 'runostty-someoneelse'; p.ws!.uid = 'ZZ9yR1nVfCcO'; })),
      file.nowUnix, IDENTITY, keys
    );
    expect(other.ok).toBe(false);
    expect(other.reason).toContain('runostty-someoneelse');
  });

  /**
   * Two uids differing only in case share ONE service name, because the name is lowercased. The
   * owner comparison is on the RAW uid for exactly this reason.
   */
  it('refuses a pass whose owner differs from this workspace only by case', () => {
    const r = authenticatePass(
      offer(pass((p) => { p.ws!.uid = IDENTITY.uid.toLowerCase(); })),
      file.nowUnix, IDENTITY, keys
    );
    expect(r.ok).toBe(false);
    expect(r.reason).toContain('another owner');
  });

  it('refuses a VM pass', () => {
    const r = authenticatePass(
      offer(pass((p) => { p.kind = 'vm.ssh'; delete p.ws; p.vm = { ns: 'vmgroup-a1b2c', name: 'vm-abcde' }; })),
      file.nowUnix, IDENTITY, keys
    );
    expect(r.ok).toBe(false);
  });

  it('refuses a pass signed by a key this workspace does not trust', () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const foreign = signPass(
      JSON.parse(JSON.stringify({
        v: 1, kid: file.kid, jti: '0123456789abcdef0123456789abcdef',
        iat: file.nowUnix - 10, exp: file.nowUnix + 50, aid: 'rjwrn', cid: 'v6b',
        sub: IDENTITY.uid, kind: 'ws.terminal', org: 'o',
        ws: { svc: IDENTITY.svc, uid: IDENTITY.uid, user: 'dev', dir: '', cmd: '' },
      })),
      privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
    );
    expect(authenticatePass(offer(foreign), file.nowUnix, IDENTITY, keys).ok).toBe(false);
  });

  it('refuses an expired pass', () => {
    expect(authenticatePass(offer(pass()), file.nowUnix + 3600, IDENTITY, keys).ok).toBe(false);
  });

  it('refuses when no pass is offered at all', () => {
    expect(authenticatePass(['runos.session.v1'], file.nowUnix, IDENTITY, keys).ok).toBe(false);
    expect(authenticatePass([], file.nowUnix, IDENTITY, keys).ok).toBe(false);
  });

  /**
   * A workspace that does not know who it belongs to admits NOBODY. The alternative, admitting
   * anyone while misconfigured, would make a missing environment variable a silent open door.
   */
  it('admits nobody when it does not know its own identity', () => {
    for (const identity of [{ svc: '', uid: 'u' }, { svc: 's', uid: '' }, { svc: '', uid: '' }]) {
      expect(authenticatePass(offer(pass()), file.nowUnix, identity, keys).ok).toBe(false);
    }
  });

  it('admits nobody when no gate key is mounted', () => {
    expect(authenticatePass(offer(pass()), file.nowUnix, IDENTITY, new Map()).ok).toBe(false);
  });
});

describe('loadGateKeys', () => {
  it('returns nothing when the file is missing, rather than throwing', () => {
    expect(loadGateKeys('/nonexistent/gate-keys').size).toBe(0);
  });
});
