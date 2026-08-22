import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyPass, PassError, PassRefusal } from './pass';

/**
 * The SAME 67 vectors the gate's Go verifier and conductor's TypeScript verifier read.
 *
 * Three programs verify a session pass and they are three separate images with three separate
 * release cycles. This file is what stops the copy in this repo drifting: a verifier that disagrees
 * with the other two about one input is a hole with a green build.
 */

const VECTORS = resolve(__dirname, 'testdata/passes.json');
const UPSTREAM = resolve(__dirname, '../../../../sessiongate/internal/pass/testdata/passes.json');

interface VectorFile {
  kid: string;
  publicKeyB64url: string;
  nowUnix: number;
  skewSeconds: number;
  vectors: {
    name: string;
    why: string;
    token: string;
    expect: string;
    payload?: Record<string, unknown>;
  }[];
}

const file = JSON.parse(readFileSync(VECTORS, 'utf8')) as VectorFile;
const opts = {
  keys: new Map([[file.kid, Buffer.from(file.publicKeyB64url, 'base64url')]]),
  now: file.nowUnix,
  skewSeconds: file.skewSeconds,
};

describe('the session pass verifier agrees with the gate and the control plane', () => {
  it('has the vectors the contract calls for', () => {
    expect(file.vectors.length).toBeGreaterThanOrEqual(30);
  });

  for (const v of file.vectors) {
    it(`${v.name}: ${v.expect}`, () => {
      if (v.expect === 'valid') {
        const p = verifyPass(v.token, opts);
        if (v.payload) {
          for (const field of ['kid', 'jti', 'aid', 'cid', 'sub', 'kind', 'org'] as const) {
            expect(p[field], `${v.name}: ${field}`).toBe(v.payload[field]);
          }
          expect(p.iat).toBe(v.payload.iat);
          expect(p.exp).toBe(v.payload.exp);
        }
        return;
      }
      let refusal: unknown;
      try {
        verifyPass(v.token, opts);
      } catch (error) {
        refusal = error;
      }
      expect(refusal, `expected ${v.expect} (${v.why}), the pass was ACCEPTED`).toBeInstanceOf(
        PassRefusal,
      );
      expect((refusal as PassRefusal).code, v.why).toBe(v.expect);
    });
  }

  it('exercises every refusal code it defines', () => {
    const used = new Set(file.vectors.filter((v) => v.expect !== 'valid').map((v) => v.expect));
    for (const code of Object.values(PassError))
      expect(used, `no vector produces ${code}`).toContain(code);
  });

  it('has not drifted from the gate repo', () => {
    if (!existsSync(UPSTREAM)) return;
    expect(readFileSync(VECTORS, 'utf8')).toBe(readFileSync(UPSTREAM, 'utf8'));
  });
});
