/**
 * Authenticating a session the GATE forwarded.
 *
 * WHY THE WORKSPACE VERIFIES A PASS AT ALL, when the gate already did. Because the alternative is
 * worse in both directions:
 *
 *   - A shared secret between the gate and every workspace would have to be readable by the gate,
 *     which means giving the gate permission to read Secrets in the cluster. The gate is a small
 *     program with one job and no business reading Secrets, and a component that can read one can
 *     read them all.
 *   - Trusting the network alone ("only the gate can reach 7681") makes the workspace's security a
 *     property of a NetworkPolicy. That policy is real and stays, but it is one apply away from
 *     being wrong, and nothing inside the workspace would notice.
 *
 * So the pass travels one more hop and is verified again by its final destination, which is the only
 * party that knows whose workspace this is.
 *
 * THIS IS NOT THE SINGLE-USE CHECK. The gate burns the pass against a Lease before it dials; the
 * workspace verifies the signature, the kind, and that the pass names THIS workspace. Doing single
 * use here as well would refuse the gate's own forward, which is the same pass by design.
 */

import fs from 'fs';
import { verifyPass, PassRefusal, type PassPayload } from './pass/pass';
import { logger } from './logger';

/** The subprotocol carrying the pass, matching what the gate forwards. */
const PASS_PROTOCOL_PREFIX = 'runos.pass.';

/**
 * The public keys this workspace trusts, from the mounted ConfigMap.
 *
 * Read FRESH on every connection rather than cached at boot. A ConfigMap update lands in the
 * container as a changed file with no restart, and a key cached at startup would make a rotation
 * look like every session suddenly failing its signature.
 */
export function loadGateKeys(path = process.env.GATE_KEYS_FILE || '/etc/runostty/gate-keys'): Map<string, Buffer> {
  const keys = new Map<string, Buffer>();
  let content: string;
  try {
    content = fs.readFileSync(path, 'utf8');
  } catch (err) {
    logger.error({ path, error: err instanceof Error ? err.message : String(err) },
      'Cannot read the session gate public keys');
    return keys;
  }
  for (const entry of content.split(/[\n,]/)) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 0) continue;
    const kid = trimmed.slice(0, eq).trim();
    const key = Buffer.from(trimmed.slice(eq + 1).trim(), 'base64url');
    // Checked here rather than at first use: a truncated key would otherwise present as every
    // session failing its signature, which reads as a compromise rather than a typo.
    if (kid.length === 16 && key.length === 32) keys.set(kid, key);
    else logger.error({ kid, bytes: key.length }, 'Ignoring a malformed gate public key');
  }
  return keys;
}

export interface WorkspaceIdentity {
  /** This workspace's Kubernetes Service name. */
  svc: string;
  /** The raw, case-sensitive uid of the person this workspace belongs to. */
  uid: string;
}

/** Read from the environment the Deployment sets. Never from a request. */
export function workspaceIdentity(): WorkspaceIdentity {
  return {
    svc: (process.env.RUNOS_WORKSPACE_SVC || '').trim(),
    uid: (process.env.RUNOS_WORKSPACE_UID || '').trim(),
  };
}

export interface PassAuthResult {
  ok: boolean;
  /** Set when ok. */
  payload?: PassPayload;
  /** For the workspace's own log. Never sent to the client. */
  reason?: string;
}

/**
 * Verify a forwarded pass and confirm it names THIS workspace.
 *
 * THE IDENTITY CHECK IS THE POINT. A signature proves the control plane issued the pass; it does not
 * prove the pass was issued for this workspace. Without comparing svc and uid, a valid pass for
 * ANY workspace on the cluster would open a session on this one, and the only thing standing in the
 * way would be the gate's own routing.
 */
export function authenticatePass(
  offeredSubprotocols: string[],
  now: number,
  identity: WorkspaceIdentity = workspaceIdentity(),
  keys: Map<string, Buffer> = loadGateKeys()
): PassAuthResult {
  if (!identity.svc || !identity.uid) {
    // A workspace that does not know who it belongs to cannot check anything, so it admits nobody.
    return { ok: false, reason: 'RUNOS_WORKSPACE_SVC and RUNOS_WORKSPACE_UID are not set' };
  }
  if (keys.size === 0) {
    return { ok: false, reason: 'no session gate public key is mounted' };
  }

  const offered = offeredSubprotocols.find((p) => p.startsWith(PASS_PROTOCOL_PREFIX));
  if (!offered) return { ok: false, reason: 'no session pass was offered' };
  const token = offered.slice(PASS_PROTOCOL_PREFIX.length);
  if (!token) return { ok: false, reason: 'the pass subprotocol carried no pass' };

  let payload: PassPayload;
  try {
    // Skew is generous here compared with the gate's, on purpose: this hop happens AFTER the gate
    // has already verified, claimed and dialled, so a pass arriving a second or two closer to its
    // expiry is normal rather than suspicious.
    payload = verifyPass(token, { keys, now, skewSeconds: 60 });
  } catch (error) {
    if (error instanceof PassRefusal) return { ok: false, reason: error.message };
    throw error;
  }

  if (payload.kind !== 'ws.terminal' && payload.kind !== 'ws.files') {
    return { ok: false, reason: `a ${payload.kind} pass does not open a workspace` };
  }
  if (!payload.ws) return { ok: false, reason: 'the pass carries no workspace target' };

  if (payload.ws.svc !== identity.svc) {
    return { ok: false, reason: `the pass names workspace ${payload.ws.svc}, this is ${identity.svc}` };
  }
  // Compared on the RAW uid, never the service name. The service name is lowercased, so two uids
  // differing only in case share one, and comparing names would let either of those people into the
  // other's workspace.
  if (payload.ws.uid !== identity.uid) {
    return { ok: false, reason: 'the pass names another owner' };
  }

  return { ok: true, payload };
}
