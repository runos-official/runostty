/**
 * The RunOS session pass: mint and verify, conductor's half.
 *
 * The gate's Go implementation is the other half, and the two are held together by a single file of
 * golden vectors that both read (sessiongate/internal/pass/testdata/passes.json, vendored here as
 * passes.json). Two implementations that each pass their own tests prove nothing about whether they
 * agree with each other, and a pass one accepts and the other refuses is a hole with a green build.
 *
 * WIRE FORM
 *
 *   runos_pass_v1.<b64url_unpadded(payload JSON)>.<b64url_unpadded(signature)>
 *
 * The Ed25519 signature covers the ASCII bytes "runos_pass_v1.<payload segment>" exactly as
 * transmitted, prefix included. Neither side re-serialises the other's payload, so a difference in
 * key order or spacing between Node and Go cannot change the signed bytes, and a future v2 pass
 * cannot be replayed as v1.
 *
 * UNPADDED base64url is required, not preferred: the pass travels as a WebSocket subprotocol value,
 * which must be an RFC 7230 token. Measured 2026-08-21 in Chrome, Safari and Firefox, a value
 * containing '=', '+' or '/' throws from the WebSocket constructor BEFORE any request is sent, so a
 * padded pass fails with an empty server log and a useless client error.
 *
 * No JWT library, and no algorithm field anywhere in the token. A negotiable `alg` is the commonest
 * way this shape gets broken.
 */

import {
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';
import { parseStrictObject, StrictJsonError } from './strictJson';

export const PASS_PREFIX = 'runos_pass_v1';

/**
 * Bounds a pass before anything expensive touches it.
 *
 * A real pass is a few hundred bytes. The cap exists because the token arrives in a header or a
 * subprotocol value whose length the client controls, and base64-decoding then Ed25519-verifying a
 * megabyte per request is cheap for the caller and expensive for the verifier. Matches the gate's
 * MaxTokenBytes exactly; a vector fails if the two drift.
 */
export const MAX_TOKEN_BYTES = 4096;

/**
 * The bounds on the free text a workspace session carries.
 *
 * ONE LIMIT, and it is the same number at every hop. These were 1024 and 4096 here, 1024 and 4096 in
 * the mint route, and 512 and 512 in the gate's own workspace resolver, so conductor returned 201
 * for a pass the gate could never serve and the client got a generic refusal at CONNECT time for a
 * request that was accepted at MINT time. Worse, a 4096-character cmd produced a token larger than
 * MAX_TOKEN_BYTES, which every verifier then refused as malformed: conductor could mint a credential
 * that violated its own size cap.
 */
export const MAX_WORKSPACE_DIR_BYTES = 512;
export const MAX_WORKSPACE_CMD_BYTES = 512;

export type PassKind = 'vm.ssh' | 'vm.serial' | 'vm.vnc' | 'ws.terminal' | 'ws.files';

const VM_KINDS: ReadonlySet<string> = new Set(['vm.ssh', 'vm.serial', 'vm.vnc']);
const ALL_KINDS: ReadonlySet<string> = new Set([...VM_KINDS, 'ws.terminal', 'ws.files']);

/** Longest exp-iat span a kind may carry. The gate applies the same cap itself. */
export function maxLifetimeSeconds(kind: string): number {
  return kind === 'ws.files' ? 300 : 60;
}

export interface VMTarget {
  ns: string;
  name: string;
}
export interface WSTarget {
  svc: string;
  uid: string;
  user: string;
  dir: string;
  cmd: string;
}

export interface PassPayload {
  v: number;
  kid: string;
  jti: string;
  iat: number;
  exp: number;
  aid: string;
  cid: string;
  sub: string;
  kind: PassKind;
  org: string;
  vm?: VMTarget;
  ws?: WSTarget;
}

/**
 * Refusal codes, deliberately few and identical to the Go side's constants.
 *
 * A taxonomy of forty codes is worse than seven: nobody keys on the rare ones and every extra code
 * is another chance for the two implementations to disagree about which one applies.
 */
export const PassError = {
  Malformed: 'pass_malformed',
  Payload: 'pass_payload',
  UnknownKey: 'pass_unknown_key',
  BadSignature: 'pass_bad_signature',
  Target: 'pass_target',
  Expired: 'pass_expired',
  Lifetime: 'pass_lifetime',
} as const;

export type PassErrorCode = (typeof PassError)[keyof typeof PassError];

export class PassRefusal extends Error {
  constructor(
    readonly code: PassErrorCode,
    reason: string,
  ) {
    super(`${code}: ${reason}`);
    this.name = 'PassRefusal';
  }
}

/**
 * Declared as a function rather than a const arrow so TypeScript narrows after a call: a
 * never-returning arrow does not make the following code unreachable to the compiler, and the
 * difference shows up as spurious "possibly undefined" everywhere a refusal has already run.
 */
function refuse(code: PassErrorCode, reason: string): never {
  throw new PassRefusal(code, reason);
}

// --- encoding ---------------------------------------------------------------------------------

const b64urlEncode = (b: Buffer): string => b.toString('base64url');

/**
 * Decode unpadded base64url, refusing anything Buffer would silently tolerate.
 *
 * Node's 'base64url' decoder is lenient: it accepts padding, accepts the standard '+' and '/'
 * alphabet, and ignores characters it does not recognise. Go's base64.RawURLEncoding refuses all
 * three. Without this check the two sides disagree about exactly the inputs a browser refuses to
 * send, which is the worst place to disagree because it can only be reached by a non-browser client.
 */
function b64urlDecodeStrict(s: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) {
    refuse(PassError.Malformed, 'a segment is not unpadded base64url');
  }
  // A base64 quantum is never 1 character; Go refuses that length outright.
  if (s.length % 4 === 1) {
    refuse(PassError.Malformed, 'a segment is not a valid base64url length');
  }
  const out = Buffer.from(s, 'base64url');
  // Round-trip guard: catches a trailing character whose bits Node drops but Go rejects.
  if (b64urlEncode(out) !== s) {
    refuse(PassError.Malformed, 'a segment is not canonical unpadded base64url');
  }
  return out;
}

// --- signing ----------------------------------------------------------------------------------

/**
 * Mint a pass. `privateKeyPem` holds the cluster's Ed25519 private key, which never leaves the
 * control plane: a gate that could sign could mint itself a session for anything.
 */
export function signPass(payload: PassPayload, privateKeyPem: string | Buffer): string {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  const segment = b64urlEncode(body);
  const signed = Buffer.from(`${PASS_PREFIX}.${segment}`, 'ascii');
  const sig = nodeSign(null, signed, createPrivateKey(privateKeyPem));
  return `${PASS_PREFIX}.${segment}.${b64urlEncode(sig)}`;
}

// --- verifying --------------------------------------------------------------------------------

export interface VerifyOptions {
  /** kid to the raw 32-byte Ed25519 public key. Two entries during a rotation. */
  keys: ReadonlyMap<string, Buffer>;
  /** Unix seconds. */
  now: number;
  /** Allowed clock difference between the control plane and the cluster, in seconds. */
  skewSeconds: number;
}

/**
 * Verify a pass and return its payload.
 *
 * ORDER IS DELIBERATE: structure, then the key id's shape, then the signature, THEN semantics.
 * Nothing out of an unverified payload decides anything, and no refusal quotes unverified content
 * back in a form that could be mistaken for a fact about the caller.
 */
export function verifyPass(token: string, opts: VerifyOptions): PassPayload {
  // Size first, before the split and long before any crypto: the cheapest check goes first.
  if (Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) {
    refuse(
      PassError.Malformed,
      `a pass is at most ${MAX_TOKEN_BYTES} bytes, this is ${Buffer.byteLength(token, 'utf8')}`,
    );
  }
  const segments = token.split('.');
  if (segments.length !== 3) {
    refuse(
      PassError.Malformed,
      `a pass has exactly three dot-separated segments, this has ${segments.length}`,
    );
  }
  const [prefix, payloadSegment, signatureSegment] = segments;
  if (prefix !== PASS_PREFIX) refuse(PassError.Malformed, `a pass starts with "${PASS_PREFIX}"`);
  if (payloadSegment === '' || signatureSegment === '')
    refuse(PassError.Malformed, 'a pass has no empty segments');

  const signature = b64urlDecodeStrict(signatureSegment);
  if (signature.length !== 64) {
    // Checked separately from the verify call: a 63-byte signature is a truncation in the
    // transport, not an attacker, and an operator should be told which.
    refuse(PassError.Malformed, `an Ed25519 signature is 64 bytes, this is ${signature.length}`);
  }
  const body = b64urlDecodeStrict(payloadSegment);

  const parsed = readPayload(body);

  if (!isLowerHex(parsed.kid, 16)) {
    refuse(PassError.Payload, 'kid is 16 lowercase hex characters');
  }
  const key = opts.keys.get(parsed.kid);
  if (!key) {
    // Says nothing about which keys ARE held: an unknown kid is either a rotation this side has not
    // seen or someone guessing, and neither is helped by an inventory.
    refuse(PassError.UnknownKey, `no key with id "${safeEcho(parsed.kid)}"`);
  }

  const signed = Buffer.from(`${PASS_PREFIX}.${payloadSegment}`, 'ascii');
  const publicKey = createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), key]),
    format: 'der',
    type: 'spki',
  });
  if (!nodeVerify(null, signed, publicKey, signature)) {
    refuse(
      PassError.BadSignature,
      `the signature does not verify under key "${safeEcho(parsed.kid)}"`,
    );
  }

  // Everything past this line is trusted bytes.
  validate(parsed, opts);
  return parsed as unknown as PassPayload;
}

const REQUIRED_FIELDS = [
  'v',
  'kid',
  'jti',
  'iat',
  'exp',
  'aid',
  'cid',
  'sub',
  'kind',
  'org',
] as const;
const ALLOWED_FIELDS: ReadonlySet<string> = new Set([...REQUIRED_FIELDS, 'vm', 'ws']);
const VM_FIELDS: ReadonlySet<string> = new Set(['ns', 'name']);
const WS_FIELDS: ReadonlySet<string> = new Set(['svc', 'uid', 'user', 'dir', 'cmd']);

interface RawPayload extends Record<string, unknown> {
  kid: string;
}

function readPayload(body: Buffer): RawPayload {
  let strict;
  try {
    strict = parseStrictObject(body.toString('utf8'));
  } catch (error) {
    if (error instanceof StrictJsonError) refuse(PassError.Payload, error.message);
    throw error;
  }
  const value = strict.value;

  for (const key of Object.keys(value)) {
    if (!ALLOWED_FIELDS.has(key)) {
      // The refusal of unknown fields is what stops a smuggled "port" reaching anything downstream.
      refuse(PassError.Payload, `"${safeEcho(key)}" is not a pass field`);
    }
  }
  for (const key of REQUIRED_FIELDS) {
    if (!(key in value)) refuse(PassError.Payload, `${key} is required`);
  }
  for (const [block, allowed] of [
    ['vm', VM_FIELDS],
    ['ws', WS_FIELDS],
  ] as const) {
    const target = value[block];
    if (target === undefined) continue;
    if (typeof target !== 'object' || target === null || Array.isArray(target)) {
      refuse(PassError.Payload, `${block} is an object`);
    }
    for (const key of Object.keys(target as Record<string, unknown>)) {
      if (!allowed.has(key))
        refuse(PassError.Payload, `"${safeEcho(key)}" is not a ${block} field`);
    }
  }

  // iat and exp are checked as LITERALS, not as parsed numbers. 1.75580006e9 and 1755800060.0 parse
  // to the same JavaScript number as the integer and are refused by Go; the JSON string
  // "1755800060" is refused here and was ACCEPTED by Go until the shared vectors caught it.
  for (const field of ['iat', 'exp'] as const) {
    const literal = strict.numberLiterals.get(field);
    if (literal === undefined)
      refuse(PassError.Payload, `${field} must be a whole number of seconds`);
    if (!/^-?(0|[1-9][0-9]*)$/.test(literal))
      refuse(PassError.Payload, `${field} must be a whole number of seconds`);
    if (!Number.isSafeInteger(Number(literal)))
      refuse(PassError.Payload, `${field} is out of range`);
  }

  return value as RawPayload;
}

function validate(p: Record<string, unknown>, opts: VerifyOptions): void {
  if (p.v !== 1)
    refuse(
      PassError.Payload,
      `this is a version ${String(p.v)} pass and this reader handles version 1`,
    );
  if (!isLowerHex(p.jti, 32)) refuse(PassError.Payload, 'jti is 32 lowercase hex characters');

  for (const field of ['aid', 'cid', 'sub', 'org'] as const) {
    const value = p[field];
    if (typeof value !== 'string' || value === '')
      refuse(PassError.Payload, `${field} is required`);
    if (!isPrintableAscii(value as string)) {
      // Homoglyphs and unicode normalisation are a real path to one identity being two strings.
      refuse(PassError.Payload, `${field} must be printable ASCII`);
    }
  }
  if (typeof p.kind !== 'string' || !ALL_KINDS.has(p.kind)) {
    refuse(PassError.Payload, `"${safeEcho(String(p.kind))}" is not a session kind`);
  }

  const iat = p.iat as number;
  const exp = p.exp as number;
  if (iat <= 0 || exp <= 0) refuse(PassError.Payload, 'iat and exp must be positive');
  if (exp <= iat) refuse(PassError.Lifetime, 'exp must be after iat');
  const life = exp - iat;
  const cap = maxLifetimeSeconds(p.kind as string);
  if (life > cap)
    refuse(PassError.Lifetime, `a ${p.kind} pass may live ${cap}s, this one claims ${life}s`);

  if (opts.now > exp + opts.skewSeconds) refuse(PassError.Expired, 'this pass expired');
  if (opts.now < iat - opts.skewSeconds) refuse(PassError.Expired, 'this pass is not valid yet');

  validateTarget(p);
}

/**
 * The tenancy and target-confusion boundary.
 *
 * The gate builds a KubeVirt subresource URL out of these strings, so anything carrying a slash, a
 * dot-dot or a query string is a path-injection vector: a name of "vm-abcde/portforward/22/tcp"
 * turns a console into a tunnel. These are allowlists, because a denylist of encodings is a game
 * nobody wins.
 */
function validateTarget(p: Record<string, unknown>): void {
  const hasVM = p.vm !== undefined;
  const hasWS = p.ws !== undefined;
  const isVM = VM_KINDS.has(p.kind as string);

  if (hasVM && hasWS)
    refuse(PassError.Target, 'a pass carries exactly one target, this has both vm and ws');
  if (!hasVM && !hasWS)
    refuse(PassError.Target, 'a pass carries a target, this has neither vm nor ws');
  if (isVM && !hasVM) refuse(PassError.Target, `a ${p.kind} pass carries a vm target`);
  if (!isVM && !hasWS) refuse(PassError.Target, `a ${p.kind} pass carries a ws target`);

  if (isVM) {
    const vm = p.vm as Record<string, unknown>;
    // The namespace shape is fixed by RunOS: one namespace per VM isolation group. Pinning it to
    // that shape is what stops a signed pass naming kube-system or the gate's own namespace,
    // WITHOUT needing a list of forbidden names.
    if (typeof vm.ns !== 'string' || !isVmGroupNamespace(vm.ns)) {
      refuse(PassError.Target, `"${safeEcho(String(vm.ns))}" is not a VM group namespace`);
    }
    if (typeof vm.name !== 'string' || !isK8sName(vm.name)) {
      refuse(PassError.Target, `"${safeEcho(String(vm.name))}" is not a machine name`);
    }
    return;
  }

  const ws = p.ws as Record<string, unknown>;
  for (const field of ['svc', 'uid', 'user'] as const) {
    if (typeof ws[field] !== 'string' || ws[field] === '')
      refuse(PassError.Target, 'a ws target names svc, uid and user');
  }
  if (!isK8sName(ws.svc as string))
    refuse(PassError.Target, `"${safeEcho(String(ws.svc))}" is not a workspace service name`);
  if (!isPrintableAscii(ws.uid as string) || !isPrintableAscii(ws.user as string)) {
    refuse(PassError.Target, "a ws target's uid and user must be printable ASCII");
  }
  const dir: unknown = ws.dir ?? '';
  const cmd: unknown = ws.cmd ?? '';
  if (typeof dir !== 'string' || typeof cmd !== 'string')
    refuse(PassError.Target, "a ws target's dir and cmd are strings");
  // BYTES, not UTF-16 code units: the gate counts Go's len() and this file must agree with it, or
  // a CJK/emoji cmd is accepted by one verifier and refused by the other. See conductor's copy.
  if (
    Buffer.byteLength(dir, 'utf8') > MAX_WORKSPACE_DIR_BYTES ||
    Buffer.byteLength(cmd, 'utf8') > MAX_WORKSPACE_CMD_BYTES
  ) {
    refuse(PassError.Target, "the ws target's dir or cmd is too long");
  }
  if (dir !== '' && !isPrintableAscii(dir))
    refuse(PassError.Target, "the ws target's dir must be printable ASCII");
}

// --- shapes -----------------------------------------------------------------------------------

function isLowerHex(value: unknown, length: number): boolean {
  return typeof value === 'string' && value.length === length && /^[0-9a-f]+$/.test(value);
}

function isPrintableAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return s.length > 0;
}

function isVmGroupNamespace(s: string): boolean {
  const prefix = 'vmgroup-';
  if (!s.startsWith(prefix)) return false;
  const rest = s.slice(prefix.length);
  return rest.length >= 1 && rest.length <= 63 - prefix.length && /^[a-z0-9]+$/.test(rest);
}

/**
 * The RFC 1123 label shape Kubernetes uses for object names: lowercase alphanumerics and dashes,
 * starting and ending alphanumeric. No dots, so no traversal; no slashes, so no path injection.
 */
function isK8sName(s: string): boolean {
  if (s.length === 0 || s.length > 253) return false;
  if (s.startsWith('-') || s.endsWith('-')) return false;
  return /^[a-z0-9-]+$/.test(s);
}

/** Bound and sanitise attacker text before it reaches a log line or an error string. */
function safeEcho(s: string): string {
  let out = '';
  for (let i = 0; i < s.length && out.length < 64; i++) {
    const c = s.charCodeAt(i);
    out += c < 0x20 || c > 0x7e ? '?' : s[i];
  }
  return s.length > 64 ? `${out}...` : out;
}
