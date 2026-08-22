import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { GenericContainer, type StartedTestContainer } from 'testcontainers';
import { WebSocket } from 'ws';
import { readFileSync } from 'node:fs';
import { createPrivateKey } from 'node:crypto';
import path from 'path';
import { signPass, type PassPayload } from '../../lib/pass/pass';

/**
 * THE PRE-SHARED KEY IS GONE. A workspace is reached only through the in-cluster session gate,
 * which forwards the caller's signed session pass, and this container verifies that pass itself.
 * So the integration suite mints REAL passes with the golden-vector test key rather than sharing a
 * secret with the container.
 *
 * The credential still never appears in a URL. HTTP takes a bearer and the websocket takes a
 * subprotocol, because an access log and a browser history both keep query strings.
 */
const vectors = JSON.parse(
  readFileSync(path.resolve(__dirname, '../../lib/pass/testdata/passes.json'), 'utf8'),
) as { kid: string; publicKeyB64url: string; privateKeySeedB64url: string };

const privateKeyPem = createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(vectors.privateKeySeedB64url, 'base64url'),
  ]),
  format: 'der',
  type: 'pkcs8',
})
  .export({ format: 'pem', type: 'pkcs8' })
  .toString();

/** What the container is told it is. A pass naming anything else must be refused. */
const IDENTITY = { svc: 'runostty-itest', uid: 'ITest0UidRawCase1234567890ab' };
const GATE_KEYS = `${vectors.kid}=${vectors.publicKeyB64url}\n`;

let jtiCounter = 0;

/** A signed pass for this workspace. Every call gets a fresh jti, as the real mint does. */
function mintPass(overrides: Partial<PassPayload> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const p: PassPayload = {
    v: 1,
    kid: vectors.kid,
    jti: (jtiCounter++).toString(16).padStart(32, '0'),
    iat: now - 5,
    exp: now + 50,
    aid: 'rjwrn',
    cid: 'itest',
    sub: IDENTITY.uid,
    kind: 'ws.terminal',
    org: 'https://console.runos.com',
    ws: { svc: IDENTITY.svc, uid: IDENTITY.uid, user: 'dev', dir: '/home/dev', cmd: '' },
    ...overrides,
  };
  return signPass(p, privateKeyPem);
}

/** A files pass, which is the only kind the HTTP endpoints accept. */
const filesPass = () => mintPass({ kind: 'ws.files' });

const httpAuth = () => ({ headers: { Authorization: `Bearer ${filesPass()}` } });
// THE GATE'S OFFER, reproduced exactly. runostty selects `runos.tty.v1`; `runos.session.v1` is the
// gate's own client-facing protocol and means nothing here. This suite stands in for the gate, so
// it must offer what the gate offers or the handshake selects nothing and a browser would abort.
const wsProtocols = () => ['runos.tty.v1', `runos.pass.${mintPass()}`];

// A pass signed by the right key but naming SOMEONE ELSE's workspace: valid signature, wrong
// workspace, and the only thing that may refuse it is this container's own identity check.
const foreignPass = () =>
  mintPass({
    ws: {
      svc: 'runostty-someoneelse',
      uid: 'SomeoneElseUid0987654321zz',
      user: 'dev',
      dir: '/home/dev',
      cmd: '',
    },
  });

describe('server integration', () => {
  let container: StartedTestContainer;
  let baseUrl: string;
  let wsUrl: string;

  beforeAll(async () => {
    container = await GenericContainer.fromDockerfile(
      path.resolve(__dirname, '../../..'),
      'Dockerfile.test',
    )
      .build('runostty-test', { deleteOnExit: false })
      .then((image) =>
        image
          .withExposedPorts(7681)
          .withCopyContentToContainer([
            {
              content: GATE_KEYS,
              target: '/etc/runostty-gate/gate-keys',
            },
          ])
          .withEnvironment({
            GATE_KEYS_FILE: '/etc/runostty-gate/gate-keys',
            RUNOS_WORKSPACE_SVC: IDENTITY.svc,
            RUNOS_WORKSPACE_UID: IDENTITY.uid,
          })
          // Create test files for file/download endpoints
          .withCommand([
            'bash',
            '-c',
            [
              'mkdir -p /home/dev/project/myapp',
              'echo "hello world" > /home/dev/testfile.txt',
              'echo \'{"key":"value"}\' > /home/dev/data.json',
              'mkdir -p /home/dev/subdir',
              'echo "nested" > /home/dev/subdir/nested.txt',
              'echo "console.log(1)" > /home/dev/project/myapp/index.ts',
              'echo "# MyApp" > /home/dev/project/myapp/README.md',
              'chown -R dev:dev /home/dev',
              'exec node /app/dist/server.js',
            ].join(' && '),
          ])
          .start(),
      );

    const host = container.getHost();
    const port = container.getMappedPort(7681);
    baseUrl = `http://${host}:${port}`;
    wsUrl = `ws://${host}:${port}`;

    // Wait for server to be ready
    await waitForReady(baseUrl);
  }, 300_000); // 5 min timeout for container build + start

  afterAll(async () => {
    if (container) await container.stop();
  });

  // --- Health check ---

  describe('health', () => {
    it('responds to /health', async () => {
      const res = await fetch(`${baseUrl}/health`);
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body).toEqual({ status: 'ok' });
    });
  });

  // --- HTTP auth ---

  describe('HTTP authentication', () => {
    it('rejects requests without a token', async () => {
      const res = await fetch(`${baseUrl}/files`);
      expect(res.status).toBe(401);
    });

    it('refuses a token in the query string, even a currently valid one', async () => {
      const res = await fetch(`${baseUrl}/files?token=${filesPass()}`);
      expect(res.status).toBe(401);
    });

    it('accepts a bearer token in the Authorization header, with none in the URL', async () => {
      const res = await fetch(`${baseUrl}/files`, {
        headers: { Authorization: `Bearer ${filesPass()}` },
      });
      expect(res.status).toBe(200);
    });

    it('rejects a wrong bearer token', async () => {
      const res = await fetch(`${baseUrl}/files`, {
        headers: { Authorization: 'Bearer not-a-pass' },
      });
      expect(res.status).toBe(401);
    });

    it('accepts requests with a valid token', async () => {
      const res = await fetch(`${baseUrl}/files`, httpAuth());
      expect(res.status).toBe(200);
    });
  });

  // --- File listing ---

  describe('GET /files', () => {
    it('lists the dev home directory by default', async () => {
      const res = await fetch(`${baseUrl}/files`, httpAuth());
      expect(res.status).toBe(200);
      const body = (await res.json()) as Array<{ name: string; type: string }>;
      const names = body.map((e) => e.name);
      expect(names).toContain('testfile.txt');
      expect(names).toContain('data.json');
      expect(names).toContain('subdir');
      expect(names).toContain('project');
    });

    it('lists a subdirectory', async () => {
      const res = await fetch(`${baseUrl}/files?dir=/home/dev/subdir`, httpAuth());
      expect(res.status).toBe(200);
      const body = (await res.json()) as Array<{ name: string }>;
      expect(body).toHaveLength(1);
      expect(body[0].name).toBe('nested.txt');
    });

    it('returns correct types for files and dirs', async () => {
      const res = await fetch(`${baseUrl}/files`, httpAuth());
      const body = (await res.json()) as Array<{ name: string; type: string; size: number }>;
      const file = body.find((e) => e.name === 'testfile.txt');
      const dir = body.find((e) => e.name === 'subdir');
      expect(file?.type).toBe('file');
      expect(file?.size).toBeGreaterThan(0);
      expect(dir?.type).toBe('dir');
    });

    it('blocks path traversal', async () => {
      const res = await fetch(`${baseUrl}/files?dir=/home/dev/../../etc`, httpAuth());
      expect(res.status).toBe(403);
    });

    it('returns 404 for non-existent directory', async () => {
      const res = await fetch(`${baseUrl}/files?dir=/home/dev/nope`, httpAuth());
      expect(res.status).toBe(404);
    });
  });

  // --- File content ---

  describe('GET /files/content', () => {
    it('returns file content', async () => {
      const res = await fetch(`${baseUrl}/files/content?path=/home/dev/testfile.txt`, httpAuth());
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(text.trim()).toBe('hello world');
    });

    it('returns JSON file with correct content', async () => {
      const res = await fetch(`${baseUrl}/files/content?path=/home/dev/data.json`, httpAuth());
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toBe('application/json');
      const text = await res.text();
      expect(JSON.parse(text)).toEqual({ key: 'value' });
    });

    it('blocks path traversal', async () => {
      const res = await fetch(
        `${baseUrl}/files/content?path=/home/dev/../../etc/passwd`,
        httpAuth(),
      );
      expect(res.status).toBe(403);
    });

    it('returns 404 for non-existent file', async () => {
      const res = await fetch(`${baseUrl}/files/content?path=/home/dev/nope.txt`, httpAuth());
      expect(res.status).toBe(404);
    });
  });

  // --- Download ---

  describe('GET /download', () => {
    it('returns a valid tar.gz archive', async () => {
      const res = await fetch(`${baseUrl}/download?project=project/myapp`, httpAuth());
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toBe('application/gzip');
      const disposition = res.headers.get('content-disposition') || '';
      expect(disposition).toMatch(/^attachment; filename="myapp_\d{8}T\d{9}Z\.tar\.gz"$/);

      const buffer = new Uint8Array(await res.arrayBuffer());
      expect(buffer.length).toBeGreaterThan(0);
      // Verify gzip magic bytes
      expect(buffer[0]).toBe(0x1f);
      expect(buffer[1]).toBe(0x8b);
    });

    it('rejects invalid project names', async () => {
      const res = await fetch(`${baseUrl}/download?project=../../../etc`, httpAuth());
      expect(res.status).toBe(403);
    });

    it('returns 404 for non-existent project', async () => {
      const res = await fetch(`${baseUrl}/download?project=nonexistent`, httpAuth());
      expect(res.status).toBe(404);
    });
  });

  // --- WebSocket auth ---

  describe('WebSocket authentication', () => {
    it('rejects connections without a token', async () => {
      const { code } = await connectWs(`${wsUrl}/`);
      expect(code).toBe(4401);
    });

    it('rejects connections with an invalid token', async () => {
      const { code } = await connectWs(`${wsUrl}/`, ['runos.tty.v1', 'runos.pass.not-a-pass']);
      expect(code).toBe(4401);
    });

    it('refuses a query token, even a currently valid one', async () => {
      const { code } = await connectWs(`${wsUrl}/?token=${mintPass()}`);
      expect(code).toBe(4401);
    });

    it('accepts connections with a valid token and receives shell output', async () => {
      const ws = new WebSocket(`${wsUrl}/`, wsProtocols());

      const data = await new Promise<string>((resolve, reject) => {
        let output = '';
        ws.on('open', () => {
          // Send a command to get some output
          ws.send('echo __INTEGRATION_TEST__\n');
        });
        ws.on('message', (msg) => {
          output += msg.toString();
          if (output.includes('__INTEGRATION_TEST__')) {
            ws.close();
            resolve(output);
          }
        });
        ws.on('error', reject);
        setTimeout(() => {
          ws.close();
          reject(new Error('Timeout waiting for shell output'));
        }, 10_000);
      });

      expect(data).toContain('__INTEGRATION_TEST__');
    });

    // The pass travels as a subprotocol rather than a query parameter, so it stays out of the
    // ingress access log, the browser's history and any leaked Referer. These run against a real
    // handshake because the part that bites is protocol-level: a server that selects NO
    // subprotocol when the client offered one makes a browser abort the connection outright.
    it('accepts a token offered as a subprotocol, with no token in the URL', async () => {
      const ws = new WebSocket(`${wsUrl}/`, wsProtocols());

      const data = await new Promise<string>((resolve, reject) => {
        let output = '';
        ws.on('open', () => ws.send('echo __SUBPROTOCOL_AUTH__\n'));
        ws.on('message', (msg) => {
          output += msg.toString();
          if (output.includes('__SUBPROTOCOL_AUTH__')) {
            ws.close();
            resolve(output);
          }
        });
        ws.on('error', reject);
        setTimeout(() => {
          ws.close();
          reject(new Error('Timeout waiting for shell output'));
        }, 10_000);
      });

      expect(data).toContain('__SUBPROTOCOL_AUTH__');
    });

    it('selects a subprotocol, without which a browser aborts the connection', async () => {
      const ws = new WebSocket(`${wsUrl}/`, wsProtocols());
      const selected = await new Promise<string>((resolve, reject) => {
        ws.on('open', () => {
          resolve(ws.protocol);
          ws.close();
        });
        ws.on('error', reject);
        setTimeout(() => reject(new Error('Timeout waiting for open')), 10_000);
      });
      expect(selected).toBe('runos.tty.v1');
    });

    it('never echoes the pass back as the selected subprotocol', async () => {
      // The selection is returned in a response header. Echoing the token there would move the
      // secret from one log to another rather than out of them.
      const ws = new WebSocket(`${wsUrl}/`, wsProtocols());
      const selected = await new Promise<string>((resolve, reject) => {
        ws.on('open', () => {
          resolve(ws.protocol);
          ws.close();
        });
        ws.on('error', reject);
        setTimeout(() => reject(new Error('Timeout waiting for open')), 10_000);
      });
      expect(selected).toBe('runos.tty.v1');
    });

    it('rejects a wrong token offered as a subprotocol', async () => {
      const { code } = await connectWs(`${wsUrl}/`, ['runos.tty.v1', 'runos.pass.not-a-pass']);
      expect(code).toBe(4401);
    });

    /**
     * THE PROPERTY THIS WHOLE FILE EXISTS FOR. A signature proves the control plane issued the
     * pass. It does NOT prove the pass was issued for THIS workspace, and this container is the
     * only party that knows whose workspace it is. The pass below is signed by the right key, is
     * in date, and names a colleague's workspace: if it opens a session, every workspace on the
     * cluster is reachable by anyone holding any valid pass, and the gate's routing is the only
     * thing in the way.
     */
    it("refuses a perfectly valid pass that names someone else's workspace", async () => {
      const { code } = await connectWs(`${wsUrl}/`, [
        'runos.tty.v1',
        `runos.pass.${foreignPass()}`,
      ]);
      expect(code).toBe(4401);
    });
  });

  // --- WebSocket terminal resize ---

  describe('WebSocket terminal', () => {
    it('handles resize messages', async () => {
      const ws = new WebSocket(`${wsUrl}/`, wsProtocols());

      await new Promise<void>((resolve, reject) => {
        ws.on('open', () => {
          // Send a resize message — should not crash or disconnect
          ws.send(JSON.stringify({ cols: 120, rows: 40 }));
          // Send a command after resize to confirm session is alive
          ws.send('echo __RESIZE_OK__\n');
        });

        let output = '';
        ws.on('message', (msg) => {
          output += msg.toString();
          if (output.includes('__RESIZE_OK__')) {
            ws.close();
            resolve();
          }
        });
        ws.on('error', reject);
        setTimeout(() => {
          ws.close();
          reject(new Error('Timeout after resize'));
        }, 10_000);
      });
    });

    /**
     * THE LOGIN COMES FROM THE SIGNED PASS, NOT THE URL, and the URL here deliberately asks for
     * the OTHER user. Before the gate, `?user=` chose the login, so anything that could reach port
     * 7681 could pick which account it landed in. Now the only field that decides is inside the
     * bytes the control plane signed, so the query string below is ignored rather than obeyed.
     */
    it('runs as the user named in the signed pass, ignoring the one in the URL', async () => {
      const token = mintPass({
        ws: { svc: IDENTITY.svc, uid: IDENTITY.uid, user: 'devops', dir: '/home/devops', cmd: '' },
      });
      const ws = new WebSocket(`${wsUrl}/?user=dev`, ['runos.tty.v1', `runos.pass.${token}`]);

      const data = await new Promise<string>((resolve, reject) => {
        let output = '';
        ws.on('open', () => {
          ws.send('whoami\n');
        });
        ws.on('message', (msg) => {
          output += msg.toString();
          if (output.includes('devops')) {
            ws.close();
            resolve(output);
          }
        });
        ws.on('error', reject);
        setTimeout(() => {
          ws.close();
          reject(new Error('Timeout waiting for whoami'));
        }, 10_000);
      });

      expect(data).toContain('devops');
    });

    /** Same rule for the working directory: the signed pass decides, the query string does not. */
    it('starts in the directory named in the signed pass, ignoring the one in the URL', async () => {
      const token = mintPass({
        ws: {
          svc: IDENTITY.svc,
          uid: IDENTITY.uid,
          user: 'dev',
          dir: '/home/dev/project',
          cmd: '',
        },
      });
      const ws = new WebSocket(`${wsUrl}/?dir=/tmp`, ['runos.tty.v1', `runos.pass.${token}`]);

      const data = await new Promise<string>((resolve, reject) => {
        let output = '';
        ws.on('open', () => {
          ws.send('pwd\n');
        });
        ws.on('message', (msg) => {
          output += msg.toString();
          if (output.includes('/home/dev/project')) {
            ws.close();
            resolve(output);
          }
        });
        ws.on('error', reject);
        setTimeout(() => {
          ws.close();
          reject(new Error('Timeout waiting for pwd'));
        }, 10_000);
      });

      expect(data).toContain('/home/dev/project');
    });
  });
});

// --- Helpers ---

async function waitForReady(baseUrl: string, retries = 30, delayMs = 500): Promise<void> {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(`${baseUrl}/health`);
      if (res.ok) return;
    } catch {
      // Server not ready yet
    }
    await new Promise((r) => setTimeout(r, delayMs));
  }
  throw new Error('Server did not become ready');
}

function connectWs(url: string, protocols?: string[]): Promise<{ code: number; reason: string }> {
  return new Promise((resolve) => {
    const ws = new WebSocket(url, protocols);
    ws.on('close', (code, reason) => {
      resolve({ code, reason: reason.toString() });
    });
    ws.on('error', () => {
      // Error fires before close — just let close handler resolve
    });
    setTimeout(() => {
      ws.close();
      resolve({ code: 1000, reason: 'timeout' });
    }, 5_000);
  });
}
