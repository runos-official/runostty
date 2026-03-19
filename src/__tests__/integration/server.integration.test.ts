import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { GenericContainer, type StartedTestContainer } from 'testcontainers';
import { WebSocket } from 'ws';
import path from 'path';

const PSK = 'test-psk-token-12345';
const INVALID_PSK = 'wrong-token';

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
              content: PSK,
              target: '/etc/runostty/psk',
            },
          ])
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

    it('rejects requests with an invalid token', async () => {
      const res = await fetch(`${baseUrl}/files?token=${INVALID_PSK}`);
      expect(res.status).toBe(401);
    });

    it('accepts requests with a valid token', async () => {
      const res = await fetch(`${baseUrl}/files?token=${PSK}`);
      expect(res.status).toBe(200);
    });
  });

  // --- File listing ---

  describe('GET /files', () => {
    it('lists the dev home directory by default', async () => {
      const res = await fetch(`${baseUrl}/files?token=${PSK}`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as Array<{ name: string; type: string }>;
      const names = body.map((e) => e.name);
      expect(names).toContain('testfile.txt');
      expect(names).toContain('data.json');
      expect(names).toContain('subdir');
      expect(names).toContain('project');
    });

    it('lists a subdirectory', async () => {
      const res = await fetch(`${baseUrl}/files?token=${PSK}&dir=/home/dev/subdir`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as Array<{ name: string }>;
      expect(body).toHaveLength(1);
      expect(body[0].name).toBe('nested.txt');
    });

    it('returns correct types for files and dirs', async () => {
      const res = await fetch(`${baseUrl}/files?token=${PSK}`);
      const body = (await res.json()) as Array<{ name: string; type: string; size: number }>;
      const file = body.find((e) => e.name === 'testfile.txt');
      const dir = body.find((e) => e.name === 'subdir');
      expect(file?.type).toBe('file');
      expect(file?.size).toBeGreaterThan(0);
      expect(dir?.type).toBe('dir');
    });

    it('blocks path traversal', async () => {
      const res = await fetch(`${baseUrl}/files?token=${PSK}&dir=/home/dev/../../etc`);
      expect(res.status).toBe(403);
    });

    it('returns 404 for non-existent directory', async () => {
      const res = await fetch(`${baseUrl}/files?token=${PSK}&dir=/home/dev/nope`);
      expect(res.status).toBe(404);
    });
  });

  // --- File content ---

  describe('GET /files/content', () => {
    it('returns file content', async () => {
      const res = await fetch(`${baseUrl}/files/content?token=${PSK}&path=/home/dev/testfile.txt`);
      expect(res.status).toBe(200);
      const text = await res.text();
      expect(text.trim()).toBe('hello world');
    });

    it('returns JSON file with correct content', async () => {
      const res = await fetch(`${baseUrl}/files/content?token=${PSK}&path=/home/dev/data.json`);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toBe('application/json');
      const text = await res.text();
      expect(JSON.parse(text)).toEqual({ key: 'value' });
    });

    it('blocks path traversal', async () => {
      const res = await fetch(
        `${baseUrl}/files/content?token=${PSK}&path=/home/dev/../../etc/passwd`,
      );
      expect(res.status).toBe(403);
    });

    it('returns 404 for non-existent file', async () => {
      const res = await fetch(`${baseUrl}/files/content?token=${PSK}&path=/home/dev/nope.txt`);
      expect(res.status).toBe(404);
    });
  });

  // --- Download ---

  describe('GET /download', () => {
    it('returns a valid tar.gz archive', async () => {
      const res = await fetch(`${baseUrl}/download?token=${PSK}&project=project/myapp`);
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
      const res = await fetch(`${baseUrl}/download?token=${PSK}&project=../../../etc`);
      expect(res.status).toBe(403);
    });

    it('returns 404 for non-existent project', async () => {
      const res = await fetch(`${baseUrl}/download?token=${PSK}&project=nonexistent`);
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
      const { code } = await connectWs(`${wsUrl}/?token=${INVALID_PSK}`);
      expect(code).toBe(4401);
    });

    it('accepts connections with a valid token and receives shell output', async () => {
      const ws = new WebSocket(`${wsUrl}/?token=${PSK}`);

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
  });

  // --- WebSocket terminal resize ---

  describe('WebSocket terminal', () => {
    it('handles resize messages', async () => {
      const ws = new WebSocket(`${wsUrl}/?token=${PSK}`);

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

    it('connects as devops user when specified', async () => {
      const ws = new WebSocket(`${wsUrl}/?token=${PSK}&user=devops`);

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

    it('uses specified working directory', async () => {
      const ws = new WebSocket(`${wsUrl}/?token=${PSK}&dir=/home/dev/project`);

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

function connectWs(url: string): Promise<{ code: number; reason: string }> {
  return new Promise((resolve) => {
    const ws = new WebSocket(url);
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
