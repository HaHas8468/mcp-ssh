import { mkdir, chmod, writeFile, readFile, readdir, stat, rm } from 'fs/promises';
import { join } from 'path';
import { isWindows } from '../shared.mjs';

async function secureDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  if (!isWindows) await chmod(path, 0o700);
}

function outputUri(requestId, stream) {
  return `mcp-ssh://outputs/${encodeURIComponent(requestId)}/${stream}`;
}

function summarizeBuffer(value, limit) {
  const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value || '', 'utf8');
  if (buffer.length <= limit) return { content: buffer.toString('utf8'), size: buffer.length, truncated: false };
  const headSize = Math.ceil(limit / 2);
  const tailSize = Math.floor(limit / 2);
  return {
    content: undefined,
    head: buffer.subarray(0, headSize).toString('utf8'),
    tail: buffer.subarray(buffer.length - tailSize).toString('utf8'),
    size: buffer.length,
    truncated: true,
  };
}

class OutputStore {
  constructor({ directory, ttlMs = 24 * 60 * 60 * 1000, now = () => Date.now() } = {}) {
    this.directory = directory;
    this.ttlMs = ttlMs;
    this.now = now;
  }

  async save(requestId, stream, value) {
    await secureDirectory(this.directory);
    const requestDir = join(this.directory, requestId);
    await secureDirectory(requestDir);
    const path = join(requestDir, stream);
    await writeFile(path, value, { mode: 0o600 });
    if (!isWindows) await chmod(path, 0o600);
    return outputUri(requestId, stream);
  }

  async read(requestId, stream, { offset = 0, limit = 128 * 1024 } = {}) {
    if (!/^[a-f0-9-]{36}$/i.test(requestId) || !['stdout', 'stderr'].includes(stream)) {
      throw new Error('无效的输出资源标识。');
    }
    const path = join(this.directory, requestId, stream);
    const value = await readFile(path);
    const start = Math.max(0, Number(offset) || 0);
    const end = Math.min(value.length, start + Math.max(1, Number(limit) || 1));
    return { content: value.subarray(start, end).toString('utf8'), size: value.length, offset: start, truncated: end < value.length };
  }

  async cleanup() {
    try {
      const entries = await readdir(this.directory, { withFileTypes: true });
      await Promise.all(entries.filter(entry => entry.isDirectory()).map(async entry => {
        const path = join(this.directory, entry.name);
        const details = await stat(path);
        if (this.now() - details.mtimeMs <= this.ttlMs) return;
        await rm(path, { recursive: true, force: true });
      }));
    } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }
}

export { OutputStore, outputUri, summarizeBuffer };
