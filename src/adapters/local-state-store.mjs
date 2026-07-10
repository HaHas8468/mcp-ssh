import { mkdir, chmod, readFile, writeFile, rename } from 'fs/promises';
import { dirname, join } from 'path';
import { randomUUID } from 'crypto';
import { isWindows } from '../shared.mjs';

async function ensureParent(path) {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  if (!isWindows) await chmod(parent, 0o700);
}

class JsonStateStore {
  constructor(path, { defaultValue = {}, now = () => Date.now() } = {}) {
    this.path = path;
    this.defaultValue = defaultValue;
    this.now = now;
    this.writeQueue = Promise.resolve();
  }

  async read() {
    try { return JSON.parse(await readFile(this.path, 'utf8')); }
    catch (error) { if (error?.code === 'ENOENT' || error instanceof SyntaxError) return structuredClone(this.defaultValue); throw error; }
  }

  async write(value) {
    this.writeQueue = this.writeQueue.then(async () => {
      await ensureParent(this.path);
      const temporary = join(dirname(this.path), `.${randomUUID()}.tmp`);
      await writeFile(temporary, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
      if (!isWindows) await chmod(temporary, 0o600);
      await rename(temporary, this.path);
      if (!isWindows) await chmod(this.path, 0o600);
    });
    return this.writeQueue;
  }

  async update(mutator) {
    this.writeQueue = this.writeQueue.then(async () => {
      const current = await this.read();
      const next = await mutator(current) || current;
      await ensureParent(this.path);
      const temporary = join(dirname(this.path), `.${randomUUID()}.tmp`);
      await writeFile(temporary, JSON.stringify(next, null, 2) + '\n', { mode: 0o600 });
      if (!isWindows) await chmod(temporary, 0o600);
      await rename(temporary, this.path);
      if (!isWindows) await chmod(this.path, 0o600);
      return next;
    });
    return this.writeQueue;
  }
}

export { JsonStateStore };
