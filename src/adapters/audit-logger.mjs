import { appendFile, chmod, mkdir } from 'fs/promises';
import { dirname } from 'path';
import { isWindows } from '../shared.mjs';

class AuditLogger {
  constructor({ path, enabled = process.env.MCP_SSH_AUDIT !== 'false' } = {}) {
    this.path = path;
    this.enabled = enabled;
  }

  async log(entry) {
    if (!this.enabled || !this.path) return;
    try {
      const directory = dirname(this.path);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      if (!isWindows) await chmod(directory, 0o700);
      // Callers only supply operation metadata. Never serialize command text,
      // environment values, file body, output, password, or raw SSH stderr.
      await appendFile(this.path, `${JSON.stringify({ at: new Date().toISOString(), ...entry })}\n`, { mode: 0o600 });
      if (!isWindows) await chmod(this.path, 0o600);
    } catch {
      // Auditing must never disclose or replace the original operation error.
    }
  }
}

export { AuditLogger };
