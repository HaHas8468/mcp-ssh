import { createRequire } from 'module';
import { chmod, writeFile } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { isWindows } from '../shared.mjs';

const require = createRequire(import.meta.url);

class CredentialProvider {
  constructor({ catalog, serviceName = 'mcp-ssh' } = {}) {
    this.catalog = catalog;
    this.serviceName = serviceName;
    this.keytar = undefined;
    this.askpassPath = null;
  }

  async _keytar() {
    if (this.keytar !== undefined) return this.keytar;
    try { this.keytar = require('keytar'); }
    catch { this.keytar = null; }
    return this.keytar;
  }

  async passwordFor(target, options = {}) {
    const keytar = await this._keytar();
    if (keytar) {
      try {
        const password = await keytar.getPassword(this.serviceName, target);
        if (password) return password;
      } catch { /* Keychain is optional. */ }
    }
    return this.catalog?.passwordFor(target, options) || null;
  }

  async askpassScript() {
    if (this.askpassPath) return this.askpassPath;
    const extension = isWindows ? '.cmd' : '.sh';
    const path = join(tmpdir(), `mcp-ssh-askpass-${process.pid}${extension}`);
    if (isWindows) {
      await writeFile(path, '@echo off\r\necho %MCP_SSH_PASS%\r\n', { mode: 0o700 });
    } else {
      await writeFile(path, '#!/bin/sh\nprintf %s "$MCP_SSH_PASS"\n', { mode: 0o700 });
      await chmod(path, 0o700);
    }
    this.askpassPath = path;
    return path;
  }

  async environment(target, options = {}) {
    const password = await this.passwordFor(target, options);
    if (!password) return null;
    return {
      ...process.env,
      MCP_SSH_PASS: password,
      SSH_ASKPASS: await this.askpassScript(),
      SSH_ASKPASS_REQUIRE: 'force',
    };
  }
}

export { CredentialProvider };
