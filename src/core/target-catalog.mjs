import { readFile, stat } from 'fs/promises';
import { existsSync } from 'fs';
import { dirname, isAbsolute, resolve } from 'path';
import { homedir } from 'os';
import { createRequire } from 'module';
import { assertTargetId, TARGET_ID_RE, configFingerprint, parseSshG } from '../domain/target.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';
import { throwIfAborted } from './operation-control.mjs';

const require = createRequire(import.meta.url);
const { globSync } = require('glob');

function isExplicitHost(name) {
  return TARGET_ID_RE.test(name) && !/[*!?]/.test(name) && !name.startsWith('-');
}

function unquote(value) {
  const trimmed = String(value || '').trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function parseConfigText(content, source) {
  const aliases = [];
  const includes = [];
  const passwords = new Map();
  let currentHosts = [];
  let lastHost = null;
  for (const rawLine of String(content).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const password = rawLine.match(/^\s*#\s*@password:\s*(.+?)\s*$/i);
    if (password && lastHost) {
      for (const host of lastHost) passwords.set(host, { password: password[1], source });
      continue;
    }
    if (line.startsWith('#')) continue;
    const match = line.match(/^(\S+)\s+(.+)$/);
    if (!match) continue;
    const keyword = match[1].toLowerCase();
    const value = unquote(match[2]);
    if (keyword === 'host') {
      currentHosts = value.split(/\s+/).filter(isExplicitHost);
      aliases.push(...currentHosts.map(id => ({ id, source })));
      lastHost = currentHosts;
    } else if (keyword === 'include') {
      includes.push({ value, source });
      currentHosts = [];
      lastHost = null;
    } else if (keyword === 'match') {
      currentHosts = [];
      lastHost = null;
    }
  }
  return { aliases, includes, passwords };
}

class TargetCatalog {
  constructor({ adapter, config, configPath = resolve(homedir(), '.ssh', 'config'), now = () => Date.now() } = {}) {
    this.adapter = adapter;
    this.config = config;
    this.configPath = configPath;
    this.now = now;
    this.cache = null;
    this.cacheAt = 0;
    this.effectiveCache = new Map();
    this.onInvalidate = new Set();
  }

  subscribe(listener) {
    this.onInvalidate.add(listener);
    return () => this.onInvalidate.delete(listener);
  }

  invalidate() {
    this.cache = null;
    this.cacheAt = 0;
    this.effectiveCache.clear();
    for (const listener of this.onInvalidate) listener();
  }

  async _fresh() {
    const ttl = (await this.config.load()).sshConfigCacheTtlMs;
    return this.cache && this.now() - this.cacheAt < ttl;
  }

  async _scanFile(path, visited, entries, passwords, sources, options = {}) {
    throwIfAborted({ ...options, phase: 'resolve' });
    const absolute = resolve(path);
    if (visited.has(absolute)) return;
    visited.add(absolute);
    let content;
    try { content = await readFile(absolute, 'utf8'); }
    catch (error) {
      if (absolute === resolve(this.configPath) && error?.code !== 'ENOENT') {
        throw new OperationFailure(ERROR_CODES.SSH_CONFIG_INVALID, `无法读取 SSH 配置：${error.message}`, { phase: 'resolve' });
      }
      return;
    }
    sources.add(absolute);
    const parsed = parseConfigText(content, absolute);
    for (const entry of parsed.aliases) if (!entries.has(entry.id)) entries.set(entry.id, entry);
    for (const [id, value] of parsed.passwords) passwords.set(id, value);
    for (const include of parsed.includes) {
      // OpenSSH accepts more than one Include path on a single directive.
      for (const pattern of include.value.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || []) {
        for (const includePath of this._expandInclude(unquote(pattern), absolute)) {
          await this._scanFile(includePath, visited, entries, passwords, sources, options);
        }
      }
    }
  }

  _expandInclude(pattern, source) {
    let target = pattern.replace(/^~(?=[/\\])/, homedir());
    if (!isAbsolute(target)) target = resolve(dirname(source), target);
    if (/[*?[]/.test(target)) return globSync(target, { nodir: true }).sort();
    return existsSync(target) ? [target] : [];
  }

  async list(options = {}) {
    throwIfAborted({ ...options, phase: 'resolve' });
    if (await this._fresh()) return this.cache.targets.map(target => ({ ...target }));
    const entries = new Map();
    const passwords = new Map();
    const sources = new Set();
    await this._scanFile(this.configPath, new Set(), entries, passwords, sources, options);
    throwIfAborted({ ...options, phase: 'resolve' });
    const targets = [...entries.values()].sort((a, b) => a.id.localeCompare(b.id));
    this.cache = { targets, passwords, sources };
    this.cacheAt = this.now();
    // A TTL refresh is also a configuration boundary. Do not retain an
    // effective ssh -G result (and therefore an old ControlMaster key) after it.
    this.effectiveCache.clear();
    return targets.map(target => ({ ...target }));
  }

  async assertAllowed(target, options = {}) {
    assertTargetId(target);
    const targets = await this.list(options);
    if (!targets.some(entry => entry.id === target)) {
      throw new OperationFailure(ERROR_CODES.TARGET_NOT_FOUND, `目标 '${target}' 未在 SSH 配置中显式定义。`, {
        phase: 'resolve', hint: '请在 ~/.ssh/config 或其 Include 文件中添加明确的 Host 别名。',
      });
    }
    return target;
  }

  async effective(target, options = {}) {
    await this.assertAllowed(target, options);
    const cached = this.effectiveCache.get(target);
    if (cached && await this._fresh()) return cached;
    let resolved;
    try { resolved = await this.adapter.resolve(target, options); }
    catch (error) {
      if (error instanceof OperationFailure) throw error;
      throw new OperationFailure(ERROR_CODES.SSH_CONFIG_INVALID, `无法解析 SSH 目标 '${target}'：${error.message}`, { phase: 'resolve', cause: error });
    }
    const raw = String(resolved.stdout || '');
    if (!raw.trim()) {
      throw new OperationFailure(ERROR_CODES.SSH_CONFIG_INVALID, `ssh -G 未返回 '${target}' 的有效配置。`, { phase: 'resolve' });
    }
    const value = { id: target, raw, config: parseSshG(raw), fingerprint: configFingerprint(raw) };
    this.effectiveCache.set(target, value);
    return value;
  }

  async passwordFor(target, options = {}) {
    await this.list(options);
    const entry = this.cache.passwords.get(target);
    if (!entry) return null;
    try {
      const details = await stat(entry.source);
      if (process.platform !== 'win32' && (details.mode & 0o777) !== 0o600) {
        throw new OperationFailure(ERROR_CODES.SSH_CONFIG_INVALID, `包含 @password 的 SSH 配置权限必须为 0600：${entry.source}`, { phase: 'resolve' });
      }
    } catch (error) {
      if (error instanceof OperationFailure) throw error;
      return null;
    }
    return entry.password;
  }

  async sources() {
    await this.list();
    return [...this.cache.sources];
  }
}

export { TargetCatalog, isExplicitHost, parseConfigText };
