import { homedir } from 'os';
import { readFile, stat, appendFile, mkdir as mkdirFs } from 'fs/promises';
import { dirname, join } from 'path';
import { existsSync } from 'fs';
import { createRequire } from 'module';
import {
  DEFAULT_SSH_CONFIG_CACHE_TTL,
  debugLog,
  isWindows,
} from './shared.mjs';

const require = createRequire(import.meta.url);
const sshConfig = require('ssh-config');

// =============================================================================
// McpConfig — loads user configuration from ~/.mcp-ssh/config.json
// =============================================================================
class McpConfig {
  constructor(configPath) {
    this.configPath = configPath || join(homedir(), '.mcp-ssh', 'config.json');
    this._config = null;
    this._defaults = {
      controlPersist: 300,
      controlPath: null, // null = auto-generate
      controlMaster: !isWindows,
      strictHostKeyChecking: 'accept-new',
      defaultTimeout: 120000,
      maxTimeout: 300000,
      maxRetries: 3,
      retryDelay: 1000,
      retryBackoffMultiplier: 2,
      maxOutputSize: 10 * 1024 * 1024,
      sshConfigCacheTtl: DEFAULT_SSH_CONFIG_CACHE_TTL,
    };
  }

  async load() {
    if (this._config !== null) return this._config;
    try {
      const content = await readFile(this.configPath, 'utf-8');
      const parsed = JSON.parse(content);
      this._config = { ...this._defaults, ...parsed };
    } catch {
      this._config = { ...this._defaults };
    }
    return this._config;
  }

  get(key) {
    return this._config ? this._config[key] : this._defaults[key];
  }

  async getAsync(key) {
    await this.load();
    return this._config[key];
  }
}

// Global config instance
const mcpConfig = new McpConfig();

// =============================================================================
// AuditLogger — persistent audit log of all operations
// =============================================================================
class AuditLogger {
  constructor(logPath) {
    this.logPath = logPath || join(homedir(), '.mcp-ssh', 'audit.log');
    this.enabled = process.env.MCP_SSH_AUDIT !== 'false';
  }

  async log(entry) {
    if (!this.enabled) return;
    try {
      await mkdirFs(dirname(this.logPath), { recursive: true });
      const record = JSON.stringify({
        timestamp: new Date().toISOString(),
        ...entry,
      }) + '\n';
      await appendFile(this.logPath, record);
    } catch (error) {
      debugLog(`Audit log write failed: ${error.message}\n`);
    }
  }
}

// =============================================================================
// PermissionGuard — per-host policy enforcement
// =============================================================================
class PermissionGuard {
  constructor(configPath) {
    this.configPath = configPath || join(homedir(), '.mcp-ssh', 'permissions.json');
    this._policies = null;
  }

  async _loadPolicies() {
    if (this._policies !== null) return;
    try {
      const content = await readFile(this.configPath, 'utf-8');
      this._policies = JSON.parse(content);
    } catch {
      this._policies = {};
    }
  }

  _matchPolicy(hostAlias) {
    if (!this._policies) return null;
    // Exact match first
    if (this._policies[hostAlias]) return this._policies[hostAlias];
    // Wildcard match
    for (const [pattern, policy] of Object.entries(this._policies)) {
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        if (regex.test(hostAlias)) return policy;
      }
    }
    return null;
  }

  async check(hostAlias, toolName, args) {
    await this._loadPolicies();
    const policy = this._matchPolicy(hostAlias);
    if (!policy) return; // No policy = allow all (backward compatible)

    // Check tool allowlist
    if (policy.allowedTools && policy.allowedTools !== '*' &&
        !policy.allowedTools.includes(toolName)) {
      throw new Error(`Tool '${toolName}' is not allowed on host '${hostAlias}' by permission policy`);
    }

    // Check deny patterns for command execution
    if (policy.denyPatterns && args?.command) {
      for (const pattern of policy.denyPatterns) {
        if (new RegExp(pattern).test(args.command)) {
          throw new Error(`Command blocked by deny pattern '${pattern}' on host '${hostAlias}'`);
        }
      }
    }
  }
}

// =============================================================================
// SSHConfigParser — enhanced SSH config parsing (backward compatible)
// =============================================================================
class SSHConfigParser {
  constructor() {
    const homeDir = homedir();
    this.configPath = join(homeDir, '.ssh', 'config');
    this.knownHostsPath = join(homeDir, '.ssh', 'known_hosts');
    this._allHostsCache = null;
    this._allHostsCacheAt = 0;
    this._configsWithPasswords = new Set();
  }

  invalidateCache() {
    this._allHostsCache = null;
    this._allHostsCacheAt = 0;
    this._configsWithPasswords = new Set();
  }

  _cloneHosts(hosts) {
    return hosts.map(host => ({ ...host }));
  }

  _cacheIsFresh(now = Date.now()) {
    const ttl = Number(mcpConfig.get('sshConfigCacheTtl') ?? DEFAULT_SSH_CONFIG_CACHE_TTL);
    return Boolean(this._allHostsCache && ttl > 0 && now - this._allHostsCacheAt < ttl);
  }

  async parseConfig() {
    try {
      const content = await readFile(this.configPath, 'utf-8');
      const config = sshConfig.parse(content);
      return this.extractHostsFromConfig(config, this.configPath);
    } catch (error) {
      debugLog(`Error reading SSH config: ${error.message}\n`);
      return [];
    }
  }

  async processIncludeDirectives(configPath) {
    try {
      const content = await readFile(configPath, 'utf-8');
      const config = sshConfig.parse(content);
      const hosts = [];

      for (const section of config) {
        if (section.param === 'Include' && section.value) {
          const includePaths = this.expandIncludePath(section.value, configPath);
          for (const includePath of includePaths) {
            const includeHosts = await this.processIncludeDirectives(includePath);
            hosts.push(...includeHosts);
          }
        }
      }

      const currentHosts = this.extractHostsFromConfig(config, configPath);
      hosts.push(...currentHosts);
      return hosts;
    } catch (error) {
      debugLog(`Error processing config file ${configPath}: ${error.message}\n`);
      return [];
    }
  }

  expandIncludePath(includePath, baseConfigPath) {
    const { dirname, resolve, isAbsolute, win32 } = require('path');
    const { glob } = require('glob');

    if (/^~(?=[\\/])/.test(includePath)) {
      includePath = includePath.replace(/^~/, homedir());
    }

    if (!isAbsolute(includePath) && !win32.isAbsolute(includePath)) {
      const baseDir = dirname(baseConfigPath);
      includePath = resolve(baseDir, includePath);
    }

    try {
      if (includePath.includes('*') || includePath.includes('?')) {
        return glob.sync(includePath).filter(path => existsSync(path));
      } else {
        return existsSync(includePath) ? [includePath] : [];
      }
    } catch (error) {
      debugLog(`Error expanding include path ${includePath}: ${error.message}\n`);
      return [];
    }
  }

  async checkFilePermissions(filePath) {
    if (isWindows) return;
    try {
      const fileStat = await stat(filePath);
      const mode = fileStat.mode & 0o777;
      if (mode !== 0o600) {
        throw new Error(
          `SSH config file ${filePath} contains @password annotations but has insecure permissions (${mode.toString(8)}). ` +
          `Required: 600. Fix with: chmod 600 ${filePath}`
        );
      }
    } catch (error) {
      if (error.code === 'ENOENT') return;
      throw error;
    }
  }

  extractHostsFromConfig(config, configPath) {
    const hosts = [];
    let hasPasswords = false;

    for (const section of config) {
      if (section.param === 'Include') continue;

      if (section.param === 'Host' && section.value !== '*') {
        const hostInfo = {
          hostname: '',
          alias: section.value,
          configFile: configPath,
        };

        for (const param of section.config) {
          if (param.type === 2 && param.content) {
            const match = param.content.match(/^#\s*@password:\s*(.+)$/);
            if (match) {
              hostInfo._password = match[1];
              hasPasswords = true;
              continue;
            }
          }

          if (!param || !param.param) continue;

          switch (param.param.toLowerCase()) {
            case 'hostname':
              hostInfo.hostname = param.value;
              break;
            case 'user':
              hostInfo.user = param.value;
              break;
            case 'port':
              hostInfo.port = parseInt(param.value, 10);
              break;
            case 'identityfile':
              hostInfo.identityFile = param.value;
              break;
            default:
              hostInfo[param.param.toLowerCase()] = param.value;
          }
        }

        if (hostInfo.hostname) {
          hosts.push(hostInfo);
        }
      }
    }

    if (hasPasswords) {
      this._configsWithPasswords.add(configPath);
    }

    return hosts;
  }

  async parseKnownHosts() {
    try {
      const content = await readFile(this.knownHostsPath, 'utf-8');
      return content.split('\n').filter(line => line.trim() !== '').map(line => {
        const parts = line.split(' ')[0];
        return parts.split(',')[0];
      });
    } catch (error) {
      if (error.code !== 'ENOENT') {
        debugLog(`Error reading known_hosts file: ${error.message}\n`);
      }
      return [];
    }
  }

  async getAllKnownHosts(options = {}) {
    const now = Date.now();
    if (!options.forceRefresh && this._cacheIsFresh(now)) {
      return this._cloneHosts(this._allHostsCache);
    }

    this._configsWithPasswords = new Set();
    const configHosts = await this.processIncludeDirectives(this.configPath);

    for (const configPath of this._configsWithPasswords) {
      await this.checkFilePermissions(configPath);
    }

    const knownHostnames = await this.parseKnownHosts();
    const allHosts = [...configHosts];

    for (const hostname of knownHostnames) {
      if (!configHosts.some(host => host.hostname === hostname || host.alias === hostname)) {
        allHosts.push({ hostname, source: 'known_hosts' });
      }
    }

    configHosts.forEach(host => { host.source = 'ssh_config'; });
    this._allHostsCache = this._cloneHosts(allHosts);
    this._allHostsCacheAt = now;
    return this._cloneHosts(allHosts);
  }
}

// =============================================================================
// RateLimiter — token bucket rate limiting per host (P2 #41)
// =============================================================================
class RateLimiter {
  constructor() {
    this.buckets = new Map();
    this.maxPerMinute = 60; // default: 60 requests per minute per host
  }

  check(hostAlias) {
    const max = mcpConfig.get('rateLimitPerMinute') || this.maxPerMinute;
    if (max <= 0) return; // 0 = disabled

    if (!this.buckets.has(hostAlias)) {
      this.buckets.set(hostAlias, { tokens: max, lastRefill: Date.now(), capacity: max });
    }
    const bucket = this.buckets.get(hostAlias);
    const now = Date.now();
    const elapsed = (now - bucket.lastRefill) / 1000;
    bucket.tokens = Math.min(bucket.capacity, bucket.tokens + elapsed * (bucket.capacity / 60));
    bucket.lastRefill = now;

    if (bucket.tokens < 1) {
      throw new Error(`Rate limit exceeded for ${hostAlias}: max ${max} requests per minute. Please retry later.`);
    }
    bucket.tokens -= 1;
  }
}

export {
  McpConfig,
  mcpConfig,
  AuditLogger,
  PermissionGuard,
  SSHConfigParser,
  RateLimiter,
};
