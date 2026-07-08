#!/usr/bin/env node

/**
 * MCP SSH Agent v2.0 — A Model Context Protocol server for SSH operations
 *
 * Upgraded from v1.3.8 with:
 * - SessionManager: ControlMaster connection pooling + cwd/env state persistence
 * - Fixed exit codes, timeout remote-process cleanup, error classification
 * - SFTP-like file operations (read/write/edit/ls/stat/mkdir/rm/mv) via native ssh+base64
 * - Directory transfer (uploadDir/downloadDir), file transfer error context
 * - Security: AuditLogger, DangerousCommandDetector, PermissionGuard, Windows ACL
 * - TaskManager: background tasks, parallel execution, enhanced batch (stopOnError)
 * - Structured output with metadata (duration, signal, errorType, truncated)
 * - Enhanced tool descriptions with examples and return-format docs
 * - Progress notifications, listChanged, optional SSE transport
 */

import { homedir } from 'os';
import { readFile, stat, writeFile, chmod, unlink, appendFile, mkdir as mkdirFs } from 'fs/promises';
import { join, dirname } from 'path';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

const { spawn, exec, execFile } = require('child_process');
const { promisify } = require('util');
const { statSync, existsSync, watch } = require('fs');
const sshConfig = require('ssh-config');

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

const isWindows = process.platform === 'win32';

function resolveExecutable(name) {
  if (!isWindows) return name;
  const pathDirs = (process.env.PATH || process.env.Path || '').split(';');
  const exts = (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';');
  for (const dir of pathDirs) {
    if (!dir) continue;
    for (const ext of exts) {
      const candidate = join(dir, name + ext);
      try {
        if (statSync(candidate).isFile()) return candidate;
      } catch {}
    }
  }
  return name + '.exe';
}

const SSH_BIN = resolveExecutable('ssh');
const SCP_BIN = resolveExecutable('scp');

const SILENT_MODE = process.env.MCP_SILENT === 'true' || process.argv.includes('--silent');

function debugLog(message) {
  if (!SILENT_MODE) {
    process.stderr.write(message);
  }
}

const MAX_OUTPUT_SIZE = 10 * 1024 * 1024;
const DEFAULT_TIMEOUT = 120000;
const MAX_TIMEOUT = 300000;

// Signal name → number mapping for exit code computation
const SIGNAL_NUMBERS = {
  SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
  SIGBUS: 7, SIGFPE: 8, SIGKILL: 9, SIGUSR1: 10, SIGSEGV: 11, SIGUSR2: 12,
  SIGPIPE: 13, SIGALRM: 14, SIGTERM: 15,
};
function signalToNum(signal) {
  if (!signal) return 0;
  if (typeof signal === 'number') return signal;
  return SIGNAL_NUMBERS[signal] || 0;
}

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
// DangerousCommandDetector — pattern-based detection of risky commands
// =============================================================================
const DANGER_PATTERNS = [
  { pattern: /rm\s+-rf?\s+\/(?:\s|$|\*)/, level: 'critical', msg: '递归删除根路径' },
  { pattern: /mkfs(\.\w+)?\s+\/dev\//, level: 'critical', msg: '格式化磁盘' },
  { pattern: /dd\s+.*of=\/dev\//, level: 'critical', msg: 'dd 写入设备' },
  { pattern: /:\(\)\s*\{.*\|.*&\s*\};:/, level: 'critical', msg: 'fork 炸弹' },
  { pattern: /chmod\s+-R?\s+777\s+\//, level: 'high', msg: '全权限开放根路径' },
  { pattern: /(drop|truncate)\s+(table|database)\s/i, level: 'high', msg: '数据库删除' },
  { pattern: /systemctl\s+(stop|restart|disable)\s/, level: 'medium', msg: '服务管理' },
  { pattern: /shutdown|reboot|halt|poweroff/, level: 'high', msg: '系统关机/重启' },
  { pattern: />\s*\/dev\/sd[a-z]/, level: 'critical', msg: '覆写磁盘设备' },
  { pattern: /iptables\s+.*--flush|iptables\s+-F/, level: 'high', msg: '清空防火墙规则' },
];

function detectDangerousCommand(command) {
  for (const { pattern, level, msg } of DANGER_PATTERNS) {
    if (pattern.test(command)) {
      return { detected: true, level, message: msg, pattern: pattern.source };
    }
  }
  return { detected: false };
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
// SessionManager — ControlMaster connection pooling + session state
// =============================================================================
class SessionManager {
  constructor(config) {
    this.sessions = new Map();
    this.config = config || mcpConfig;
    // %C is a hash of connection parameters that OpenSSH expands automatically
    this.controlPath = this.config.get('controlPath') ||
      join(homedir(), '.mcp-ssh', 'cm-%C');
    this.controlPersist = this.config.get('controlPersist');
  }

  getControlArgs() {
    if (!this.config.get('controlMaster')) return [];
    return [
      '-o', 'ControlMaster=auto',
      '-o', `ControlPath=${this.controlPath}`,
      '-o', `ControlPersist=${this.controlPersist}`,
    ];
  }

  async getSession(hostAlias) {
    if (!this.sessions.has(hostAlias)) {
      this.sessions.set(hostAlias, {
        cwd: null,
        env: new Map(),
        sudoCache: null,
        lastUsed: Date.now(),
        connectionHealthy: true,
        retryCount: 0,
      });
    }
    const session = this.sessions.get(hostAlias);
    session.lastUsed = Date.now();
    return session;
  }

  // Check if the ControlMaster connection is still alive
  async checkConnection(hostAlias) {
    try {
      const { execFileAsync: execF } = require('util');
      const { promisify: prom } = require('util');
      const cp = prom(require('child_process').execFile);
      await cp(SSH_BIN, [
        '-o', `ControlPath=${this.controlPath}`,
        '-O', 'check', hostAlias,
      ], { timeout: 3000, windowsHide: true });
      return true;
    } catch {
      return false;
    }
  }

  // Mark session connection as unhealthy (triggers reconnect on next command)
  markUnhealthy(hostAlias) {
    const session = this.sessions.get(hostAlias);
    if (session) {
      session.connectionHealthy = false;
    }
  }

  markHealthy(hostAlias) {
    const session = this.sessions.get(hostAlias);
    if (session) {
      session.connectionHealthy = true;
      session.retryCount = 0;
    }
  }

  // Exponential backoff retry wrapper for connection failures
  async retryWithBackoff(fn, hostAlias, options = {}) {
    const maxRetries = options.maxRetries ?? this.config.get('maxRetries');
    const baseDelay = options.retryDelay ?? this.config.get('retryDelay');
    const multiplier = options.retryBackoffMultiplier ?? this.config.get('retryBackoffMultiplier');

    let lastError;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const result = await fn();
        // If this was a retry, mark session as healthy again
        if (attempt > 0) {
          this.markHealthy(hostAlias);
          debugLog(`Reconnected to ${hostAlias} after ${attempt} retries\n`);
        }
        return result;
      } catch (error) {
        lastError = error;
        // Only retry on connection failures, not on command failures
        const isRetryable = error?.errorType === 'connection_failed' ||
                           error?.errorType === 'timeout' ||
                           error?.errorType === 'ssh_error';
        if (!isRetryable || attempt >= maxRetries) {
          throw error;
        }
        const delay = baseDelay * Math.pow(multiplier, attempt);
        this.markUnhealthy(hostAlias);
        const session = this.sessions.get(hostAlias);
        if (session) session.retryCount = attempt + 1;
        debugLog(`Connection to ${hostAlias} failed (attempt ${attempt + 1}/${maxRetries + 1}), retrying in ${delay}ms...\n`);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    throw lastError;
  }

  buildCommandWithState(hostAlias, command) {
    const session = this.sessions.get(hostAlias);
    if (!session) return command;
    let prefix = '';
    for (const [k, v] of session.env) {
      prefix += `export ${k}=${JSON.stringify(v)}; `;
    }
    if (session.cwd) {
      prefix += `cd ${JSON.stringify(session.cwd)} && `;
    }
    return prefix + command;
  }

  updateStateFromCommand(hostAlias, command, code) {
    const session = this.sessions.get(hostAlias);
    if (!session || code !== 0) return;
    // Track cd commands
    const cdMatch = command.match(/(?:^|&&|;)\s*cd\s+([^\s;&|]+)/);
    if (cdMatch) {
      const target = cdMatch[1].replace(/^["']|["']$/g, '');
      if (target === '-') return; // cd - is complex, skip
      session.cwd = target.startsWith('/') ? target
        : session.cwd ? join(session.cwd, target) : target;
    }
    // Track export commands
    const exportMatches = command.matchAll(/export\s+(\w+)=(["']?)([^;"'\s]+)\2/g);
    for (const m of exportMatches) {
      session.env.set(m[1], m[3]);
    }
  }

  clearSession(hostAlias) {
    this.sessions.delete(hostAlias);
  }

  listSessions() {
    return Array.from(this.sessions.entries()).map(([alias, s]) => ({
      hostAlias: alias,
      cwd: s.cwd,
      envCount: s.env.size,
      lastUsed: new Date(s.lastUsed).toISOString(),
    }));
  }
}

// =============================================================================
// TaskManager — background tasks and parallel execution
// =============================================================================
class TaskManager {
  constructor() {
    this.tasks = new Map();
  }

  generateTaskId() {
    return `task_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  }

  register(hostAlias, remotePid, command, options = {}) {
    const taskId = options.taskId || this.generateTaskId();
    const logFile = options.logFile || `/tmp/mcp-task-${taskId}.log`;
    this.tasks.set(taskId, {
      hostAlias,
      remotePid,
      command,
      startedAt: Date.now(),
      logFile,
    });
    return taskId;
  }

  get(taskId) {
    return this.tasks.get(taskId) || null;
  }

  remove(taskId) {
    this.tasks.delete(taskId);
  }

  entries() {
    return Array.from(this.tasks.entries());
  }

  list() {
    return Array.from(this.tasks.entries()).map(([id, t]) => ({
      taskId: id,
      hostAlias: t.hostAlias,
      command: t.command,
      startedAt: new Date(t.startedAt).toISOString(),
      remotePid: t.remotePid,
    }));
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
      this._configsWithPasswords = this._configsWithPasswords || new Set();
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

  async getAllKnownHosts() {
    const configHosts = await this.processIncludeDirectives(this.configPath);

    if (this._configsWithPasswords) {
      for (const configPath of this._configsWithPasswords) {
        await this.checkFilePermissions(configPath);
      }
    }

    const knownHostnames = await this.parseKnownHosts();
    const allHosts = [...configHosts];

    for (const hostname of knownHostnames) {
      if (!configHosts.some(host => host.hostname === hostname || host.alias === hostname)) {
        allHosts.push({ hostname, source: 'known_hosts' });
      }
    }

    configHosts.forEach(host => { host.source = 'ssh_config'; });
    return allHosts;
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

// =============================================================================
// SSHClient — enhanced with sessions, file ops, tasks, error handling
// =============================================================================
class SSHClient {
  constructor() {
    this.configParser = new SSHConfigParser();
    this.config = mcpConfig;
    this.sessionManager = new SessionManager(this.config);
    this.taskManager = new TaskManager();
    this.auditLogger = new AuditLogger();
    this.permissionGuard = new PermissionGuard();
    this.rateLimiter = new RateLimiter();
    this._keytar = null; // lazy-loaded keytar module
    this._askpassScript = null;
    this._spawn = this._spawn || spawn;
    this._execFileAsync = execFileAsync;
    // Load config asynchronously
    this.config.load().catch(e => debugLog(`Config load failed: ${e.message}\n`));
  }

  // Lazy-load keytar for OS keychain integration (P0 #9)
  async _getKeytar() {
    if (this._keytar !== null) return this._keytar;
    try {
      this._keytar = require('keytar');
    } catch {
      this._keytar = false; // keytar not installed
    }
    return this._keytar;
  }

  async listKnownHosts() {
    return await this.configParser.getAllKnownHosts();
  }

  _assertSafeHostAlias(hostAlias) {
    if (typeof hostAlias !== 'string' || hostAlias.length === 0) {
      throw new Error('hostAlias must be a non-empty string');
    }
    if (!/^[A-Za-z0-9_.@:][A-Za-z0-9._@:-]*$/.test(hostAlias)) {
      throw new Error(
        `Invalid hostAlias: must match [A-Za-z0-9._@:-] and not start with '-'`
      );
    }
  }

  async _assertKnownHostAlias(hostAlias) {
    const cleanAlias = hostAlias.includes('@') ? hostAlias.split('@').pop() : hostAlias;
    const knownHosts = await this.configParser.getAllKnownHosts();
    const isKnown = knownHosts.some((host) =>
      host.alias === hostAlias || host.hostname === hostAlias ||
      host.alias === cleanAlias || host.hostname === cleanAlias
    );
    if (!isKnown) {
      throw new Error(`Unknown hostAlias: ${hostAlias} is not defined in ~/.ssh/config or ~/.ssh/known_hosts`);
    }
  }

  async getPasswordForHost(hostAlias) {
    // Try OS keychain first (P0 #9) — passwords stored encrypted in OS keychain
    const cleanAlias = hostAlias.includes('@') ? hostAlias.split('@').pop() : hostAlias;
    const keytar = await this._getKeytar();
    if (keytar) {
      try {
        const password = await keytar.getPassword('mcp-ssh', cleanAlias);
        if (password) return password;
      } catch (e) {
        debugLog(`Keychain lookup failed for ${cleanAlias}: ${e.message}\n`);
      }
    }

    // Legacy fallback: @password annotation in ~/.ssh/config
    const hosts = await this.configParser.processIncludeDirectives(this.configParser.configPath);
    const host = hosts.find(h => h.alias === cleanAlias || h.hostname === cleanAlias);
    return host?._password || null;
  }

  async getAskpassScript() {
    if (this._askpassScript) return this._askpassScript;

    const { tmpdir } = require('os');
    let scriptPath;
    if (isWindows) {
      scriptPath = join(tmpdir(), `mcp-ssh-askpass-${process.pid}.cmd`);
      await writeFile(scriptPath, '@echo off\r\necho %MCP_SSH_PASS%\r\n');
      // SECURITY FIX: restrict ACL to current user only (P0 #29)
      try {
        await execAsync(`icacls "${scriptPath}" /inheritance:r /grant:r "${process.env.USERNAME}:R"`);
      } catch (e) {
        debugLog(`ACL restriction failed (non-fatal): ${e.message}\n`);
      }
    } else {
      scriptPath = join(tmpdir(), `mcp-ssh-askpass-${process.pid}.sh`);
      await writeFile(scriptPath, '#!/bin/sh\necho "$MCP_SSH_PASS"\n');
      await chmod(scriptPath, 0o700);
    }
    this._askpassScript = scriptPath;

    const cleanup = () => { try { require('fs').unlinkSync(scriptPath); } catch {} };
    process.on('exit', cleanup);
    process.on('SIGINT', () => { cleanup(); process.exit(130); });
    process.on('SIGTERM', () => { cleanup(); process.exit(143); });

    return scriptPath;
  }

  async buildSpawnEnv(hostAlias) {
    const password = await this.getPasswordForHost(hostAlias);
    if (!password) return null;

    if (this.configParser._configsWithPasswords) {
      for (const configPath of this.configParser._configsWithPasswords) {
        await this.configParser.checkFilePermissions(configPath);
      }
    }

    const askpassScript = await this.getAskpassScript();
    return {
      ...process.env,
      MCP_SSH_PASS: password,
      SSH_ASKPASS: askpassScript,
      SSH_ASKPASS_REQUIRE: 'force',
    };
  }

  // ===========================================================================
  // Core: runRemoteCommand — with session state, fixed exit codes, timeout cleanup
  // ===========================================================================
  async runRemoteCommand(hostAlias, command, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);

    // Permission check
    await this.permissionGuard.check(hostAlias, 'runRemoteCommand', { command });

    // Rate limiting (P2 #41)
    this.rateLimiter.check(hostAlias);

    // Dangerous command confirmation / elicitation (P0 #18)
    const danger = detectDangerousCommand(command);
    if (danger.detected && !options.confirmed && !options.force) {
      return {
        success: false,
        confirmationRequired: true,
        danger,
        command,
        hostAlias,
        message: `Dangerous operation detected: ${danger.message}. Call again with confirmed=true to proceed.`,
      };
    }

    // Auto-reconnect with exponential backoff (P0 #19)
    const maxRetries = this.sessionManager.config.get('maxRetries');
    return this.sessionManager.retryWithBackoff(
      () => this._runRemoteCommandOnce(hostAlias, command, options).then(result => {
        // If connection failed, throw to trigger retry
        if (result.errorType === 'connection_failed' && maxRetries > 0) {
          const err = new Error(`Connection failed: ${result.stderr}`);
          err.errorType = result.errorType;
          throw err;
        }
        return result;
      }),
      hostAlias,
      { maxRetries, retryDelay: this.sessionManager.config.get('retryDelay') }
    ).catch(err => {
      // If all retries failed, return the error as a structured result
      if (err.errorType === 'connection_failed') {
        return {
          success: false,
          code: 255,
          signal: null,
          errorType: 'connection_failed',
          stdout: '',
          stderr: err.message,
          duration: 0,
          timedOut: false,
          truncated: false,
          originalStdoutSize: 0,
          originalStderrSize: 0,
          retried: true,
        };
      }
      throw err;
    });
  }

  async _runRemoteCommandOnce(hostAlias, command, options = {}) {
    const timeout = Math.min(options.timeout || this.sessionManager.config.get('defaultTimeout'),
                              this.sessionManager.config.get('maxTimeout'));
    const useSession = options.useSession !== false; // default true
    const abortSignal = options.signal || null; // MCP AbortSignal for cancellation
    const onProgress = options.onProgress || null; // MCP progress callback
    const combineOutput = options.combineOutput || false; // P0 #15: interleave stdout/stderr

    // Get or create session, build command with state
    let fullCommand = command;
    if (useSession) {
      await this.sessionManager.getSession(hostAlias);
      fullCommand = this.sessionManager.buildCommandWithState(hostAlias, command);
    }

    // Wrap command with a unique marker for timeout cleanup (P0 #3)
    const marker = `MCP_${process.pid}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const wrappedCommand = `echo ${marker}START; ${fullCommand}; echo ${marker}_RC=$?`;

    debugLog(`Executing: ssh ${hostAlias} ${fullCommand}\n`);

    const passwordEnv = await this.buildSpawnEnv(hostAlias);
    const startTime = Date.now();

    // Early abort check — don't spawn if already cancelled (P0 #16)
    if (abortSignal?.aborted) {
      return {
        success: false, code: 0, signal: null, errorType: 'cancelled',
        stdout: '', stderr: 'Request cancelled before execution',
        duration: 0, timedOut: false, truncated: false,
        originalStdoutSize: 0, originalStderrSize: 0,
      };
    }

    return new Promise((resolve) => {
      const spawnOptions = {
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        shell: false,
      };
      if (passwordEnv) {
        spawnOptions.env = passwordEnv;
        if (!isWindows) {
          spawnOptions.detached = true;
        }
      }

      // Build SSH args with ControlMaster (P0 #1) + strict host key checking
      const sshArgs = [
        ...this.sessionManager.getControlArgs(),
        '-o', `StrictHostKeyChecking=${this.sessionManager.config.get('strictHostKeyChecking')}`,
        '--', hostAlias, wrappedCommand,
      ];

      const child = this._spawn(SSH_BIN, sshArgs, spawnOptions);

      let stdout = '';
      let stderr = '';
      let timedOut = false;
      let cancelled = false;
      let stdoutTruncated = false;
      let stderrTruncated = false;
      let originalStdoutSize = 0;
      let originalStderrSize = 0;
      const outputChunks = []; // P0 #15: timestamped chunks for interleaving
      let streamLineBuffer = ''; // P1 #30: buffer for streaming complete lines

      // MCP Cancellation: listen to AbortSignal (P0 #16)
      const onAbort = () => {
        cancelled = true;
        child.kill('SIGTERM');
        setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1000);
        // Kill remote process by marker
        try {
          this._spawn(SSH_BIN, [
            ...this.sessionManager.getControlArgs(),
            '-o', 'ConnectTimeout=5',
            '--', hostAlias, `pkill -f '${marker}' 2>/dev/null; true`,
          ], { stdio: 'ignore', windowsHide: true, shell: false });
        } catch {}
      };
      if (abortSignal) {
        abortSignal.addEventListener('abort', onAbort, { once: true });
      }

      const timer = setTimeout(async () => {
        timedOut = true;
        child.kill('SIGTERM');
        // SIGKILL escalation after 1s (P0 #3)
        setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1000);
        // Kill remote process by marker (P0 #3)
        try {
          await this._spawn(SSH_BIN, [
            ...this.sessionManager.getControlArgs(),
            '-o', 'ConnectTimeout=5',
            '--', hostAlias, `pkill -f '${marker}' 2>/dev/null; true`,
          ], { stdio: 'ignore', windowsHide: true, shell: false });
        } catch {}
      }, timeout);

      child.stdout.on('data', (data) => {
        originalStdoutSize += data.length;
        const text = data.toString();
        if (stdout.length < MAX_OUTPUT_SIZE) {
          const remaining = MAX_OUTPUT_SIZE - stdout.length;
          stdout += text.slice(0, remaining);
          if (data.length > remaining) stdoutTruncated = true;
        } else if (!stdoutTruncated) {
          stdoutTruncated = true;
        }
        // P0 #15: collect timestamped chunks for interleaving
        if (combineOutput) outputChunks.push({ stream: 'stdout', text, time: Date.now() });
        // P1 #30: streaming output — send complete lines via onProgress
        if (onProgress) {
          streamLineBuffer += text;
          const lines = streamLineBuffer.split('\n');
          streamLineBuffer = lines.pop(); // keep incomplete line
          for (const line of lines) {
            onProgress(originalStdoutSize, null, line);
          }
        }
      });

      child.stderr.on('data', (data) => {
        originalStderrSize += data.length;
        const text = data.toString();
        if (stderr.length < MAX_OUTPUT_SIZE) {
          const remaining = MAX_OUTPUT_SIZE - stderr.length;
          stderr += text.slice(0, remaining);
          if (data.length > remaining) stderrTruncated = true;
        } else if (!stderrTruncated) {
          stderrTruncated = true;
        }
        // P0 #15: collect timestamped chunks for interleaving
        if (combineOutput) outputChunks.push({ stream: 'stderr', text, time: Date.now() });
      });

      child.on('close', (code, sig) => {
        clearTimeout(timer);
        if (abortSignal) abortSignal.removeEventListener('abort', onAbort);
        const duration = Date.now() - startTime;

        // Fixed exit code handling (P0 #4): null→1, signal→128+num
        let exitCode;
        if (cancelled) {
          exitCode = 130; // SIGINT-like for cancellation
        } else if (timedOut) {
          exitCode = 124;
        } else if (sig) {
          exitCode = 128 + signalToNum(sig);
        } else if (code !== null && code !== undefined) {
          exitCode = code;
        } else {
          exitCode = 1; // null without signal = unknown failure, NOT 0
        }

        // Extract real exit code from marker if present (command was wrapped)
        if (!timedOut && stdout.includes(`${marker}_RC=`)) {
          const rcMatch = stdout.match(new RegExp(`${marker}_RC=(\\d+)`));
          if (rcMatch) {
            exitCode = parseInt(rcMatch[1], 10);
          }
          // Strip marker lines from output
          stdout = stdout.replace(new RegExp(`${marker}START\\s*\n?`), '')
                         .replace(new RegExp(`${marker}_RC=\\d+\\s*\n?`), '');
        }
        stdout = stdout.replace(new RegExp(`${marker}START\\s*\n?`), '');

        // Error classification must use the marker-derived command exit code.
        const errorType = cancelled ? 'cancelled'
          : this._classifyError(exitCode, stderr, sig, timedOut);

        // Update session state (P0 #2)
        if (useSession) {
          this.sessionManager.updateStateFromCommand(hostAlias, command, exitCode);
        }

        // Audit log (P1 #27)
        this.auditLogger.log({
          tool: 'runRemoteCommand',
          hostAlias,
          command,
          code: exitCode,
          duration,
          errorType,
          timedOut,
        });

        // P1 #32: content type detection
        const contentType = this._detectContentType(stdout);

        // P0 #15: build interleaved output if requested
        let combined = undefined;
        if (combineOutput && outputChunks.length > 0) {
          combined = outputChunks
            .sort((a, b) => a.time - b.time)
            .map(c => c.text)
            .join('');
        }

        // Structured output (P0 #14)
        resolve({
          success: exitCode === 0,
          code: exitCode,
          signal: sig || null,
          errorType,
          stdout,
          stderr: timedOut ? stderr + '\n[Command timed out]' : stderr,
          combined,
          contentType,
          duration,
          timedOut,
          truncated: stdoutTruncated || stderrTruncated,
          originalStdoutSize,
          originalStderrSize,
        });
      });

      child.on('error', (error) => {
        clearTimeout(timer);
        if (abortSignal) abortSignal.removeEventListener('abort', onAbort);
        const duration = Date.now() - startTime;
        debugLog(`Error executing command on ${hostAlias}: ${error.message}\n`);
        resolve({
          success: false,
          code: 1,
          signal: null,
          errorType: 'spawn_error',
          stdout,
          stderr: error.message,
          duration,
          timedOut: false,
          truncated: false,
          originalStdoutSize,
          originalStderrSize,
        });
      });
    });
  }

  _classifyError(code, stderr, signal, timedOut) {
    if (timedOut) return 'timeout';
    if (code === 0) return null;
    if (code === 124) return 'timeout';
    if (code === 127) return 'command_not_found';
    if (code === 255) {
      const s = (stderr || '').toLowerCase();
      if (/permission denied|authenticat/i.test(s)) return 'auth_failed';
      if (/connection refused|connection timed out|unreachable|no route/i.test(s)) return 'connection_failed';
      if (/host key verification/i.test(s)) return 'host_key_mismatch';
      return 'ssh_error';
    }
    if (code >= 128) return 'killed_by_signal';
    return 'command_failed';
  }

  // P1 #32: detect output content type (binary/json/text)
  _detectContentType(str) {
    if (!str || str.length === 0) return 'empty';
    // Check for binary (null bytes or high concentration of non-printable chars)
    if (/\x00/.test(str)) return 'binary';
    let nonPrintable = 0;
    for (let i = 0; i < Math.min(str.length, 1000); i++) {
      const c = str.charCodeAt(i);
      if (c < 32 && c !== 9 && c !== 10 && c !== 13) nonPrintable++;
    }
    if (nonPrintable > 30) return 'binary';
    // Check for JSON
    const trimmed = str.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try { JSON.parse(trimmed); return 'json'; } catch {}
    }
    return 'text';
  }

  // ===========================================================================
  // Session management tools (P0 #11)
  // ===========================================================================
  async openSession(hostAlias) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);
    await this.sessionManager.getSession(hostAlias);
    // Establish the ControlMaster connection with a no-op
    const result = await this.runRemoteCommand(hostAlias, 'echo session_opened', { useSession: false });
    return {
      hostAlias,
      opened: result.success,
      cwd: null,
      env: {},
    };
  }

  async runInSession(hostAlias, command, options = {}) {
    // Same as runRemoteCommand but useSession is forced true
    return this.runRemoteCommand(hostAlias, command, { ...options, useSession: true });
  }

  async closeSession(hostAlias) {
    // Close the ControlMaster connection
    try {
      await execFileAsync(SSH_BIN, [
        '-o', `ControlPath=${this.sessionManager.controlPath}`,
        '-O', 'exit', hostAlias,
      ], { timeout: 5000, windowsHide: true });
    } catch {}
    this.sessionManager.clearSession(hostAlias);
    return { closed: true };
  }

  listSessions() {
    return this.sessionManager.listSessions();
  }

  // ===========================================================================
  // File operations via native ssh + base64 (P0 #7, #8)
  // ===========================================================================
  async readFile(hostAlias, remotePath, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);
    await this.permissionGuard.check(hostAlias, 'readFile', { remotePath });

    // Use base64 encoding for binary-safe transfer (P1 #32)
    let cmd = `base64 "${remotePath.replace(/"/g, '\\"')}"`;
    if (options.offset !== undefined || options.limit !== undefined) {
      const offset = options.offset || 0;
      const limit = options.limit ? `head -c ${options.limit}` : 'cat';
      cmd = `tail -c +${offset + 1} "${remotePath.replace(/"/g, '\\"')}" | ${limit} | base64`;
    }

    const result = await this.runRemoteCommand(hostAlias, cmd, { useSession: false });
    if (result.code !== 0) {
      return {
        success: false,
        error: result.stderr.trim() || `Failed to read file (code ${result.code})`,
        errorType: result.errorType,
      };
    }

    let content;
    try {
      content = Buffer.from(result.stdout.replace(/\s/g, ''), 'base64').toString('utf-8');
    } catch (e) {
      content = result.stdout;
    }

    return {
      success: true,
      path: remotePath,
      content,
      size: content.length,
      encoding: 'utf-8',
    };
  }

  async writeFile(hostAlias, remotePath, content, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);
    await this.permissionGuard.check(hostAlias, 'writeFile', { remotePath });

    const encoded = Buffer.from(content, 'utf-8').toString('base64');
    const escapedPath = remotePath.replace(/"/g, '\\"');

    // Pipe base64 content via stdin to remote base64 -d
    return new Promise((resolve) => {
      const spawnOptions = {
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
        shell: false,
      };

      const passwordEnvP = this.buildSpawnEnv(hostAlias);
      passwordEnvP.then((passwordEnv) => {
        if (passwordEnv) {
          spawnOptions.env = passwordEnv;
          if (!isWindows) spawnOptions.detached = true;
        }

        const modeFlag = options.mode ? ` && chmod ${options.mode} "${escapedPath}"` : '';
        const child = this._spawn(SSH_BIN, [
          ...this.sessionManager.getControlArgs(),
          '-o', `StrictHostKeyChecking=${this.sessionManager.config.get('strictHostKeyChecking')}`,
          '--', hostAlias,
          `base64 -d > "${escapedPath}"${modeFlag}`,
        ], spawnOptions);

        let stderr = '';
        child.stderr.on('data', (d) => { stderr += d.toString(); });

        const timer = setTimeout(() => {
          child.kill('SIGTERM');
          setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1000);
        }, options.timeout || DEFAULT_TIMEOUT);

        child.on('close', (code) => {
          clearTimeout(timer);
          this.auditLogger.log({
            tool: 'writeFile', hostAlias, remotePath, code, duration: 0,
          });
          resolve({
            success: code === 0,
            path: remotePath,
            bytesWritten: content.length,
            error: code !== 0 ? stderr : undefined,
          });
        });

        child.on('error', (error) => {
          clearTimeout(timer);
          resolve({ success: false, path: remotePath, error: error.message });
        });

        child.stdin.write(encoded);
        child.stdin.end();
      });
    });
  }

  async editFile(hostAlias, remotePath, edits, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);

    // Read current content
    const readResult = await this.readFile(hostAlias, remotePath);
    if (!readResult.success) {
      if (options.createIfMissing) {
        // Create empty file and proceed
        await this.writeFile(hostAlias, remotePath, '');
        return this.editFile(hostAlias, remotePath, edits, { ...options, createIfMissing: false });
      }
      return { success: false, error: readResult.error };
    }

    let content = readResult.content;
    const applied = [];
    for (const edit of edits) {
      if (!content.includes(edit.oldText)) {
        applied.push({
          found: false,
          oldText: edit.oldText.slice(0, 80),
          error: 'oldText not found in file',
        });
        continue;
      }
      const occurrences = content.split(edit.oldText).length - 1;
      content = content.replace(edit.oldText, edit.newText);
      applied.push({ found: true, occurrences, preview: this._diffPreview(edit.oldText, edit.newText) });
    }

    // Write back
    const writeResult = await this.writeFile(hostAlias, remotePath, content);
    return {
      success: writeResult.success,
      path: remotePath,
      editsApplied: applied.filter(a => a.found).length,
      editsFailed: applied.filter(a => !a.found).length,
      details: applied,
      error: writeResult.error,
    };
  }

  _diffPreview(oldText, newText) {
    const oldLines = oldText.split('\n');
    const newLines = newText.split('\n');
    const maxLines = 3;
    const preview = [];
    for (let i = 0; i < Math.min(maxLines, oldLines.length); i++) {
      preview.push(`- ${oldLines[i]}`);
    }
    for (let i = 0; i < Math.min(maxLines, newLines.length); i++) {
      preview.push(`+ ${newLines[i]}`);
    }
    return preview.join('\n');
  }

  async appendFile(hostAlias, remotePath, content) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);

    const encoded = Buffer.from(content, 'utf-8').toString('base64');
    const escapedPath = remotePath.replace(/"/g, '\\"');

    return new Promise((resolve) => {
      const spawnOptions = { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true, shell: false };
      this.buildSpawnEnv(hostAlias).then((passwordEnv) => {
        if (passwordEnv) {
          spawnOptions.env = passwordEnv;
          if (!isWindows) spawnOptions.detached = true;
        }
        const child = this._spawn(SSH_BIN, [
          ...this.sessionManager.getControlArgs(),
          '-o', `StrictHostKeyChecking=${this.sessionManager.config.get('strictHostKeyChecking')}`,
          '--', hostAlias,
          `base64 -d >> "${escapedPath}"`,
        ], spawnOptions);

        let stderr = '';
        child.stderr.on('data', (d) => { stderr += d.toString(); });

        child.on('close', (code) => {
          resolve({ success: code === 0, path: remotePath, bytesAppended: content.length, error: code !== 0 ? stderr : undefined });
        });
        child.on('error', (error) => {
          resolve({ success: false, error: error.message });
        });
        child.stdin.write(encoded);
        child.stdin.end();
      });
    });
  }

  async listDir(hostAlias, remotePath, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);

    const escapedPath = (remotePath || '.').replace(/"/g, '\\"');
    const detailed = options.detailed !== false;
    // Use find for structured output, or ls for simple
    const cmd = detailed
      ? `find "${escapedPath}" -mindepth 1 -maxdepth 1 -printf '%y|%s|%T@|%p\\n' 2>/dev/null || ls -1A "${escapedPath}"`
      : `ls -1A "${escapedPath}"`;

    const result = await this.runRemoteCommand(hostAlias, cmd);
    if (result.code !== 0) {
      return { success: false, error: result.stderr.trim(), errorType: result.errorType };
    }

    let entries;
    if (detailed && result.stdout.includes('|')) {
      entries = result.stdout.trim().split('\n').filter(Boolean).map(line => {
        const [type, size, mtime, ...pathParts] = line.split('|');
        const name = pathParts.join('|').split('/').pop();
        return {
          name,
          type: type === 'd' ? 'directory' : type === 'f' ? 'file' : type === 'l' ? 'symlink' : 'other',
          size: parseInt(size, 10) || 0,
          modifiedAt: new Date(parseInt(mtime, 10) * 1000).toISOString(),
        };
      });
    } else {
      entries = result.stdout.trim().split('\n').filter(Boolean).map(name => ({ name, type: 'unknown' }));
    }

    return { success: true, path: remotePath, entries, count: entries.length };
  }

  async stat(hostAlias, remotePath) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);

    const escapedPath = remotePath.replace(/"/g, '\\"');
    const cmd = `stat -c '%s|%a|%Y|%F' "${escapedPath}" 2>/dev/null || stat -f '%z|%Lp|%m|%HT' "${escapedPath}"`;

    const result = await this.runRemoteCommand(hostAlias, cmd);
    if (result.code !== 0) {
      return { success: false, error: result.stderr.trim(), errorType: result.errorType };
    }

    const parts = result.stdout.trim().split('|');
    return {
      success: true,
      path: remotePath,
      size: parseInt(parts[0], 10) || 0,
      mode: parts[1] || 'unknown',
      modifiedAt: parts[2] ? new Date(parseInt(parts[2], 10) * 1000).toISOString() : null,
      type: parts[3] || 'unknown',
    };
  }

  async mkdir(hostAlias, remotePath, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);
    await this.permissionGuard.check(hostAlias, 'mkdir', { remotePath });

    const parents = options.parents !== false ? '-p' : '';
    const escapedPath = remotePath.replace(/"/g, '\\"');
    const result = await this.runRemoteCommand(hostAlias, `mkdir ${parents} "${escapedPath}"`);
    return { success: result.code === 0, path: remotePath, error: result.code !== 0 ? result.stderr.trim() : undefined };
  }

  async remove(hostAlias, remotePath, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);
    await this.permissionGuard.check(hostAlias, 'remove', { remotePath });

    // Dangerous command detection (P1 #18)
    const danger = detectDangerousCommand(`rm -rf ${remotePath}`);
    if (danger.detected && !options.force) {
      return {
        success: false,
        error: `Dangerous operation detected: ${danger.message}. Set force=true to override.`,
        danger,
      };
    }

    const escapedPath = remotePath.replace(/"/g, '\\"');
    const recursive = options.recursive !== false ? '-rf' : '-f';
    const result = await this.runRemoteCommand(hostAlias, `rm ${recursive} "${escapedPath}"`);
    this.auditLogger.log({ tool: 'remove', hostAlias, remotePath, code: result.code });
    return { success: result.code === 0, path: remotePath, error: result.code !== 0 ? result.stderr.trim() : undefined };
  }

  async move(hostAlias, srcPath, destPath) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);

    const escapedSrc = srcPath.replace(/"/g, '\\"');
    const escapedDest = destPath.replace(/"/g, '\\"');
    const result = await this.runRemoteCommand(hostAlias, `mv "${escapedSrc}" "${escapedDest}"`);
    return { success: result.code === 0, srcPath, destPath, error: result.code !== 0 ? result.stderr.trim() : undefined };
  }

  // ===========================================================================
  // Enhanced file transfer (P0 #6, #25, #40)
  // ===========================================================================
  async uploadFile(hostAlias, localPath, remotePath, options = {}) {
    const startTime = Date.now();
    try {
      this._assertSafeHostAlias(hostAlias);
      await this._assertKnownHostAlias(hostAlias);
      await this.permissionGuard.check(hostAlias, 'uploadFile', { localPath, remotePath });

      // MCP Cancellation: check if already aborted (P0 #16)
      if (options.signal?.aborted) {
        return { success: false, localPath, remotePath, error: 'Cancelled before start', errorType: 'cancelled', duration: 0 };
      }

      const localStat = await stat(localPath);
      const passwordEnv = await this.buildSpawnEnv(hostAlias);
      const scpArgs = [
        ...this.sessionManager.getControlArgs(),
        '-o', `StrictHostKeyChecking=${this.sessionManager.config.get('strictHostKeyChecking')}`,
      ];
      if (options.preservePermissions) scpArgs.push('-p');
      scpArgs.push('--', localPath, `${hostAlias}:${remotePath}`);

      const execOptions = { timeout: options.timeout || 60000, windowsHide: true, shell: false };
      if (passwordEnv) execOptions.env = passwordEnv;

      // Use spawn-based approach for progress + cancellation support
      if (options.signal || options.onProgress) {
        await new Promise((resolve, reject) => {
          const child = this._spawn(SCP_BIN, scpArgs, { ...execOptions, stdio: ['ignore', 'pipe', 'pipe'] });
          let stderr = '';
          child.stderr.on('data', (d) => { stderr += d.toString(); });

          // Cancellation
          const onAbort = () => {
            child.kill('SIGTERM');
            setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1000);
          };
          if (options.signal) options.signal.addEventListener('abort', onAbort, { once: true });

          // Progress (scp doesn't give byte-level progress, but we can report completion)
          if (options.onProgress) {
            options.onProgress(0, localStat.size, 'Starting upload...');
          }

          child.on('close', (code) => {
            if (options.signal) options.signal.removeEventListener('abort', onAbort);
            if (code === 0) {
              if (options.onProgress) options.onProgress(localStat.size, localStat.size, 'Upload complete');
              resolve();
            } else {
              reject(Object.assign(new Error('scp failed'), { stderr }));
            }
          });
          child.on('error', (err) => {
            if (options.signal) options.signal.removeEventListener('abort', onAbort);
            reject(err);
          });
        });
      } else {
        await this._execFileAsync(SCP_BIN, scpArgs, execOptions);
      }

      this.auditLogger.log({ tool: 'uploadFile', hostAlias, localPath, remotePath, code: 0, duration: Date.now() - startTime });

      return {
        success: true,
        localPath,
        remotePath,
        bytesTransferred: localStat.size,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      this.auditLogger.log({ tool: 'uploadFile', hostAlias, localPath, remotePath, code: 1, error: error.message });
      return {
        success: false,
        localPath,
        remotePath,
        error: error.message,
        stderr: error.stderr || '',
        errorType: options.signal?.aborted ? 'cancelled' : this._classifyScpError(error),
        duration: Date.now() - startTime,
      };
    }
  }

  async downloadFile(hostAlias, remotePath, localPath, options = {}) {
    const startTime = Date.now();
    try {
      this._assertSafeHostAlias(hostAlias);
      await this._assertKnownHostAlias(hostAlias);
      await this.permissionGuard.check(hostAlias, 'downloadFile', { remotePath, localPath });

      const passwordEnv = await this.buildSpawnEnv(hostAlias);
      const scpArgs = [
        ...this.sessionManager.getControlArgs(),
        '-o', `StrictHostKeyChecking=${this.sessionManager.config.get('strictHostKeyChecking')}`,
      ];
      if (options.preservePermissions) scpArgs.push('-p');
      scpArgs.push('--', `${hostAlias}:${remotePath}`, localPath);

      const execOptions = { timeout: options.timeout || 60000, windowsHide: true, shell: false };
      if (passwordEnv) execOptions.env = passwordEnv;

      await this._execFileAsync(SCP_BIN, scpArgs, execOptions);

      let bytesTransferred = 0;
      try { bytesTransferred = (await stat(localPath)).size; } catch {}

      this.auditLogger.log({ tool: 'downloadFile', hostAlias, localPath, remotePath, code: 0, duration: Date.now() - startTime });

      return {
        success: true,
        localPath,
        remotePath,
        bytesTransferred,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      this.auditLogger.log({ tool: 'downloadFile', hostAlias, localPath, remotePath, code: 1, error: error.message });
      return {
        success: false,
        localPath,
        remotePath,
        error: error.message,
        stderr: error.stderr || '',
        errorType: this._classifyScpError(error),
        duration: Date.now() - startTime,
      };
    }
  }

  _classifyScpError(error) {
    const msg = ((error.message || '') + ' ' + (error.stderr || '')).toLowerCase();
    if (/no such file|not found/.test(msg)) return 'not_found';
    if (/permission denied/.test(msg)) return 'permission_denied';
    if (/no space left|disk full/.test(msg)) return 'disk_full';
    if (/connection|timeout|refused/.test(msg)) return 'connection_error';
    return 'unknown';
  }

  async uploadDir(hostAlias, localPath, remotePath, options = {}) {
    // P0 #6: directory transfer via scp -r
    return this._transferDir(hostAlias, localPath, remotePath, 'upload', options);
  }

  async downloadDir(hostAlias, remotePath, localPath, options = {}) {
    return this._transferDir(hostAlias, remotePath, localPath, 'download', options);
  }

  async _transferDir(hostAlias, srcPath, dstPath, direction, options = {}) {
    const startTime = Date.now();
    try {
      this._assertSafeHostAlias(hostAlias);
      await this._assertKnownHostAlias(hostAlias);

      const passwordEnv = await this.buildSpawnEnv(hostAlias);
      const scpArgs = [
        ...this.sessionManager.getControlArgs(),
        '-o', `StrictHostKeyChecking=${this.sessionManager.config.get('strictHostKeyChecking')}`,
        '-r', // recursive
      ];
      if (options.preservePermissions) scpArgs.push('-p');

      if (direction === 'upload') {
        scpArgs.push('--', srcPath, `${hostAlias}:${dstPath}`);
      } else {
        scpArgs.push('--', `${hostAlias}:${srcPath}`, dstPath);
      }

      const execOptions = { timeout: options.timeout || 300000, windowsHide: true, shell: false };
      if (passwordEnv) execOptions.env = passwordEnv;

      await this._execFileAsync(SCP_BIN, scpArgs, execOptions);
      this.auditLogger.log({ tool: `${direction}Dir`, hostAlias, code: 0, duration: Date.now() - startTime });

      return { success: true, direction, srcPath, dstPath, duration: Date.now() - startTime };
    } catch (error) {
      return {
        success: false,
        direction,
        srcPath,
        dstPath,
        error: error.message,
        stderr: error.stderr || '',
        errorType: this._classifyScpError(error),
        duration: Date.now() - startTime,
      };
    }
  }

  // ===========================================================================
  // Enhanced batch execution (P1 #20, #23, #33)
  // ===========================================================================
  async runCommandBatch(hostAlias, commands, options = {}) {
    const mode = options.mode || 'sequential'; // sequential | parallel | stopOnError
    const startTime = Date.now();

    if (mode === 'parallel') {
      return this._runBatchParallel(hostAlias, commands, options, startTime);
    }

    // sequential or stopOnError
    const results = [];
    let success = true;
    let firstFailure = null;

    for (let i = 0; i < commands.length; i++) {
      const result = await this.runRemoteCommand(hostAlias, commands[i], options);
      results.push({ index: i, command: commands[i], ...result });

      if (result.code !== 0) {
        success = false;
        if (!firstFailure) {
          firstFailure = { index: i, command: commands[i], errorType: result.errorType, code: result.code };
        }
        if (mode === 'stopOnError') {
          break; // P1 #23: stop on first failure
        }
      }
    }

    // P1 #33: aggregate summary
    return {
      summary: {
        total: commands.length,
        executed: results.length,
        succeeded: results.filter(r => r.code === 0).length,
        failed: results.filter(r => r.code !== 0).length,
        firstFailure,
        totalDuration: Date.now() - startTime,
      },
      results,
      success,
    };
  }

  async _runBatchParallel(hostAlias, commands, options, startTime) {
    const concurrency = Math.min(options.concurrency || 5, commands.length);
    const results = new Array(commands.length);
    let nextIndex = 0;

    async function worker(sshClient) {
      while (nextIndex < commands.length) {
        const i = nextIndex++;
        const result = await sshClient.runRemoteCommand(hostAlias, commands[i], options);
        results[i] = { index: i, command: commands[i], ...result };
      }
    }

    const workers = Array.from({ length: concurrency }, () => worker(this));
    await Promise.all(workers);

    const succeeded = results.filter(r => r && r.code === 0).length;
    const failed = results.filter(r => r && r.code !== 0).length;
    const firstFailureIdx = results.findIndex(r => r && r.code !== 0);
    const firstFailure = firstFailureIdx >= 0
      ? { index: firstFailureIdx, command: commands[firstFailureIdx], errorType: results[firstFailureIdx].errorType }
      : null;

    return {
      summary: {
        total: commands.length,
        executed: results.length,
        succeeded,
        failed,
        firstFailure,
        totalDuration: Date.now() - startTime,
        mode: 'parallel',
        concurrency,
      },
      results,
      success: failed === 0,
    };
  }

  // ===========================================================================
  // Parallel execution across hosts/commands (P1 #12)
  // ===========================================================================
  async runParallel(requests, options = {}) {
    const concurrency = Math.min(options.concurrency || 5, requests.length);
    const startTime = Date.now();
    const results = new Array(requests.length);
    let nextIndex = 0;

    async function worker() {
      while (nextIndex < requests.length) {
        const i = nextIndex++;
        const req = requests[i];
        try {
          const result = await this.runRemoteCommand(req.hostAlias, req.command, req.options || {});
          results[i] = { index: i, ...req, ...result };
        } catch (error) {
          results[i] = { index: i, ...req, success: false, code: 1, error: error.message, errorType: 'exception' };
        }
      }
    }

    const workers = Array.from({ length: concurrency }, () => worker.call(this));
    await Promise.all(workers);

    return {
      summary: {
        total: requests.length,
        succeeded: results.filter(r => r.code === 0).length,
        failed: results.filter(r => r.code !== 0).length,
        totalDuration: Date.now() - startTime,
        concurrency,
      },
      results,
    };
  }

  // ===========================================================================
  // Background tasks (P1 #13)
  // ===========================================================================
  async startBackground(hostAlias, command, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);

    const taskId = this.taskManager.generateTaskId();
    const logFile = `/tmp/mcp-task-${taskId}.log`;
    // Start with nohup, capture PID
    const wrapped = `nohup bash -c ${JSON.stringify(command)} > ${logFile} 2>&1 & echo $!`;

    const timeout = options.timeout ?? this.config.get('defaultTimeout') ?? 120000;
    const result = await this.runRemoteCommand(hostAlias, wrapped, { useSession: false, timeout });
    if (result.code !== 0) {
      return { success: false, error: result.stderr.trim(), errorType: result.errorType };
    }

    const remotePid = parseInt(result.stdout.trim(), 10);
    this.taskManager.register(hostAlias, remotePid, command, { taskId, logFile });

    this.auditLogger.log({ tool: 'startBackground', hostAlias, command, taskId, remotePid });

    return {
      success: true,
      taskId,
      remotePid,
      logFile,
      command,
      hostAlias,
    };
  }

  async getTaskStatus(taskId) {
    const task = this.taskManager.get(taskId);
    if (!task) {
      return { success: false, error: `Task ${taskId} not found` };
    }

    const checkCmd = `ps -p ${task.remotePid} -o pid,stat,etime,comm --no-headers 2>/dev/null || echo "EXITED"`;
    const checkResult = await this.runRemoteCommand(task.hostAlias, checkCmd, { useSession: false, timeout: 10000 });

    const logCmd = `tail -50 ${task.logFile} 2>/dev/null || echo "(no log yet)"`;
    const logResult = await this.runRemoteCommand(task.hostAlias, logCmd, { useSession: false, timeout: 10000 });

    const running = !checkResult.stdout.includes('EXITED');

    return {
      success: true,
      taskId,
      running,
      process: checkResult.stdout.trim(),
      recentLog: logResult.stdout,
      command: task.command,
      hostAlias: task.hostAlias,
      startedAt: new Date(task.startedAt).toISOString(),
    };
  }

  async listTasks(options = {}) {
    const statusTimeout = options.statusTimeout || 10000;
    const tasks = [];

    for (const [taskId, task] of this.taskManager.entries()) {
      const checkCmd = `ps -p ${task.remotePid} -o pid,stat,etime,comm --no-headers 2>/dev/null || echo "EXITED"`;
      try {
        const checkResult = await this.runRemoteCommand(task.hostAlias, checkCmd, { useSession: false, timeout: statusTimeout });
        const running = !checkResult.stdout.includes('EXITED');
        if (!running) {
          this.taskManager.remove(taskId);
          continue;
        }
        tasks.push({
          taskId,
          hostAlias: task.hostAlias,
          command: task.command,
          startedAt: new Date(task.startedAt).toISOString(),
          remotePid: task.remotePid,
          running,
        });
      } catch (error) {
        tasks.push({
          taskId,
          hostAlias: task.hostAlias,
          command: task.command,
          startedAt: new Date(task.startedAt).toISOString(),
          remotePid: task.remotePid,
          running: null,
          statusError: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return { tasks };
  }

  async stopTask(taskId) {
    const task = this.taskManager.get(taskId);
    if (!task) {
      return { success: false, error: `Task ${taskId} not found` };
    }

    const result = await this.runRemoteCommand(task.hostAlias, `kill ${task.remotePid} 2>/dev/null; echo done`, { useSession: false });
    this.taskManager.remove(taskId);
    this.auditLogger.log({ tool: 'stopTask', taskId, remotePid: task.remotePid });

    return { success: true, taskId, stopped: true };
  }

  // ===========================================================================
  // Existing tools (enhanced)
  // ===========================================================================
  async getHostInfo(hostAlias) {
    const hosts = await this.configParser.processIncludeDirectives(this.configParser.configPath);
    const host = hosts.find(host => host.alias === hostAlias || host.hostname === hostAlias) || null;
    if (host) {
      const { _password, ...safeHost } = host;
      if (_password) safeHost.passwordAuth = true;
      return safeHost;
    }
    return null;
  }

  async checkConnectivity(hostAlias, options = {}) {
    try {
      const timeout = options.timeout ?? 15000;
      const result = await this.runRemoteCommand(hostAlias, 'echo connected', { useSession: false, timeout });
      const connected = result.code === 0 && result.stdout.trim() === 'connected';
      return {
        connected,
        message: connected ? 'Connection successful' : 'Connection failed',
        errorType: connected ? null : result.errorType,
        latency: result.duration,
      };
    } catch (error) {
      debugLog(`Connectivity error with ${hostAlias}: ${error.message}\n`);
      return { connected: false, message: error instanceof Error ? error.message : String(error) };
    }
  }
}

// =============================================================================
// Tool definitions — 6 action-based tools (simplified from 26)
// =============================================================================
function getToolDefinitions() {
  return [
    {
      name: "ssh_hosts",
      description: `Manage SSH hosts: list known hosts, get host info, check connectivity, or list active sessions.

Actions:
- "list": List all known SSH hosts from ~/.ssh/config and ~/.ssh/known_hosts
- "info": Get detailed config for a specific host (hostname, user, port, key). Passwords never exposed.
- "check": Test SSH connectivity to a host, returns {connected, latency, errorType}
- "sessions": List active SSH sessions with their cwd and env state

Example: ssh_hosts({ action: "list" })
Example: ssh_hosts({ action: "check", hostAlias: "prod" })`,
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["list", "info", "check", "sessions"], description: "Action to perform", default: "list" },
          hostAlias: { type: "string", description: "Host alias (required for 'info' and 'check')" },
          timeout: { type: "number", description: "Connectivity check timeout ms (default: 15000, max: 300000)", default: 15000 },
        },
        required: ["action"],
      },
    },
    {
      name: "ssh_exec",
      description: `Execute commands on remote SSH host(s). Supports single command, batch (multiple commands on one host), or parallel (same command on multiple hosts).

Parameters:
- command (string): Single command to execute
- commands (array): Multiple commands — runs as batch with mode selection
- hosts (array of {hostAlias, command}): Run different commands on different hosts in parallel

Returns: { success, code, stdout, stderr, errorType, duration, contentType, ... }
- code 0=success, 124=timeout, 127=not found, 255=SSH error, 130=cancelled
- errorType: null|timeout|auth_failed|connection_failed|command_not_found|command_failed|cancelled
- Session state (cwd, env) auto-preserved between calls on same host
- Dangerous commands (rm -rf /, mkfs, etc.) require confirmed=true

Example:
- ssh_exec({ hostAlias: "prod", command: "df -h" })
- ssh_exec({ hostAlias: "prod", commands: ["cd /app", "npm test"], mode: "stopOnError" })
- ssh_exec({ hosts: [{hostAlias:"web1",command:"uptime"},{hostAlias:"web2",command:"uptime"}] })`,
      inputSchema: {
        type: "object",
        properties: {
          hostAlias: { type: "string", description: "Target host (for single/batch command)" },
          command: { type: "string", description: "Single command to execute" },
          commands: { type: "array", items: { type: "string" }, description: "Multiple commands for batch execution" },
          hosts: { type: "array", items: { type: "object", properties: { hostAlias: { type: "string" }, command: { type: "string" } }, required: ["hostAlias", "command"] }, description: "Requests for parallel execution across hosts" },
          mode: { type: "string", enum: ["sequential", "stopOnError", "parallel"], description: "Batch mode (default: sequential)", default: "sequential" },
          timeout: { type: "number", description: "Per-command timeout ms (default: 120000, max: 300000)", default: 120000 },
          combineOutput: { type: "boolean", description: "Interleave stdout+stderr by timestamp", default: false },
          confirmed: { type: "boolean", description: "Confirm dangerous operation", default: false },
          useSession: { type: "boolean", description: "Use session state (default: true)", default: true },
        },
      },
    },
    {
      name: "ssh_file",
      description: `Read, write, edit, or append remote file content via SSH (base64-encoded, binary-safe). No download/upload needed.

Actions:
- "read": Read file content. Supports offset/limit for partial reads. Returns {content, size, contentType}
- "write": Write content to file (creates/overwrites). Optional mode setting (e.g. "644", "755")
- "edit": Apply search-replace edits in-place. Use read first to see content. Returns diff preview.
- "append": Append content to file (creates if not exists)

Examples:
- ssh_file({ action: "read", hostAlias: "prod", path: "/etc/nginx/nginx.conf" })
- ssh_file({ action: "edit", hostAlias: "prod", path: "/etc/nginx/nginx.conf", edits: [{oldText:"listen 80;", newText:"listen 443 ssl;"}] })
- ssh_file({ action: "write", hostAlias: "prod", path: "/app/config.json", content: "{\\"debug\\":true}", mode: "644" })`,
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["read", "write", "edit", "append"], description: "File operation" },
          hostAlias: { type: "string", description: "Target host" },
          path: { type: "string", description: "Remote file path" },
          content: { type: "string", description: "Content to write/append (for write/append actions)" },
          edits: { type: "array", items: { type: "object", properties: { oldText: { type: "string" }, newText: { type: "string" } }, required: ["oldText", "newText"] }, description: "Search-replace edits (for edit action)" },
          mode: { type: "string", description: "File permissions e.g. '644', '755' (for write action)" },
          offset: { type: "number", description: "Byte offset to start reading (for read action)" },
          limit: { type: "number", description: "Max bytes to read (for read action)" },
          createIfMissing: { type: "boolean", description: "Create file if not exists (for edit action)", default: false },
        },
        required: ["action", "hostAlias", "path"],
      },
    },
    {
      name: "ssh_fs",
      description: `Remote filesystem operations: list directory, stat file, mkdir, remove, move.

Actions:
- "list": List directory contents. Returns structured entries {name, type, size, modifiedAt}
- "stat": Get file metadata {size, mode, modifiedAt, type}
- "mkdir": Create directory (parents=true by default, like mkdir -p)
- "rm": Remove file/directory (recursive by default). Dangerous paths require force=true.
- "mv": Move/rename file or directory

Examples:
- ssh_fs({ action: "list", hostAlias: "prod", path: "/var/log" })
- ssh_fs({ action: "mkdir", hostAlias: "prod", path: "/app/logs" })
- ssh_fs({ action: "rm", hostAlias: "prod", path: "/tmp/build", force: true })`,
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["list", "stat", "mkdir", "rm", "mv"], description: "Filesystem operation" },
          hostAlias: { type: "string", description: "Target host" },
          path: { type: "string", description: "Remote path" },
          destPath: { type: "string", description: "Destination path (for mv action)" },
          parents: { type: "boolean", description: "Create parent dirs (mkdir, default: true)", default: true },
          recursive: { type: "boolean", description: "Recursive (rm, default: true)", default: true },
          force: { type: "boolean", description: "Override danger detection (rm, default: false)", default: false },
          detailed: { type: "boolean", description: "Include size/type/modifiedAt (list, default: true)", default: true },
        },
        required: ["action", "hostAlias", "path"],
      },
    },
    {
      name: "ssh_transfer",
      description: `Transfer files between local and remote via SCP. Supports single files and directories.

Actions:
- "upload": Upload local file/dir to remote host
- "download": Download remote file/dir to local

Set recursive=true for directory transfer (uses scp -r).
Returns {success, bytesTransferred, duration} or {success:false, error, errorType, stderr} on failure.

Examples:
- ssh_transfer({ action: "upload", hostAlias: "prod", localPath: "./dist", remotePath: "/app/dist", recursive: true })
- ssh_transfer({ action: "download", hostAlias: "prod", remotePath: "/var/log/app.log", localPath: "./app.log" })`,
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["upload", "download"], description: "Transfer direction" },
          hostAlias: { type: "string", description: "Target host" },
          localPath: { type: "string", description: "Local file/directory path" },
          remotePath: { type: "string", description: "Remote file/directory path" },
          recursive: { type: "boolean", description: "Transfer directory recursively (default: false)", default: false },
          preservePermissions: { type: "boolean", description: "Preserve file permissions (scp -p, default: false)", default: false },
          timeout: { type: "number", description: "Timeout ms (default: 60000 for files, 300000 for dirs)", default: 60000 },
        },
        required: ["action", "hostAlias", "localPath", "remotePath"],
      },
    },
    {
      name: "ssh_task",
      description: `Manage background tasks on remote hosts: start long-running commands, check status, stop, or list active tasks.

Actions:
- "start": Start a command in background (via nohup). Returns {taskId, remotePid, logFile}
- "status": Check task status. Returns {running, process, recentLog (last 50 lines), startedAt}
- "stop": Stop a running background task (kills remote process)
- "list": List all active background tasks

Examples:
- ssh_task({ action: "start", hostAlias: "prod", command: "npm run build" })
- ssh_task({ action: "status", taskId: "task_12345" })
- ssh_task({ action: "list" })`,
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["start", "status", "stop", "list"], description: "Task operation" },
          hostAlias: { type: "string", description: "Target host (for start action)" },
          command: { type: "string", description: "Command to run in background (for start action)" },
          taskId: { type: "string", description: "Task ID (for status/stop actions)" },
          timeout: { type: "number", description: "Startup timeout ms for background command (default: 120000, max: 300000)", default: 120000 },
        },
        required: ["action"],
      },
    },
  ];
}
// =============================================================================
// Main — MCP server setup with all tools
// =============================================================================
async function main() {
  try {
    debugLog("Initializing SSH client (v2.0)...\n");
    const sshClient = new SSHClient();

    debugLog("Creating MCP server...\n");
    const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
    const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
    const { CallToolRequestSchema, ListToolsRequestSchema, ListResourcesRequestSchema, ReadResourceRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

    const server = new Server(
      { name: "mcp-ssh", version: "2.0.0" },
      { capabilities: { tools: {}, resources: {} } }
    );

    // listChanged: watch SSH config for changes (P1 #36)
    try {
      const configDir = join(homedir(), '.ssh');
      watch(configDir, (eventType, filename) => {
        if (filename && (filename === 'config' || filename === 'known_hosts')) {
          debugLog(`SSH config changed: ${filename}, notifying clients...\n`);
          try {
            server.notification({ method: "notifications/tools/list_changed" });
          } catch {}
        }
      });
    } catch (e) {
      debugLog(`Config watch failed (non-fatal): ${e.message}\n`);
    }

    // P2 #43: MCP Resources — expose host list as resources
    server.setRequestHandler(ListResourcesRequestSchema, async () => {
      const hosts = await sshClient.listKnownHosts();
      return {
        resources: hosts
          .filter(h => h.alias || h.hostname)
          .map(h => ({
            uri: `ssh://hosts/${encodeURIComponent(h.alias || h.hostname)}`,
            name: h.alias || h.hostname,
            description: `SSH host: ${h.hostname}${h.user ? ` (user: ${h.user})` : ''}${h.port ? ` port: ${h.port}` : ''}`,
            mimeType: "application/json",
          })),
      };
    });

    server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const uri = request.params.uri;
      const match = uri.match(/^ssh:\/\/hosts\/(.+)$/);
      if (!match) {
        throw new Error(`Unknown resource URI: ${uri}`);
      }
      const hostAlias = decodeURIComponent(match[1]);
      const info = await sshClient.getHostInfo(hostAlias);
      if (!info) {
        throw new Error(`Host not found: ${hostAlias}`);
      }
      return {
        contents: [{
          uri,
          mimeType: "application/json",
          text: JSON.stringify(info, null, 2),
        }],
      };
    });

    server.setRequestHandler(ListToolsRequestSchema, async () => {
      return { tools: getToolDefinitions() };
    });

    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const { name, arguments: args } = request.params;
      debugLog(`Received callTool request for tool: ${name} (action: ${args?.action || 'n/a'})\n`);

      // MCP Cancellation: extract AbortSignal from extra
      const abortSignal = extra?.signal || null;

      // MCP Progress: extract progressToken and sendNotification
      const progressToken = request.params?._meta?.progressToken || null;
      const sendNotification = extra?.sendNotification || null;
      const onProgress = (progressToken && sendNotification)
        ? (progress, total, message) => {
            sendNotification({
              method: "notifications/progress",
              params: { progressToken, progress, total: total ?? null, message: message ?? undefined },
            }).catch(() => {});
          }
        : null;

      if (!args) {
        throw new Error(`No arguments provided for tool: ${name}`);
      }

      try {
        let result;
        const action = args.action;

        switch (name) {
          // ===================================================================
          // ssh_hosts — list | info | check | sessions
          // ===================================================================
          case "ssh_hosts": {
            if (action === 'list' || !action) {
              const hosts = await sshClient.listKnownHosts();
              result = hosts.map(({ _password, ...host }) => {
                if (_password) host.passwordAuth = true;
                return host;
              });
            } else if (action === 'info') {
              result = await sshClient.getHostInfo(args.hostAlias);
            } else if (action === 'check') {
              result = await sshClient.checkConnectivity(args.hostAlias, { timeout: args.timeout });
            } else if (action === 'sessions') {
              result = sshClient.listSessions();
            } else {
              throw new Error(`Unknown action '${action}' for ssh_hosts. Use: list, info, check, sessions`);
            }
            break;
          }

          // ===================================================================
          // ssh_exec — single | batch | parallel
          // ===================================================================
          case "ssh_exec": {
            if (args.hosts) {
              // Parallel: multiple hosts
              result = await sshClient.runParallel(args.hosts, { concurrency: args.concurrency || 5 });
            } else if (args.commands) {
              // Batch: multiple commands on one host
              result = await sshClient.runCommandBatch(args.hostAlias, args.commands, {
                mode: args.mode || 'sequential', timeout: args.timeout,
                concurrency: args.concurrency,
              });
            } else if (args.command) {
              // Single command
              result = await sshClient.runRemoteCommand(args.hostAlias, args.command, {
                timeout: args.timeout, useSession: args.useSession,
                combineOutput: args.combineOutput, confirmed: args.confirmed,
                signal: abortSignal, onProgress,
              });
            } else {
              throw new Error('ssh_exec requires one of: command, commands, or hosts');
            }
            break;
          }

          // ===================================================================
          // ssh_file — read | write | edit | append
          // ===================================================================
          case "ssh_file": {
            if (action === 'read') {
              result = await sshClient.readFile(args.hostAlias, args.path, { offset: args.offset, limit: args.limit });
            } else if (action === 'write') {
              result = await sshClient.writeFile(args.hostAlias, args.path, args.content, { mode: args.mode });
            } else if (action === 'edit') {
              result = await sshClient.editFile(args.hostAlias, args.path, args.edits, { createIfMissing: args.createIfMissing });
            } else if (action === 'append') {
              result = await sshClient.appendFile(args.hostAlias, args.path, args.content);
            } else {
              throw new Error(`Unknown action '${action}' for ssh_file. Use: read, write, edit, append`);
            }
            break;
          }

          // ===================================================================
          // ssh_fs — list | stat | mkdir | rm | mv
          // ===================================================================
          case "ssh_fs": {
            if (action === 'list') {
              result = await sshClient.listDir(args.hostAlias, args.path, { detailed: args.detailed });
            } else if (action === 'stat') {
              result = await sshClient.stat(args.hostAlias, args.path);
            } else if (action === 'mkdir') {
              result = await sshClient.mkdir(args.hostAlias, args.path, { parents: args.parents });
            } else if (action === 'rm') {
              result = await sshClient.remove(args.hostAlias, args.path, { recursive: args.recursive, force: args.force });
            } else if (action === 'mv') {
              result = await sshClient.move(args.hostAlias, args.path, args.destPath);
            } else {
              throw new Error(`Unknown action '${action}' for ssh_fs. Use: list, stat, mkdir, rm, mv`);
            }
            break;
          }

          // ===================================================================
          // ssh_transfer — upload | download
          // ===================================================================
          case "ssh_transfer": {
            const opts = { preservePermissions: args.preservePermissions, timeout: args.timeout, signal: abortSignal, onProgress };
            if (action === 'upload') {
              result = args.recursive
                ? await sshClient.uploadDir(args.hostAlias, args.localPath, args.remotePath, opts)
                : await sshClient.uploadFile(args.hostAlias, args.localPath, args.remotePath, opts);
            } else if (action === 'download') {
              result = args.recursive
                ? await sshClient.downloadDir(args.hostAlias, args.remotePath, args.localPath, opts)
                : await sshClient.downloadFile(args.hostAlias, args.remotePath, args.localPath, opts);
            } else {
              throw new Error(`Unknown action '${action}' for ssh_transfer. Use: upload, download`);
            }
            break;
          }

          // ===================================================================
          // ssh_task — start | status | stop | list
          // ===================================================================
          case "ssh_task": {
            if (action === 'start') {
              result = await sshClient.startBackground(args.hostAlias, args.command, { timeout: args.timeout });
            } else if (action === 'status') {
              result = await sshClient.getTaskStatus(args.taskId);
            } else if (action === 'stop') {
              result = await sshClient.stopTask(args.taskId);
            } else if (action === 'list' || !action) {
              result = await sshClient.listTasks();
            } else {
              throw new Error(`Unknown action '${action}' for ssh_task. Use: start, status, stop, list`);
            }
            break;
          }

          default:
            throw new Error(`Unknown tool: ${name}. Available: ssh_hosts, ssh_exec, ssh_file, ssh_fs, ssh_transfer, ssh_task`);
        }

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        debugLog(`Error executing tool ${name}: ${error.message}\n`);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : String(error),
              errorType: 'tool_error',
            }, null, 2),
          }],
        };
      }
    });

    // Transport selection: STDIO (default) or SSE (P1 #35)
    const transportType = process.env.MCP_TRANSPORT || 'stdio';
    let transport;

    if (transportType === 'sse') {
      try {
        const { SSEServerTransport } = require('@modelcontextprotocol/sdk/server/sse.js');
        const port = parseInt(process.env.MCP_PORT || '3000', 10);
        transport = new SSEServerTransport(port);
        debugLog(`Starting MCP SSH Agent on SSE port ${port}...\n`);
      } catch (e) {
        debugLog(`SSE transport not available, falling back to STDIO: ${e.message}\n`);
        transport = new StdioServerTransport();
      }
    } else {
      transport = new StdioServerTransport();
    }

    await server.connect(transport);
    debugLog("MCP SSH Agent v2.0 connected and ready!\n");

  } catch (error) {
    debugLog(`Error starting MCP SSH Agent: ${error.message}\n`);
    process.exit(1);
  }
}

export { SSHConfigParser, SSHClient, SessionManager, TaskManager, AuditLogger, PermissionGuard, McpConfig, RateLimiter, detectDangerousCommand, debugLog, main };
