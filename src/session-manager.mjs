import { homedir } from 'os';
import { join } from 'path';
import { createRequire } from 'module';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { mcpConfig } from './config.mjs';
import { SSH_BIN, debugLog, shQuote } from './shared.mjs';

const require = createRequire(import.meta.url);
const execFileAsync = promisify(execFile);

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

  async resetControlMaster(hostAlias, reason = '') {
    if (!this.config.get('controlMaster')) {
      return { attempted: false, ok: false, reason: 'ControlMaster disabled' };
    }

    try {
      await execFileAsync(SSH_BIN, [
        '-o', `ControlPath=${this.controlPath}`,
        '-O', 'exit', hostAlias,
      ], { timeout: 5000, windowsHide: true });
      this.markUnhealthy(hostAlias);
      return { attempted: true, ok: true, reason };
    } catch (error) {
      this.markUnhealthy(hostAlias);
      return {
        attempted: true,
        ok: false,
        reason,
        error: error instanceof Error ? error.message : String(error),
        stderr: error?.stderr || '',
      };
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

  snapshot(hostAlias) {
    const session = this.sessions.get(hostAlias);
    if (!session) return null;
    return {
      cwd: session.cwd,
      env: Object.fromEntries(session.env.entries()),
      envCount: session.env.size,
      connectionHealthy: session.connectionHealthy,
      retryCount: session.retryCount,
      lastUsed: new Date(session.lastUsed).toISOString(),
    };
  }

  diffSnapshots(before, after) {
    if (!before && !after) return {};
    const beforeEnv = before?.env || {};
    const afterEnv = after?.env || {};
    const envAdded = {};
    const envChanged = {};
    const envRemoved = [];

    for (const [key, value] of Object.entries(afterEnv)) {
      if (!(key in beforeEnv)) {
        envAdded[key] = value;
      } else if (beforeEnv[key] !== value) {
        envChanged[key] = { before: beforeEnv[key], after: value };
      }
    }
    for (const key of Object.keys(beforeEnv)) {
      if (!(key in afterEnv)) envRemoved.push(key);
    }

    return {
      cwdChanged: (before?.cwd || null) !== (after?.cwd || null),
      cwdBefore: before?.cwd || null,
      cwdAfter: after?.cwd || null,
      envAdded,
      envChanged,
      envRemoved,
    };
  }

  // Exponential backoff retry wrapper for connection failures
  async retryWithBackoff(fn, hostAlias, options = {}) {
    const maxRetries = options.maxRetries ?? this.config.get('maxRetries');
    const baseDelay = options.retryDelay ?? this.config.get('retryDelay');
    const multiplier = options.retryBackoffMultiplier ?? this.config.get('retryBackoffMultiplier');

    let lastError;
    let controlResetDone = false;
    const recoveryActions = [];
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        const result = await fn();
        // If this was a retry, mark session as healthy again
        if (attempt > 0) {
          this.markHealthy(hostAlias);
          if (result && typeof result === 'object') {
            result.retried = true;
            result.retryAttempts = attempt;
            result.recoveryActions = recoveryActions;
          }
          debugLog(`Reconnected to ${hostAlias} after ${attempt} retries\n`);
        }
        return result;
      } catch (error) {
        lastError = error;
        // Only retry on connection failures, not on command failures
        const isRetryable = error?.retryable === true ||
                           error?.errorType === 'connection_failed' ||
                           error?.errorType === 'timeout' ||
                           error?.errorType === 'ssh_error';
        error.retryAttempts = attempt;
        error.recoveryActions = recoveryActions;
        if (!isRetryable || attempt >= maxRetries) {
          throw error;
        }

        const shouldResetControlMaster =
          !controlResetDone &&
          (error?.sshError?.category === 'local_control_connection' ||
           error?.sshError?.category === 'remote_exchange_closed' ||
           error?.errorType === 'ssh_error');
        if (shouldResetControlMaster) {
          const recovery = await this.resetControlMaster(hostAlias, error?.sshError?.category || error?.errorType || 'ssh_error');
          recoveryActions.push({ action: 'reset_control_master', ...recovery });
          controlResetDone = true;
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
      prefix += `export ${k}=${shQuote(v)}; `;
    }
    if (session.cwd) {
      prefix += `cd ${shQuote(session.cwd)} && `;
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

export { SessionManager };
