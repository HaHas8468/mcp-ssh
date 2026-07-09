import { writeFile, chmod, stat } from 'fs/promises';
import { join } from 'path';
import { createRequire } from 'module';
import {
  AuditLogger,
  PermissionGuard,
  RateLimiter,
  SSHConfigParser,
  mcpConfig,
} from './config.mjs';
import { SessionManager } from './session-manager.mjs';
import { TaskManager } from './task-manager.mjs';
import {
  buildTaskStatusCommand,
  normalizeTaskStatusOptions,
  parseKeyValueBlock,
  parseListeningPorts,
  parseProcessTree,
  safeRegexTest,
  summarizeResources,
} from './task-status.mjs';
import {
  DEFAULT_TIMEOUT,
  MAX_OUTPUT_SIZE,
  SCP_BIN,
  SSH_BIN,
  clampNonNegativeInteger,
  debugLog,
  detectDangerousCommand,
  diagnoseSshTransportError,
  escapeRegExp,
  isWindows,
  nonNegativeInteger,
  normalizeStringList,
  parsePidList,
  shQuote,
  signalToNum,
  validateFileMode,
} from './shared.mjs';

const require = createRequire(import.meta.url);
const { spawn, exec, execFile } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

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
    const hosts = await this.configParser.getAllKnownHosts();
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

    for (const configPath of this.configParser._configsWithPasswords) {
      await this.configParser.checkFilePermissions(configPath);
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
        // If the SSH transport failed, throw to trigger retry/recovery. Command
        // failures and user-command timeouts are returned directly.
        if (this._isRetryableConnectionResult(result) && maxRetries > 0) {
          const err = new Error(`SSH transport failed: ${result.stderr}`);
          err.errorType = result.errorType;
          err.code = result.code;
          err.stderr = result.stderr;
          err.sshError = result.sshError;
          err.retryable = result.sshError?.retryable !== false;
          err.result = result;
          throw err;
        }
        return result;
      }),
      hostAlias,
      { maxRetries, retryDelay: this.sessionManager.config.get('retryDelay') }
    ).catch(err => {
      // If all retries failed, return the error as a structured result
      if (err.result) {
        return {
          ...err.result,
          retried: true,
          retryAttempts: err.retryAttempts ?? maxRetries,
          recoveryActions: err.recoveryActions || [],
        };
      }
      if (err.errorType === 'connection_failed' || err.errorType === 'ssh_error') {
        return {
          success: false,
          code: err.code || 255,
          signal: null,
          errorType: err.errorType,
          sshError: err.sshError || diagnoseSshTransportError(err.stderr || err.message),
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

  _isRetryableConnectionResult(result) {
    if (!result || result.code !== 255) return false;
    if (result.sshError?.retryable === false) return false;
    return result.errorType === 'connection_failed' || result.errorType === 'ssh_error';
  }

  async _runRemoteCommandOnce(hostAlias, command, options = {}) {
    const timeout = Math.min(options.timeout || this.sessionManager.config.get('defaultTimeout'),
                              this.sessionManager.config.get('maxTimeout'));
    const useSession = options.useSession !== false; // default true
    const abortSignal = options.signal || null; // MCP AbortSignal for cancellation
    const onProgress = options.onProgress || null; // MCP progress callback
    const combineOutput = options.combineOutput || false; // P0 #15: interleave stdout/stderr
    const showSessionContext = options.showSessionContext || useSession === false;

    // Get or create session, build command with state
    let fullCommand = command;
    let sessionBefore = null;
    if (useSession) {
      await this.sessionManager.getSession(hostAlias);
      sessionBefore = this.sessionManager.snapshot(hostAlias);
      fullCommand = this.sessionManager.buildCommandWithState(hostAlias, command);
    }

    // Wrap command with a unique marker for timeout cleanup (P0 #3).
    // Keep marker commands on their own lines so user commands ending in a
    // here-doc delimiter are not polluted by an appended "; echo ...".
    const marker = `MCP_${process.pid}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const markerKillPattern = `[${marker[0]}]${marker.slice(1)}`;
    const wrappedCommand = [
      `printf '%s\\n' ${shQuote(`${marker}START`)}`,
      `printf '%s\\n' "${marker}_PID=$$"`,
      fullCommand,
      '__mcp_ssh_rc=$?',
      `printf '%s\\n' "${marker}_RC=$__mcp_ssh_rc"`,
    ].join('\n');

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
      let remoteCleanupPromise = null;
      const outputChunks = []; // P0 #15: timestamped chunks for interleaving
      let streamLineBuffer = ''; // P1 #30: buffer for streaming complete lines

      // MCP Cancellation: listen to AbortSignal (P0 #16)
      const onAbort = () => {
        cancelled = true;
        child.kill('SIGTERM');
        setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1000);
        // Kill remote process by marker
        remoteCleanupPromise = this._cleanupRemoteMarkedCommand(hostAlias, markerKillPattern);
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
        remoteCleanupPromise = this._cleanupRemoteMarkedCommand(hostAlias, markerKillPattern);
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

      child.on('close', async (code, sig) => {
        clearTimeout(timer);
        if (abortSignal) abortSignal.removeEventListener('abort', onAbort);
        const duration = Date.now() - startTime;
        let remoteCleanup = null;
        if ((timedOut || cancelled) && remoteCleanupPromise) {
          remoteCleanup = await remoteCleanupPromise;
        }

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

        const remotePidMatch = stdout.match(new RegExp(`${escapeRegExp(marker)}_PID=(\\d+)`));
        const remotePid = remotePidMatch ? Number.parseInt(remotePidMatch[1], 10) : null;

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
        stdout = stdout.replace(new RegExp(`${marker}START\\s*\n?`), '')
                       .replace(new RegExp(`${marker}_PID=\\d+\\s*\n?`), '');

        // Error classification must use the marker-derived command exit code.
        const errorType = cancelled ? 'cancelled'
          : this._classifyError(exitCode, stderr, sig, timedOut);
        const sshError = exitCode === 255 ? diagnoseSshTransportError(stderr) : null;

        // Update session state (P0 #2)
        let sessionAfter = null;
        if (useSession) {
          this.sessionManager.updateStateFromCommand(hostAlias, command, exitCode);
          sessionAfter = this.sessionManager.snapshot(hostAlias);
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

        const remoteState = (timedOut || cancelled)
          ? {
              remotePid,
              cleanup: remoteCleanup || { attempted: false },
              canQuery: false,
              canCleanup: Boolean(remoteCleanup && !remoteCleanup.terminated),
              cleanupCommand: `pkill -f ${shQuote(markerKillPattern)} 2>/dev/null; true`,
            }
          : undefined;

        const sessionContext = showSessionContext
          ? (useSession
              ? {
                  useSession: true,
                  persistent: true,
                  before: sessionBefore,
                  after: sessionAfter,
                  delta: this.sessionManager.diffSnapshots(sessionBefore, sessionAfter),
                }
              : { useSession: false, persistent: false })
          : undefined;

        // Structured output (P0 #14)
        resolve({
          success: exitCode === 0,
          code: exitCode,
          signal: sig || null,
          errorType,
          sshError,
          stdout,
          stderr: timedOut ? stderr + `\n[Command timed out; remote cleanup ${remoteCleanup?.terminated ? 'terminated matching process(es)' : 'did not confirm termination'}]` : stderr,
          combined,
          contentType,
          duration,
          timedOut,
          truncated: stdoutTruncated || stderrTruncated,
          originalStdoutSize,
          originalStderrSize,
          remotePid,
          remoteState,
          sessionContext,
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

  async _cleanupRemoteMarkedCommand(hostAlias, markerKillPattern) {
    const cleanupScript = `
__mcp_pattern=${shQuote(markerKillPattern)}
__mcp_before="$(pgrep -f "$__mcp_pattern" 2>/dev/null | awk 'NF' | sort -n | uniq | tr '\\n' ' ')"
printf 'MATCHED %s\\n' "$__mcp_before"
if [ -n "$__mcp_before" ]; then
  kill -TERM $__mcp_before 2>/dev/null || true
fi
sleep 1
__mcp_after_term="$(pgrep -f "$__mcp_pattern" 2>/dev/null | awk 'NF' | sort -n | uniq | tr '\\n' ' ')"
printf 'AFTER_TERM %s\\n' "$__mcp_after_term"
if [ -n "$__mcp_after_term" ]; then
  kill -KILL $__mcp_after_term 2>/dev/null || true
fi
sleep 1
__mcp_remaining="$(pgrep -f "$__mcp_pattern" 2>/dev/null | awk 'NF' | sort -n | uniq | tr '\\n' ' ')"
printf 'REMAINING %s\\n' "$__mcp_remaining"
`;

    return new Promise((resolve) => {
      const child = this._spawn(SSH_BIN, [
        ...this.sessionManager.getControlArgs(),
        '-o', 'ConnectTimeout=5',
        '--', hostAlias, cleanupScript,
      ], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: false });

      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch {}
        setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1000);
      }, 3000);

      child.stdout.on('data', d => { stdout += d.toString(); });
      child.stderr.on('data', d => { stderr += d.toString(); });
      child.on('close', (code) => {
        clearTimeout(timer);
        const matchedPids = parsePidList(stdout.match(/^MATCHED\s*(.*)$/m)?.[1] || '');
        const afterTermPids = parsePidList(stdout.match(/^AFTER_TERM\s*(.*)$/m)?.[1] || '');
        const remainingPids = parsePidList(stdout.match(/^REMAINING\s*(.*)$/m)?.[1] || '');
        resolve({
          attempted: true,
          code,
          matchedPids,
          afterTermPids,
          remainingPids,
          terminated: remainingPids.length === 0,
          stderr,
        });
      });
      child.on('error', (error) => {
        clearTimeout(timer);
        resolve({
          attempted: true,
          code: 1,
          matchedPids: [],
          afterTermPids: [],
          remainingPids: [],
          terminated: false,
          error: error instanceof Error ? error.message : String(error),
          stderr,
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
      const sshError = diagnoseSshTransportError(stderr);
      if (sshError.category === 'auth_failed') return 'auth_failed';
      if (sshError.category === 'host_key_mismatch') return 'host_key_mismatch';
      if (sshError.category === 'target_unreachable') return 'connection_failed';
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
  async openSession(hostAlias, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);
    await this.sessionManager.getSession(hostAlias);
    // Establish the ControlMaster connection with a no-op
    const result = await this.runRemoteCommand(hostAlias, 'echo session_opened', { useSession: false, timeout: options.timeout });
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
    this._assertSafeHostAlias(hostAlias);
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
    const quotedPath = shQuote(remotePath);
    let cmd = `base64 ${quotedPath}`;
    if (options.offset !== undefined || options.limit !== undefined) {
      const offset = options.offset === undefined ? 0 : nonNegativeInteger(options.offset, 'offset');
      const limit = options.limit === undefined ? null : nonNegativeInteger(options.limit, 'limit');
      const limitCmd = limit === null ? 'cat' : `head -c ${limit}`;
      cmd = `tail -c +${offset + 1} ${quotedPath} | ${limitCmd} | base64`;
    }

    const result = await this.runRemoteCommand(hostAlias, cmd, { useSession: false });
    if (result.code !== 0) {
      return {
        success: false,
        error: result.stderr.trim() || `Failed to read file (code ${result.code})`,
        errorType: result.errorType,
      };
    }
    if (result.truncated) {
      return {
        success: false,
        path: remotePath,
        error: 'Remote file output exceeded the MCP output limit; use ssh_transfer download for large files.',
        errorType: 'output_truncated',
        truncated: true,
        originalStdoutSize: result.originalStdoutSize,
        originalStderrSize: result.originalStderrSize,
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
      byteLength: Buffer.byteLength(content, 'utf-8'),
      encoding: 'utf-8',
      truncated: false,
      originalStdoutSize: result.originalStdoutSize,
    };
  }

  async writeFile(hostAlias, remotePath, content, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);
    await this.permissionGuard.check(hostAlias, 'writeFile', { remotePath });

    const encoded = Buffer.from(content, 'utf-8').toString('base64');
    const quotedPath = shQuote(remotePath);
    const mode = validateFileMode(options.mode);

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

        const modeFlag = mode ? ` && chmod ${mode} ${quotedPath}` : '';
        const child = this._spawn(SSH_BIN, [
          ...this.sessionManager.getControlArgs(),
          '-o', `StrictHostKeyChecking=${this.sessionManager.config.get('strictHostKeyChecking')}`,
          '--', hostAlias,
          `base64 -d > ${quotedPath}${modeFlag}`,
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
    const quotedPath = shQuote(remotePath);

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
          `base64 -d >> ${quotedPath}`,
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

    const quotedPath = shQuote(remotePath || '.');
    const detailed = options.detailed !== false;
    // Use find for structured output, or ls for simple
    const cmd = detailed
      ? `find ${quotedPath} -mindepth 1 -maxdepth 1 -printf '%y|%s|%T@|%p\\n' 2>/dev/null || ls -1A ${quotedPath}`
      : `ls -1A ${quotedPath}`;

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

    const quotedPath = shQuote(remotePath);
    const cmd = `stat -c '%s|%a|%Y|%F' ${quotedPath} 2>/dev/null || stat -f '%z|%Lp|%m|%HT' ${quotedPath}`;

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
    const quotedPath = shQuote(remotePath);
    const result = await this.runRemoteCommand(hostAlias, `mkdir ${parents} -- ${quotedPath}`);
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

    const quotedPath = shQuote(remotePath);
    const recursive = options.recursive !== false ? '-rf' : '-f';
    const result = await this.runRemoteCommand(hostAlias, `rm ${recursive} -- ${quotedPath}`);
    this.auditLogger.log({ tool: 'remove', hostAlias, remotePath, code: result.code });
    return { success: result.code === 0, path: remotePath, error: result.code !== 0 ? result.stderr.trim() : undefined };
  }

  async move(hostAlias, srcPath, destPath) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);

    const quotedSrc = shQuote(srcPath);
    const quotedDest = shQuote(destPath);
    const result = await this.runRemoteCommand(hostAlias, `mv -- ${quotedSrc} ${quotedDest}`);
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

    if (options.singleConnection === false) {
      return this._runBatchSequentialLegacy(hostAlias, commands, options, startTime);
    }

    return this._runBatchSingleConnection(hostAlias, commands, options, startTime);
  }

  async _runBatchSequentialLegacy(hostAlias, commands, options, startTime) {
    const mode = options.mode || 'sequential';

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

  _buildBatchScript(marker, commands, mode) {
    const lines = [
      'set +e',
      `__mcp_mode=${shQuote(mode)}`,
    ];

    commands.forEach((command, index) => {
      const stdoutPrefix = `${marker}_STDOUT_${index}=`;
      const stderrPrefix = `${marker}_STDERR_${index}=`;
      const rcPrefix = `${marker}_RC_${index}=`;
      lines.push(`__mcp_stdout=$(mktemp "\${TMPDIR:-/tmp}/mcp-ssh-batch.XXXXXX") || exit 1`);
      lines.push(`__mcp_stderr=$(mktemp "\${TMPDIR:-/tmp}/mcp-ssh-batch.XXXXXX") || { rm -f "$__mcp_stdout"; exit 1; }`);
      lines.push(`set +e`);
      lines.push(`eval ${shQuote(command)} >"$__mcp_stdout" 2>"$__mcp_stderr"`);
      lines.push(`__mcp_rc=$?`);
      lines.push(`printf '%s' ${shQuote(stdoutPrefix)}; base64 < "$__mcp_stdout" | tr -d '\\n'; printf '\\n'`);
      lines.push(`printf '%s' ${shQuote(stderrPrefix)}; base64 < "$__mcp_stderr" | tr -d '\\n'; printf '\\n'`);
      lines.push(`printf '%s%s\\n' ${shQuote(rcPrefix)} "$__mcp_rc"`);
      lines.push(`rm -f "$__mcp_stdout" "$__mcp_stderr"`);
      if (mode === 'stopOnError') {
        lines.push(`if [ "$__mcp_rc" -ne 0 ]; then exit 0; fi`);
      }
    });

    return lines.join('\n');
  }

  _readMarkerValue(output, marker) {
    const match = output.match(new RegExp(`^${escapeRegExp(marker)}(.*)$`, 'm'));
    return match ? match[1] : null;
  }

  _decodeBatchField(value) {
    if (value === null || value === undefined || value === '') return '';
    return Buffer.from(value, 'base64').toString('utf-8');
  }

  _batchSummary(total, results, startTime, extra = {}) {
    const failedResults = results.filter(r => r.code !== 0);
    const firstFailureResult = failedResults[0] || null;
    return {
      summary: {
        total,
        executed: results.length,
        succeeded: results.filter(r => r.code === 0).length,
        failed: failedResults.length,
        firstFailure: firstFailureResult
          ? { index: firstFailureResult.index, command: firstFailureResult.command, errorType: firstFailureResult.errorType, code: firstFailureResult.code }
          : null,
        totalDuration: Date.now() - startTime,
        ...extra,
      },
      results,
      success: failedResults.length === 0,
    };
  }

  async _runBatchSingleConnection(hostAlias, commands, options, startTime) {
    if (commands.length === 0) {
      return this._batchSummary(0, [], startTime, { singleConnection: true });
    }

    const mode = options.mode || 'sequential';
    const marker = `MCP_BATCH_${process.pid}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const script = this._buildBatchScript(marker, commands, mode);
    const result = await this.runRemoteCommand(hostAlias, `bash -c ${shQuote(script)}`, {
      timeout: options.timeout,
      useSession: options.useSession,
      confirmed: options.confirmed,
      force: options.force,
      showSessionContext: options.showSessionContext,
      signal: options.signal,
      onProgress: options.onProgress,
    });

    if (result.confirmationRequired) {
      const confirmationResult = {
        index: 0,
        command: commands[0],
        success: false,
        code: 1,
        stdout: '',
        stderr: result.message,
        errorType: 'confirmation_required',
        confirmationRequired: true,
        danger: result.danger,
      };
      return this._batchSummary(commands.length, [confirmationResult], startTime, { singleConnection: true });
    }

    const results = [];
    for (let i = 0; i < commands.length; i++) {
      const codeValue = this._readMarkerValue(result.stdout, `${marker}_RC_${i}=`);
      if (codeValue === null) break;
      const stdout = this._decodeBatchField(this._readMarkerValue(result.stdout, `${marker}_STDOUT_${i}=`));
      const stderr = this._decodeBatchField(this._readMarkerValue(result.stdout, `${marker}_STDERR_${i}=`));
      const code = Number.parseInt(codeValue, 10);
      const errorType = this._classifyError(code, stderr, null, false);
      results.push({
        index: i,
        command: commands[i],
        success: code === 0,
        code,
        signal: null,
        errorType,
        stdout,
        stderr,
        duration: result.duration,
        timedOut: false,
        truncated: result.truncated,
        contentType: this._detectContentType(stdout),
      });
      if (options.useSession !== false) {
        this.sessionManager.updateStateFromCommand(hostAlias, commands[i], code);
      }
    }

    if (results.length === 0) {
      return this._batchSummary(commands.length, [{
        index: 0,
        command: commands[0],
        ...result,
      }], startTime, { singleConnection: true, parseFailed: true });
    }

    return this._batchSummary(commands.length, results, startTime, { singleConnection: true });
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
    const exitFile = `/tmp/mcp-task-${taskId}.exit`;
    const taskScript = [
      'set +e',
      command,
      '__mcp_task_rc=$?',
      `printf '%s\\n' "$__mcp_task_rc" > ${shQuote(exitFile)}`,
      'exit "$__mcp_task_rc"',
    ].join('\n');
    // Start in a new session/process group when setsid exists. The returned
    // PID is then also the process-group id, making stopTask able to clean up
    // child processes such as vLLM EngineCore workers.
    const wrapped = [
      'if command -v setsid >/dev/null 2>&1; then',
      `  nohup setsid bash -c ${shQuote(taskScript)} > ${shQuote(logFile)} 2>&1 < /dev/null &`,
      'else',
      `  nohup bash -c ${shQuote(taskScript)} > ${shQuote(logFile)} 2>&1 < /dev/null &`,
      'fi',
      'echo $!',
    ].join('\n');

    const timeout = options.timeout ?? this.config.get('defaultTimeout') ?? 120000;
    const result = await this.runRemoteCommand(hostAlias, wrapped, { useSession: false, timeout });
    if (result.code !== 0) {
      return { success: false, error: result.stderr.trim(), errorType: result.errorType };
    }

    const remotePid = parseInt(result.stdout.trim(), 10);
    this.taskManager.register(hostAlias, remotePid, command, {
      taskId,
      logFile,
      exitFile,
      processGroupId: remotePid,
    });

    this.auditLogger.log({ tool: 'startBackground', hostAlias, command, taskId, remotePid });

    return {
      success: true,
      taskId,
      remotePid,
      processGroupId: remotePid,
      logFile,
      exitFile,
      command,
      hostAlias,
    };
  }

  async getTaskStatus(taskId, options = {}) {
    const task = this.taskManager.get(taskId);
    if (!task) {
      return { success: false, error: `Task ${taskId} not found` };
    }

    const remotePid = nonNegativeInteger(task.remotePid, 'remotePid');
    const processGroupId = nonNegativeInteger(task.processGroupId ?? task.remotePid, 'processGroupId');
    const statusOptions = normalizeTaskStatusOptions(options);
    const marker = `MCP_TASK_${process.pid}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const markers = {
      processStart: `${marker}_PROCESS_START`,
      processEnd: `${marker}_PROCESS_END`,
      treeStart: `${marker}_TREE_START`,
      treeEnd: `${marker}_TREE_END`,
      portStart: `${marker}_PORT_START`,
      portEnd: `${marker}_PORT_END`,
      exitStart: `${marker}_EXIT_START`,
      exitEnd: `${marker}_EXIT_END`,
      logMetaStart: `${marker}_LOG_META_START`,
      logMetaEnd: `${marker}_LOG_META_END`,
      logStart: `${marker}_LOG_START`,
      logEnd: `${marker}_LOG_END`,
    };
    const statusCmd = buildTaskStatusCommand({ ...task, taskId }, statusOptions, markers);
    const statusResult = await this.runRemoteCommand(task.hostAlias, statusCmd, { useSession: false, timeout: 10000 });

    if (statusResult.code !== 0) {
      return { success: false, error: statusResult.stderr.trim(), errorType: statusResult.errorType };
    }

    const processText = this._extractMarkedBlock(statusResult.stdout, markers.processStart, markers.processEnd).trim();
    const processTree = parseProcessTree(this._extractMarkedBlock(statusResult.stdout, markers.treeStart, markers.treeEnd));
    const portsListening = parseListeningPorts(
      this._extractMarkedBlock(statusResult.stdout, markers.portStart, markers.portEnd),
      processTree.map(proc => proc.pid),
      statusOptions.ports
    );
    const exitMeta = parseKeyValueBlock(this._extractMarkedBlock(statusResult.stdout, markers.exitStart, markers.exitEnd));
    const logMeta = parseKeyValueBlock(this._extractMarkedBlock(statusResult.stdout, markers.logMetaStart, markers.logMetaEnd));
    const recentLog = this._extractMarkedBlock(statusResult.stdout, markers.logStart, markers.logEnd);
    const recentExitCode = exitMeta.exitCode === '' || exitMeta.exitCode === undefined ? null : Number.parseInt(exitMeta.exitCode, 10);
    const running = processTree.length > 0 || (!processText.includes('EXITED') && processText.length > 0);
    const logEndOffset = Number.parseInt(logMeta.end || '0', 10) || 0;
    const logStartOffset = Number.parseInt(logMeta.start || '0', 10) || 0;
    if (statusOptions.onlyNew) {
      task.lastLogOffset = logEndOffset;
    }
    task.lastExitCode = recentExitCode;

    const readyByLog = statusOptions.readyPattern
      ? safeRegexTest(statusOptions.readyPattern, recentLog)
      : null;
    const readyByPort = statusOptions.ports.length > 0
      ? statusOptions.ports.every(port => portsListening.some(entry => entry.port === port))
      : (portsListening.length > 0 ? true : null);
    const ready = readyByLog !== null ? readyByLog : readyByPort;
    const resources = summarizeResources(processTree);

    return {
      success: true,
      taskId,
      running,
      process: processText,
      processTree,
      recentLog,
      log: {
        file: task.logFile,
        lines: statusOptions.logLines,
        grep: statusOptions.grep,
        exclude: statusOptions.exclude,
        tailBytes: statusOptions.tailBytes,
        onlyNew: statusOptions.onlyNew,
        startByte: logStartOffset,
        endByte: logEndOffset,
        truncatedToBytes: Math.max(0, logEndOffset - logStartOffset),
        maxLineLength: statusOptions.maxLogLineLength,
      },
      portsListening,
      recentExitCode,
      resources,
      health: {
        running,
        ready,
        readyByLog,
        readyByPort,
        portsListening,
        processCount: processTree.length,
        recentExitCode,
        resources,
      },
      command: task.command,
      hostAlias: task.hostAlias,
      remotePid: task.remotePid,
      processGroupId,
      startedAt: new Date(task.startedAt).toISOString(),
    };
  }

  _extractMarkedBlock(text, startMarker, endMarker) {
    const start = text.indexOf(startMarker);
    const end = text.indexOf(endMarker);
    if (start < 0 || end < 0 || end < start) return '';
    return text.slice(start + startMarker.length, end).replace(/^\r?\n/, '').replace(/\r?\n$/, '');
  }

  async listTasks(options = {}) {
    const statusTimeout = options.statusTimeout || 10000;
    const tasks = [];

    for (const [taskId, task] of this.taskManager.entries()) {
      const remotePid = nonNegativeInteger(task.remotePid, 'remotePid');
      const processGroupId = nonNegativeInteger(task.processGroupId ?? task.remotePid, 'processGroupId');
      const checkCmd = [
        `if ps -p ${remotePid} >/dev/null 2>&1; then`,
        `  ps -p ${remotePid} -o pid,ppid,pgid,stat,etime,comm --no-headers 2>/dev/null;`,
        `elif pgrep -g ${processGroupId} >/dev/null 2>&1; then`,
        `  pgrep -g ${processGroupId} -a 2>/dev/null | sed 's/^/GROUP /';`,
        'else',
        '  echo "EXITED";',
        'fi',
      ].join(' ');
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
          processGroupId,
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

    const remotePid = nonNegativeInteger(task.remotePid, 'remotePid');
    const processGroupId = nonNegativeInteger(task.processGroupId ?? task.remotePid, 'processGroupId');
    const stopCmd = `
pid=${remotePid}
pgid=${processGroupId}
term_targets=""
if ps -p "$pid" >/dev/null 2>&1; then term_targets="$term_targets $pid"; fi
if pgrep -g "$pgid" >/dev/null 2>&1; then
  kill -TERM -- "-$pgid" 2>/dev/null || true
fi
if [ -n "$term_targets" ]; then kill -TERM $term_targets 2>/dev/null || true; fi
sleep 2
remaining="$( { ps -p "$pid" -o pid= 2>/dev/null; pgrep -g "$pgid" 2>/dev/null; } | awk 'NF' | sort -n | uniq | tr '\\n' ' ' )"
if [ -n "$remaining" ]; then
  kill -KILL $remaining 2>/dev/null || true
  if pgrep -g "$pgid" >/dev/null 2>&1; then kill -KILL -- "-$pgid" 2>/dev/null || true; fi
fi
sleep 1
remaining="$( { ps -p "$pid" -o pid= 2>/dev/null; pgrep -g "$pgid" 2>/dev/null; } | awk 'NF' | sort -n | uniq | tr '\\n' ' ' )"
if [ -n "$remaining" ]; then
  echo "REMAINING $remaining"
else
  echo "STOPPED"
fi
`;
    const result = await this.runRemoteCommand(task.hostAlias, stopCmd, { useSession: false, timeout: 15000 });
    const stopped = result.code === 0 && result.stdout.includes('STOPPED') && !result.stdout.includes('REMAINING');
    if (stopped) {
      this.taskManager.remove(taskId);
    }
    this.auditLogger.log({ tool: 'stopTask', taskId, remotePid: task.remotePid, processGroupId, stopped });

    return {
      success: stopped,
      taskId,
      stopped,
      remotePid,
      processGroupId,
      remaining: stopped ? '' : result.stdout.trim(),
      errorType: stopped ? null : (result.errorType || 'process_still_running'),
    };
  }

  // ===========================================================================
  // Existing tools (enhanced)
  // ===========================================================================
  async getHostInfo(hostAlias) {
    const hosts = await this.configParser.getAllKnownHosts();
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
        sshError: connected ? null : result.sshError,
        recoveryActions: result.recoveryActions || [],
        retried: Boolean(result.retried),
        retryAttempts: result.retryAttempts || 0,
        latency: result.duration,
      };
    } catch (error) {
      debugLog(`Connectivity error with ${hostAlias}: ${error.message}\n`);
      return { connected: false, message: error instanceof Error ? error.message : String(error) };
    }
  }

  _compileUserPattern(pattern) {
    if (!pattern) return null;
    try {
      return new RegExp(String(pattern));
    } catch {
      return null;
    }
  }

  async inspectRemote(hostAlias, options = {}) {
    this._assertSafeHostAlias(hostAlias);
    await this._assertKnownHostAlias(hostAlias);

    const marker = `MCP_INSPECT_${process.pid}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const maxProcesses = clampNonNegativeInteger(options.maxProcesses ?? 50, 'maxProcesses', 1, 500);
    const portsFilter = normalizeStringList(options.ports)
      .map(v => Number.parseInt(v, 10))
      .filter(v => Number.isSafeInteger(v) && v > 0 && v <= 65535);
    const inspectCmd = [
      `printf '%s\\n' ${shQuote(`${marker}_PROCESS_START`)}`,
      `ps -eo pid= -o ppid= -o pgid= -o stat= -o etime= -o pcpu= -o pmem= -o rss= -o comm= -o args= 2>/dev/null | awk -v marker=${shQuote(marker)} '{pid=$1; ppid=$2; pgid=$3; stat=$4; etime=$5; cpu=$6; mem=$7; rss=$8; comm=$9; $1=$2=$3=$4=$5=$6=$7=$8=$9=""; sub(/^ +/, ""); if (index($0, marker) > 0) next; print pid "|" ppid "|" pgid "|" stat "|" etime "|" cpu "|" mem "|" rss "|" comm "|" $0}'`,
      `printf '%s\\n' ${shQuote(`${marker}_PROCESS_END`)}`,
      `printf '%s\\n' ${shQuote(`${marker}_PORT_START`)}`,
      `if command -v ss >/dev/null 2>&1; then ss -H -ltnp 2>/dev/null; elif command -v lsof >/dev/null 2>&1; then lsof -Pan -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print}'; fi`,
      `printf '%s\\n' ${shQuote(`${marker}_PORT_END`)}`,
    ].join('\n');

    const result = await this.runRemoteCommand(hostAlias, inspectCmd, { useSession: false, timeout: options.timeout ?? 10000 });
    if (result.code !== 0) {
      return {
        success: false,
        error: result.stderr.trim(),
        errorType: result.errorType,
        sshError: result.sshError,
      };
    }

    const processText = this._extractMarkedBlock(result.stdout, `${marker}_PROCESS_START`, `${marker}_PROCESS_END`);
    const portText = this._extractMarkedBlock(result.stdout, `${marker}_PORT_START`, `${marker}_PORT_END`);
    let processes = parseProcessTree(processText)
      .filter(proc => proc.pid !== result.remotePid && proc.ppid !== result.remotePid)
      .filter(proc => !/MCP_(INSPECT|TASK|BATCH)_/.test(proc.args));

    const regex = this._compileUserPattern(options.processPattern);
    const literalPattern = regex ? null : (options.processPattern ? String(options.processPattern) : null);
    if (regex) {
      processes = processes.filter(proc => regex.test(proc.args) || regex.test(proc.command));
    } else if (literalPattern) {
      processes = processes.filter(proc => proc.args.includes(literalPattern) || proc.command.includes(literalPattern));
    }
    processes = processes.slice(0, maxProcesses);

    const processPids = processes.map(proc => proc.pid);
    const restrictPortsToPids = options.processPattern ? processPids : [];
    const portsListening = parseListeningPorts(portText, restrictPortsToPids, portsFilter);

    return {
      success: true,
      hostAlias,
      processPattern: options.processPattern || null,
      processes,
      portsListening,
      summary: {
        processCount: processes.length,
        portCount: portsListening.length,
        wrapperFiltered: true,
        maxProcesses,
      },
    };
  }
}

export { SSHClient };
