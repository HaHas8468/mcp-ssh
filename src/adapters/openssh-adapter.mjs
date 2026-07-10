import { spawn as nativeSpawn } from 'child_process';
import { readFileSync, readdirSync } from 'fs';
import { SCP_BIN, SSH_BIN } from '../shared.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';
import { remainingMs, throwIfAborted } from '../core/operation-control.mjs';

function redactSshError(stderr) {
  return String(stderr || '')
    .replace(/(?:password|passphrase)\s*[:=].*/gi, '$1: [REDACTED]')
    .replace(/identityfile\s+\S+/gi, 'identityfile [REDACTED]');
}

function classifySshFailure(stderr, phase = 'connect') {
  const text = String(stderr || '');
  if (/permission denied|authentication failed|too many authentication failures/i.test(text)) {
    return { code: ERROR_CODES.SSH_AUTH_FAILED, phase: 'authenticate', retryable: false };
  }
  if (/host key verification failed|remote host identification has changed/i.test(text)) {
    return { code: ERROR_CODES.SSH_HOST_KEY_FAILED, phase: 'authenticate', retryable: false };
  }
  if (/could not resolve hostname|name or service not known|temporary failure in name resolution/i.test(text)) {
    return { code: ERROR_CODES.SSH_DNS_FAILED, phase: 'connect', retryable: true };
  }
  if (MUX_DIAGNOSTIC_RE.test(text) || /control socket|controlpath/i.test(text)) {
    return { code: ERROR_CODES.SSH_MASTER_FAILED, phase: 'connect', retryable: true };
  }
  return { code: phase === 'transfer' ? ERROR_CODES.TRANSFER_FAILED : ERROR_CODES.SSH_HOP_UNREACHABLE, phase, retryable: true };
}

function controlArgs(controlPath) {
  return controlPath ? ['-o', `ControlPath=${controlPath}`] : [];
}

const MUX_DIAGNOSTIC_RE = /mux_client|session open refused|controlsocket already exists|control socket .*already exists|master.*(?:dead|broken|refused)|controlpath.*(?:dead|broken|refused)/i;

function extractMuxDiagnostics(stderr) {
  const diagnostics = [];
  const remote = [];
  for (const line of String(stderr || '').split(/\r?\n/)) {
    if (MUX_DIAGNOSTIC_RE.test(line)) diagnostics.push(line);
    else remote.push(line);
  }
  return {
    degraded: diagnostics.length > 0,
    diagnostics,
    stderr: remote.join('\n').replace(/^\n+|\n+$/g, ''),
  };
}

function procDescendants(rootPid) {
  const children = new Map();
  try {
    for (const name of readdirSync('/proc')) {
      if (!/^\d+$/.test(name)) continue;
      let stat;
      try { stat = readFileSync(`/proc/${name}/stat`, 'utf8'); } catch { continue; }
      const match = stat.match(/^\d+ \(.*\) \S (\d+) /);
      if (!match) continue;
      const pid = Number(name);
      const ppid = Number(match[1]);
      if (!children.has(ppid)) children.set(ppid, []);
      children.get(ppid).push(pid);
    }
  } catch { return []; }
  const descendants = [];
  const pending = [...(children.get(rootPid) || [])];
  while (pending.length) {
    const pid = pending.shift();
    descendants.push(pid);
    pending.push(...(children.get(pid) || []));
  }
  return descendants;
}

class OpenSshAdapter {
  constructor({ spawn = nativeSpawn, credentials, config, sshBin = SSH_BIN, scpBin = SCP_BIN, sshConfigPath, now = () => Date.now(), platform = process.platform, killProcess = process.kill, descendantPids = procDescendants } = {}) {
    this.spawn = spawn;
    this.credentials = credentials;
    this.config = config;
    this.sshBin = sshBin;
    this.scpBin = scpBin;
    this.sshConfigPath = sshConfigPath;
    this.now = now;
    this.platform = platform;
    this.killProcess = killProcess;
    this.descendantPids = descendantPids;
    this.activeProcesses = new Map();
    this.shuttingDown = false;
  }

  _signalProcess(entry, signal) {
    if (!entry?.child?.pid) return;
    try {
      if (this.platform !== 'win32') this.killProcess(-entry.child.pid, signal);
      else if (signal !== 'SIGCONT') {
        const args = ['/pid', String(entry.child.pid), '/t', ...(signal === 'SIGKILL' ? ['/f'] : [])];
        const killer = nativeSpawn('taskkill', args, { shell: false, windowsHide: true, stdio: 'ignore' });
        killer.unref?.();
      }
    } catch {}
  }

  _signalProcessTree(entry, signal) {
    if (!entry?.child?.pid) return;
    if (this.platform === 'win32') {
      this._signalProcess(entry, signal);
      return;
    }
    const descendants = this.descendantPids(entry.child.pid);
    for (const pid of descendants.reverse()) {
      try { this.killProcess(-pid, signal); } catch {}
      try { this.killProcess(pid, signal); } catch {}
    }
    this._signalProcess(entry, signal);
  }

  _terminateProcess(entry) {
    if (!entry || entry.terminating) return;
    entry.terminating = true;
    this._signalProcessTree(entry, 'SIGTERM');
    entry.escalation = setTimeout(() => this._signalProcessTree(entry, 'SIGKILL'), 1_000);
    entry.escalation.unref?.();
  }

  resumeActiveProcesses() {
    for (const entry of this.activeProcesses.values()) this._signalProcess(entry, 'SIGCONT');
  }

  async shutdown() {
    this.shuttingDown = true;
    const closes = [];
    for (const entry of this.activeProcesses.values()) {
      this._terminateProcess(entry);
      closes.push(entry.closed);
    }
    await Promise.allSettled(closes);
  }

  activeProcessCount() {
    return this.activeProcesses.size;
  }

  _configArgs() {
    return this.sshConfigPath ? ['-F', this.sshConfigPath] : [];
  }

  async _run(binary, args, { target, timeoutMs, deadline, signal, stdin, env, phase = 'connect', onProgress } = {}) {
    const startedAt = this.now();
    if (this.shuttingDown) {
      return { code: null, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.from('服务正在关闭'), cancelled: true, durationMs: 0 };
    }
    throwIfAborted({ signal, deadline, phase });
    const inheritedEnv = env || (target ? await this.credentials?.environment(target, { signal, deadline }) : null) || process.env;
    if (signal?.aborted || (deadline !== undefined && this.now() >= deadline)) {
      return { code: null, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.from('请求已取消'), cancelled: signal?.aborted, timedOut: !signal?.aborted, durationMs: 0 };
    }
    return new Promise((resolveResult) => {
      let child;
      try {
        child = this.spawn(binary, args, {
          shell: false,
          windowsHide: true,
          detached: this.platform !== 'win32',
          stdio: ['pipe', 'pipe', 'pipe'],
          env: inheritedEnv,
        });
      } catch (error) {
        resolveResult({ code: null, stdout: Buffer.alloc(0), stderr: Buffer.from(error.message), spawnError: error, durationMs: this.now() - startedAt });
        return;
      }
      const stdout = [];
      const stderr = [];
      let settled = false;
      let timedOut = false;
      let cancelled = false;
      let resolveClosed;
      const entry = { child, terminating: false, escalation: null, closed: new Promise(resolve => { resolveClosed = resolve; }) };
      this.activeProcesses.set(child.pid ?? child, entry);
      const finish = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        if (entry.escalation) clearTimeout(entry.escalation);
        signal?.removeEventListener('abort', abort);
        this.activeProcesses.delete(child.pid ?? child);
        resolveClosed?.();
        resolveResult({ stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), durationMs: this.now() - startedAt, timedOut, cancelled, ...result });
      };
      const abort = () => { cancelled = true; this._terminateProcess(entry); };
      const timeout = setTimeout(() => { timedOut = true; this._terminateProcess(entry); }, remainingMs(deadline, timeoutMs || 30_000));
      timeout.unref?.();
      child.once('error', error => finish({ code: null, signal: null, spawnError: error }));
      child.once('exit', (code, childSignal) => {
        if (!entry.terminating) return;
        // A multiplex master can retain the stdio pipe after the short-lived
        // mux client exits. Do not wait for `close`: detach the local readers
        // so cancellation can proceed to remote process-group cleanup.
        child.stdout?.destroy?.();
        child.stderr?.destroy?.();
        finish({ code, signal: childSignal });
      });
      child.once('close', (code, childSignal) => finish({ code, signal: childSignal }));
      child.stdout?.on('data', chunk => { stdout.push(Buffer.from(chunk)); });
      child.stderr?.on('data', chunk => { stderr.push(Buffer.from(chunk)); });
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
      if (stdin !== undefined && stdin !== null) child.stdin?.end(stdin);
      else child.stdin?.end();
      onProgress?.(0, undefined, 'SSH 操作已开始');
    });
  }

  async resolve(target, options = {}) {
    const result = await this._run(this.sshBin, [...this._configArgs(), '-G', '--', target], { timeoutMs: 15_000, phase: 'resolve', ...options });
    if (result.spawnError || result.code !== 0) {
      const classified = classifySshFailure(result.stderr, 'resolve');
      throw new OperationFailure(classified.code, `ssh -G 失败：${redactSshError(result.stderr) || '未知错误'}`, { ...classified, cause: result.spawnError });
    }
    return { stdout: result.stdout.toString('utf8'), stderr: result.stderr.toString('utf8') };
  }

  async openMaster(target, controlPath, options = {}) {
    const config = await this.config.load();
    const args = [
      ...this._configArgs(),
      '-M', '-N', '-f',
      '-o', 'ControlMaster=yes',
      '-o', `ControlPersist=${Math.ceil(config.connectionPersistMs / 1000)}`,
      '-o', `ControlPath=${controlPath}`,
      '-o', `StrictHostKeyChecking=${config.strictHostKeyChecking}`,
      '--', target.id,
    ];
    const result = await this._run(this.sshBin, args, { target: target.id, timeoutMs: config.defaultTimeoutMs, phase: 'connect', ...options });
    if (result.code !== 0 || result.spawnError) {
      const classified = classifySshFailure(result.stderr, 'connect');
      const error = new OperationFailure(classified.code, `无法建立 SSH 连接：${redactSshError(result.stderr) || '未知错误'}`, { ...classified, cause: result.spawnError });
      error.stderr = result.stderr.toString('utf8');
      throw error;
    }
  }

  async checkMaster(target, controlPath, options = {}) {
    const result = await this._run(this.sshBin, [...this._configArgs(), '-O', 'check', ...controlArgs(controlPath), '--', target.id], {
      target: target.id, timeoutMs: 10_000, phase: 'connect', ...options,
    });
    return { ok: result.code === 0, stderr: result.stderr.toString('utf8') };
  }

  async closeMaster(target, controlPath, options = {}) {
    const result = await this._run(this.sshBin, [...this._configArgs(), '-O', 'exit', ...controlArgs(controlPath), '--', target.id], {
      target: target.id, timeoutMs: 10_000, phase: 'cleanup', ...options,
    });
    return { ok: result.code === 0, stderr: redactSshError(result.stderr) };
  }

  async exec({ target, command, controlPath, timeoutMs, deadline, signal, stdin, onProgress }) {
    const config = await this.config.load();
    const result = await this._run(this.sshBin, [
      ...this._configArgs(), ...controlArgs(controlPath), '-o', `StrictHostKeyChecking=${config.strictHostKeyChecking}`,
      '--', target.id, command,
    ], { target: target.id, timeoutMs, deadline, signal, stdin, phase: 'execute', onProgress });
    const mux = extractMuxDiagnostics(redactSshError(result.stderr.toString('utf8')));
    return { ...result, stdout: result.stdout.toString('utf8'), stderr: mux.stderr, masterDegraded: mux.degraded, muxDiagnostics: mux.diagnostics };
  }

  async transfer({ direction, target, localPath, remotePath, recursive = false, preserve = false, controlPath, timeoutMs, deadline, signal, onProgress }) {
    const config = await this.config.load();
    const remote = `${target.id}:${remotePath}`;
    const args = [
      ...this._configArgs(), ...controlArgs(controlPath), '-o', `StrictHostKeyChecking=${config.strictHostKeyChecking}`,
      ...(recursive ? ['-r'] : []), ...(preserve ? ['-p'] : []), '--',
      ...(direction === 'upload' ? [localPath, remote] : [remote, localPath]),
    ];
    const result = await this._run(this.scpBin, args, { target: target.id, timeoutMs, deadline, signal, phase: 'transfer', onProgress });
    const mux = extractMuxDiagnostics(redactSshError(result.stderr.toString('utf8')));
    return { ...result, stdout: result.stdout.toString('utf8'), stderr: mux.stderr, masterDegraded: mux.degraded, muxDiagnostics: mux.diagnostics };
  }

  async probe(target, { timeoutMs = 10_000, deadline, signal } = {}) {
    const result = await this._run(this.sshBin, [...this._configArgs(), '-o', 'BatchMode=yes', '-o', `ConnectTimeout=${Math.ceil(timeoutMs / 1000)}`, '--', target, 'true'], {
      target, timeoutMs, deadline, signal, phase: 'connect',
    });
    return { ok: result.code === 0, stderr: redactSshError(result.stderr.toString('utf8')), durationMs: result.durationMs };
  }
}

function controlMasterUnavailable(error) {
  const text = `${error?.message || ''}\n${error?.stderr || ''}`;
  return /unknown configuration option.*control|controlmaster.*(?:not supported|unsupported)|controlpath.*(?:not supported|unsupported)/i.test(text);
}

export { OpenSshAdapter, classifySshFailure, redactSshError, controlArgs, controlMasterUnavailable, extractMuxDiagnostics, procDescendants };
