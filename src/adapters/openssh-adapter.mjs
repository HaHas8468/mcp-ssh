import { spawn as nativeSpawn } from 'child_process';
import { SCP_BIN, SSH_BIN } from '../shared.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';

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
  if (/control socket|mux_client|master.*(?:dead|broken|refused)|controlpath/i.test(text)) {
    return { code: ERROR_CODES.SSH_MASTER_FAILED, phase: 'connect', retryable: true };
  }
  return { code: phase === 'transfer' ? ERROR_CODES.TRANSFER_FAILED : ERROR_CODES.SSH_HOP_UNREACHABLE, phase, retryable: true };
}

function controlArgs(controlPath) {
  return controlPath ? ['-o', `ControlPath=${controlPath}`] : [];
}

class OpenSshAdapter {
  constructor({ spawn = nativeSpawn, credentials, config, sshBin = SSH_BIN, scpBin = SCP_BIN, now = () => Date.now() } = {}) {
    this.spawn = spawn;
    this.credentials = credentials;
    this.config = config;
    this.sshBin = sshBin;
    this.scpBin = scpBin;
    this.now = now;
  }

  async _run(binary, args, { target, timeoutMs, signal, stdin, env, phase = 'connect', onProgress } = {}) {
    const startedAt = this.now();
    const inheritedEnv = env || (target ? await this.credentials?.environment(target) : null) || process.env;
    if (signal?.aborted) return { code: null, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.from('请求已取消'), cancelled: true, durationMs: 0 };
    return new Promise((resolveResult) => {
      let child;
      try {
        child = this.spawn(binary, args, {
          shell: false,
          windowsHide: true,
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
      const finish = (result) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        signal?.removeEventListener('abort', abort);
        resolveResult({ stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), durationMs: this.now() - startedAt, timedOut, cancelled, ...result });
      };
      const terminate = () => {
        try { child.kill('SIGTERM'); } catch {}
        const escalation = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} }, 1_000);
        escalation.unref?.();
      };
      const abort = () => { cancelled = true; terminate(); };
      const timeout = setTimeout(() => { timedOut = true; terminate(); }, Math.max(1, timeoutMs || 30_000));
      timeout.unref?.();
      child.once('error', error => finish({ code: null, signal: null, spawnError: error }));
      child.once('close', (code, childSignal) => finish({ code, signal: childSignal }));
      child.stdout?.on('data', chunk => { stdout.push(Buffer.from(chunk)); });
      child.stderr?.on('data', chunk => { stderr.push(Buffer.from(chunk)); });
      signal?.addEventListener('abort', abort, { once: true });
      if (stdin !== undefined && stdin !== null) child.stdin?.end(stdin);
      else child.stdin?.end();
      onProgress?.(0, undefined, 'SSH 操作已开始');
    });
  }

  async resolve(target) {
    const result = await this._run(this.sshBin, ['-G', '--', target], { timeoutMs: 15_000, phase: 'resolve' });
    if (result.spawnError || result.code !== 0) {
      const classified = classifySshFailure(result.stderr, 'resolve');
      throw new OperationFailure(classified.code, `ssh -G 失败：${redactSshError(result.stderr) || '未知错误'}`, { ...classified, cause: result.spawnError });
    }
    return { stdout: result.stdout.toString('utf8'), stderr: result.stderr.toString('utf8') };
  }

  async openMaster(target, controlPath) {
    const config = await this.config.load();
    const args = [
      '-M', '-N', '-f',
      '-o', 'ControlMaster=yes',
      '-o', `ControlPersist=${Math.ceil(config.connectionPersistMs / 1000)}`,
      '-o', `ControlPath=${controlPath}`,
      '-o', `StrictHostKeyChecking=${config.strictHostKeyChecking}`,
      '--', target.id,
    ];
    const result = await this._run(this.sshBin, args, { target: target.id, timeoutMs: config.defaultTimeoutMs, phase: 'connect' });
    if (result.code !== 0 || result.spawnError) {
      const classified = classifySshFailure(result.stderr, 'connect');
      const error = new OperationFailure(classified.code, `无法建立 SSH 连接：${redactSshError(result.stderr) || '未知错误'}`, { ...classified, cause: result.spawnError });
      error.stderr = result.stderr.toString('utf8');
      throw error;
    }
  }

  async checkMaster(target, controlPath) {
    const result = await this._run(this.sshBin, ['-O', 'check', ...controlArgs(controlPath), '--', target.id], {
      target: target.id, timeoutMs: 10_000, phase: 'connect',
    });
    return { ok: result.code === 0, stderr: result.stderr.toString('utf8') };
  }

  async closeMaster(target, controlPath) {
    const result = await this._run(this.sshBin, ['-O', 'exit', ...controlArgs(controlPath), '--', target.id], {
      target: target.id, timeoutMs: 10_000, phase: 'cleanup',
    });
    return { ok: result.code === 0, stderr: redactSshError(result.stderr) };
  }

  async exec({ target, command, controlPath, timeoutMs, signal, stdin, onProgress }) {
    const config = await this.config.load();
    const result = await this._run(this.sshBin, [
      ...controlArgs(controlPath), '-o', `StrictHostKeyChecking=${config.strictHostKeyChecking}`,
      '--', target.id, command,
    ], { target: target.id, timeoutMs, signal, stdin, phase: 'execute', onProgress });
    return { ...result, stdout: result.stdout.toString('utf8'), stderr: redactSshError(result.stderr.toString('utf8')) };
  }

  async transfer({ direction, target, localPath, remotePath, recursive = false, preserve = false, controlPath, timeoutMs, signal, onProgress }) {
    const config = await this.config.load();
    const remote = `${target.id}:${remotePath}`;
    const args = [
      ...controlArgs(controlPath), '-o', `StrictHostKeyChecking=${config.strictHostKeyChecking}`,
      ...(recursive ? ['-r'] : []), ...(preserve ? ['-p'] : []), '--',
      ...(direction === 'upload' ? [localPath, remote] : [remote, localPath]),
    ];
    const result = await this._run(this.scpBin, args, { target: target.id, timeoutMs, signal, phase: 'transfer', onProgress });
    return { ...result, stdout: result.stdout.toString('utf8'), stderr: redactSshError(result.stderr.toString('utf8')) };
  }

  async probe(target, { timeoutMs = 10_000 } = {}) {
    const result = await this._run(this.sshBin, ['-o', 'BatchMode=yes', '-o', `ConnectTimeout=${Math.ceil(timeoutMs / 1000)}`, '--', target, 'true'], {
      target, timeoutMs, phase: 'connect',
    });
    return { ok: result.code === 0, stderr: redactSshError(result.stderr.toString('utf8')), durationMs: result.durationMs };
  }
}

function controlMasterUnavailable(error) {
  const text = `${error?.message || ''}\n${error?.stderr || ''}`;
  return /unknown configuration option.*control|controlmaster.*(?:not supported|unsupported)|controlpath.*(?:not supported|unsupported)/i.test(text);
}

export { OpenSshAdapter, classifySshFailure, redactSshError, controlArgs, controlMasterUnavailable };
