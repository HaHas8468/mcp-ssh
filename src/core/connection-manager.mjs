import { createHash, randomUUID } from 'crypto';
import { mkdir, chmod, readFile, rm, stat, unlink, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { isWindows } from '../shared.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';
import { controlMasterUnavailable } from '../adapters/openssh-adapter.mjs';
import { throwIfAborted, waitForAbortable } from './operation-control.mjs';

function connectionKey(target) {
  return `${target.id}:${target.configFingerprint}`;
}

function controlFileName(target) {
  return createHash('sha256').update(connectionKey(target)).digest('hex').slice(0, 40);
}

async function secureDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  if (!isWindows) await chmod(path, 0o700);
}

function processAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; }
  catch (error) { return error?.code === 'EPERM'; }
}

async function delay(ms, signal) {
  await waitForAbortable(new Promise(resolve => {
    setTimeout(resolve, ms);
  }), { signal, phase: 'connect' });
}

class ConnectionManager {
  constructor({ adapter, config, controlDirectory, now = () => Date.now(), platform = process.platform, lockStaleMs = 30_000 } = {}) {
    this.adapter = adapter;
    this.config = config;
    this.controlDirectory = controlDirectory;
    this.now = now;
    this.platform = platform;
    this.lockStaleMs = lockStaleMs;
    this.records = new Map();
    this.instanceId = randomUUID();
  }

  _record(target) {
    const key = connectionKey(target);
    let record = this.records.get(key);
    if (!record) {
      record = {
        key, targetId: target.id, configFingerprint: target.configFingerprint,
        controlPath: join(this.controlDirectory, controlFileName(target)), state: 'cold',
        lastCheckedAt: 0, lastUsedAt: 0, connecting: null, generation: 0,
        requiresCheck: true,
      };
      this.records.set(key, record);
    }
    return record;
  }

  _lease(target, record, startedAt, { reused, connectStartedAt } = {}) {
    return {
      target,
      key: record.key,
      generation: record.generation,
      generationToken: record.generationToken,
      connectionReused: Boolean(reused),
      connectMs: connectStartedAt ? this.now() - connectStartedAt : 0,
      connectionWaitMs: connectStartedAt ? connectStartedAt - startedAt : this.now() - startedAt,
      controlPath: record.state === 'ready' ? record.controlPath : null,
      state: record.state,
    };
  }

  async ensureReady(target, { signal, deadline, forceCheck = false } = {}) {
    throwIfAborted({ signal, deadline, phase: 'connect' });
    const settings = await this.config.load();
    const startedAt = this.now();
    if (this.platform === 'win32' || settings.controlMaster === false) {
      return { target, key: connectionKey(target), generation: 0, connectionReused: false, connectMs: 0, connectionWaitMs: 0, controlPath: null, state: 'disabled' };
    }
    await secureDirectory(this.controlDirectory);
    throwIfAborted({ signal, deadline, phase: 'connect' });
    const record = this._record(target);
    const socketExists = existsSync(record.controlPath);
    const age = this.now() - record.lastCheckedAt;
    if (record.state === 'ready' && socketExists && !forceCheck && !record.requiresCheck && age <= settings.connectionHealthTtlMs) {
      record.lastUsedAt = this.now();
      return this._lease(target, record, startedAt, { reused: true });
    }
    const joinedExisting = Boolean(record.connecting);
    if (!record.connecting) this._startConnection(record, target, settings);
    await this._waitForConnection(record, { signal, deadline });
    return this._lease(target, record, startedAt, {
      reused: joinedExisting || record.lastConnectAdopted,
      connectStartedAt: joinedExisting ? undefined : record.connectStartedAt,
    });
  }

  _startConnection(record, target, settings) {
    const controller = new AbortController();
    const connecting = { controller, waiters: 0, settled: false, promise: null };
    record.state = 'connecting';
    record.connectStartedAt = this.now();
    record.lastConnectAdopted = false;
    connecting.promise = this._connectOrAdopt(record, target, settings, controller.signal)
      .finally(() => {
        connecting.settled = true;
        if (record.connecting === connecting) record.connecting = null;
      });
    // A waiter observes and reports the rejection. Avoid an unhandled rejection
    // in the narrow interval before it installs its handler.
    connecting.promise.catch(() => {});
    record.connecting = connecting;
  }

  async _waitForConnection(record, { signal, deadline }) {
    const connecting = record.connecting;
    if (!connecting) return;
    connecting.waiters += 1;
    try {
      await waitForAbortable(connecting.promise, { signal, deadline, phase: 'connect' });
    } finally {
      connecting.waiters -= 1;
      if (!connecting.settled && connecting.waiters === 0) connecting.controller.abort({ code: 'NO_WAITERS' });
    }
  }

  async _connectOrAdopt(record, target, settings, signal) {
    try {
      await this._withControlLock(record.controlPath, signal, async () => {
        throwIfAborted({ signal, phase: 'connect' });
        if (existsSync(record.controlPath)) {
          const health = await this.adapter.checkMaster(target, record.controlPath, { signal });
          record.lastCheckedAt = this.now();
          if (health.ok) {
            record.lastConnectAdopted = true;
            record.state = 'ready';
            record.lastUsedAt = this.now();
            record.requiresCheck = false;
            record.generation += 1;
            record.generationToken = await this._readGeneration(record.controlPath) || randomUUID();
            await this._writeGeneration(record.controlPath, record.generationToken);
            return;
          }
          await this._removeSocket(record.controlPath);
        }
        throwIfAborted({ signal, phase: 'connect' });
        await this.adapter.openMaster(target, record.controlPath, { signal });
        record.generation += 1;
        record.generationToken = randomUUID();
        await this._writeGeneration(record.controlPath, record.generationToken);
        record.state = 'ready';
        record.createdAt = this.now();
        record.lastUsedAt = this.now();
        record.lastCheckedAt = this.now();
        record.requiresCheck = false;
      });
    } catch (error) {
      if (controlMasterUnavailable(error)) {
        record.state = 'disabled';
        return;
      }
      record.state = 'stale';
      record.failure = error?.operationError || { message: error?.message };
      if (error instanceof OperationFailure && [ERROR_CODES.REMOTE_COMMAND_CANCELLED, ERROR_CODES.REMOTE_COMMAND_TIMEOUT].includes(error.operationError.code)) throw error;
      if (signal.aborted) {
        throw new OperationFailure(ERROR_CODES.REMOTE_COMMAND_CANCELLED, 'SSH 连接准备已取消。', { phase: 'connect', retryable: false, cause: error });
      }
      const hop = await this._firstFailedHop(target, { signal }).catch(() => null);
      const details = error?.operationError || { phase: 'connect', retryable: true };
      throw new OperationFailure(
        details.code || ERROR_CODES.SSH_MASTER_FAILED,
        details.message || `无法建立 '${target.id}' 的 SSH 主连接。`,
        { ...details, ...(hop ? { hop } : {}), cause: error },
      );
    }
  }

  async _withControlLock(controlPath, signal, callback) {
    const lockPath = `${controlPath}.lock`;
    const ownerPath = join(lockPath, 'owner.json');
    while (true) {
      throwIfAborted({ signal, phase: 'connect' });
      try {
        await mkdir(lockPath, { mode: 0o700 });
        await writeFile(ownerPath, JSON.stringify({ pid: process.pid, timestamp: this.now(), instanceId: this.instanceId }), { mode: 0o600 });
        break;
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
        let owner;
        try { owner = JSON.parse(await readFile(ownerPath, 'utf8')); } catch {}
        let lockAge = 0;
        try { lockAge = this.now() - (await stat(lockPath)).mtimeMs; } catch {}
        const stale = owner ? !processAlive(Number(owner.pid)) : lockAge >= this.lockStaleMs;
        if (stale) {
          await rm(lockPath, { recursive: true, force: true });
          continue;
        }
        await delay(25, signal);
      }
    }
    try { return await callback(); }
    finally { await rm(lockPath, { recursive: true, force: true }); }
  }

  async _removeSocket(path) {
    try { await unlink(path); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }

  _generationPath(controlPath) { return `${controlPath}.generation`; }

  async _readGeneration(controlPath) {
    try { return (await readFile(this._generationPath(controlPath), 'utf8')).trim() || null; }
    catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
  }

  async _writeGeneration(controlPath, token) {
    await writeFile(this._generationPath(controlPath), `${token}\n`, { mode: 0o600 });
  }

  async invalidate(lease, { close = true } = {}) {
    if (!lease?.key || lease.controlPath === null) return false;
    const record = this.records.get(lease.key);
    if (!record || record.generation !== lease.generation || record.generationToken !== lease.generationToken) return false;
    let invalidated = false;
    await this._withControlLock(record.controlPath, undefined, async () => {
      const currentToken = await this._readGeneration(record.controlPath);
      if (record.generation !== lease.generation || record.generationToken !== lease.generationToken || currentToken !== lease.generationToken) return;
      record.state = 'stale';
      record.requiresCheck = true;
      if (close) {
        try { await this.adapter.closeMaster({ id: record.targetId }, record.controlPath); } catch {}
      }
      await this._removeSocket(record.controlPath);
      try { await unlink(this._generationPath(record.controlPath)); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
      invalidated = true;
    });
    return invalidated;
  }

  markForRecheck() {
    for (const record of this.records.values()) record.requiresCheck = true;
  }

  async _firstFailedHop(target, options = {}) {
    const route = target.proxyMode === 'opaque-command' ? [target.route.at(-1)] : target.route;
    for (const hop of route) {
      const probe = await this.adapter.probe(hop.alias, { timeoutMs: 10_000, ...options });
      if (!probe.ok) return { alias: hop.alias, depth: hop.depth };
    }
    const final = route.at(-1);
    return final ? { alias: final.alias, depth: final.depth } : null;
  }

  async drainTarget(targetId) {
    const records = [...this.records.values()].filter(record => record.targetId === targetId);
    await Promise.all(records.map(async record => {
      record.state = 'closing';
      try { await this.adapter.closeMaster({ id: targetId }, record.controlPath); } catch {}
      await this._removeSocket(record.controlPath);
      try { await unlink(this._generationPath(record.controlPath)); } catch {}
      this.records.delete(record.key);
    }));
  }

  list() {
    return [...this.records.values()].map(({ connecting, ...record }) => ({ ...record, connecting: Boolean(connecting) }));
  }
}

export { ConnectionManager, connectionKey, controlFileName, secureDirectory, processAlive };
