import { createHash } from 'crypto';
import { mkdir, chmod, unlink } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { isWindows } from '../shared.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';
import { controlMasterUnavailable } from '../adapters/openssh-adapter.mjs';

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

class ConnectionManager {
  constructor({ adapter, config, controlDirectory, now = () => Date.now(), platform = process.platform } = {}) {
    this.adapter = adapter;
    this.config = config;
    this.controlDirectory = controlDirectory;
    this.now = now;
    this.platform = platform;
    this.records = new Map();
  }

  async ensureReady(target) {
    const settings = await this.config.load();
    const startedAt = this.now();
    if (this.platform === 'win32' || settings.controlMaster === false) {
      return { target, connectionReused: false, connectMs: 0, connectionWaitMs: 0, controlPath: null, state: 'disabled' };
    }
    await secureDirectory(this.controlDirectory);
    const key = connectionKey(target);
    let record = this.records.get(key);
    if (!record) {
      record = {
        key, targetId: target.id, configFingerprint: target.configFingerprint,
        controlPath: join(this.controlDirectory, controlFileName(target)), state: 'cold',
        lastCheckedAt: 0, lastUsedAt: 0, connecting: null,
      };
      this.records.set(key, record);
    }
    const hasSocket = existsSync(record.controlPath);
    if (record.state === 'ready' && hasSocket) {
      const age = this.now() - record.lastCheckedAt;
      if (age <= settings.connectionHealthTtlMs) {
        record.lastUsedAt = this.now();
        return { target, connectionReused: true, connectMs: 0, connectionWaitMs: this.now() - startedAt, controlPath: record.controlPath, state: 'ready' };
      }
      const health = await this.adapter.checkMaster(target, record.controlPath);
      record.lastCheckedAt = this.now();
      if (health.ok) {
        record.lastUsedAt = this.now();
        return { target, connectionReused: true, connectMs: 0, connectionWaitMs: this.now() - startedAt, controlPath: record.controlPath, state: 'ready' };
      }
      await this._markStale(record);
    }
    if (record.connecting) {
      await record.connecting;
      return { target, connectionReused: true, connectMs: 0, connectionWaitMs: this.now() - startedAt, controlPath: record.controlPath, state: record.state };
    }
    const connectStartedAt = this.now();
    record.state = 'connecting';
    record.connecting = (async () => {
      try {
        // A file without a working master is never reused.
        if (existsSync(record.controlPath)) await this._removeSocket(record.controlPath);
        await this.adapter.openMaster(target, record.controlPath);
        record.state = 'ready';
        record.createdAt = this.now();
        record.lastUsedAt = this.now();
        record.lastCheckedAt = this.now();
      } catch (error) {
        if (controlMasterUnavailable(error)) {
          record.state = 'disabled';
          return;
        }
        record.state = 'stale';
        record.failure = error?.operationError || { message: error?.message };
        const hop = await this._firstFailedHop(target).catch(() => null);
        const details = error?.operationError || { phase: 'connect', retryable: true };
        throw new OperationFailure(
          details.code || ERROR_CODES.SSH_MASTER_FAILED,
          details.message || `无法建立 '${target.id}' 的 SSH 主连接。`,
          { ...details, ...(hop ? { hop } : {}), cause: error }
        );
      } finally {
        record.connecting = null;
      }
    })();
    await record.connecting;
    return {
      target,
      connectionReused: false,
      connectMs: this.now() - connectStartedAt,
      connectionWaitMs: connectStartedAt - startedAt,
      controlPath: record.state === 'ready' ? record.controlPath : null,
      state: record.state,
    };
  }

  async _removeSocket(path) {
    try { await unlink(path); } catch (error) { if (error?.code !== 'ENOENT') throw error; }
  }

  async _markStale(record) {
    record.state = 'stale';
    await this._removeSocket(record.controlPath);
  }

  async _firstFailedHop(target) {
    // ProxyCommand is intentionally opaque: parsing or replaying it would
    // violate the OpenSSH configuration boundary, so only name the target.
    const route = target.proxyMode === 'opaque-command' ? [target.route.at(-1)] : target.route;
    for (const hop of route) {
      const probe = await this.adapter.probe(hop.alias, { timeoutMs: 10_000 });
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
      this.records.delete(record.key);
    }));
  }

  list() {
    return [...this.records.values()].map(({ connecting, ...record }) => ({ ...record }));
  }
}

export { ConnectionManager, connectionKey, controlFileName, secureDirectory };
