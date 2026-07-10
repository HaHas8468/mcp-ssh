import { lstat, realpath } from 'fs/promises';
import { resolve, relative } from 'path';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';
import { createRequestId, emptyTiming, successResult, failureResult } from '../domain/result.mjs';
import { createDeadline } from '../core/operation-control.mjs';
import { evictDegradedMaster } from '../core/master-recovery.mjs';

function isWithin(path, root) {
  const value = relative(root, path);
  return value === '' || (!value.startsWith('..') && !value.includes(`..${process.platform === 'win32' ? '\\' : '/'}`));
}

async function canonicalLocalPath(path, { allowMissing = false } = {}) {
  const absolute = resolve(String(path || ''));
  try { return await realpath(absolute); }
  catch (error) {
    if (!allowMissing || error?.code !== 'ENOENT') throw error;
    // A download destination can be absent. Canonicalize the closest existing parent.
    const parent = resolve(absolute, '..');
    try { return resolve(await realpath(parent), absolute.slice(parent.length + 1)); }
    catch { return absolute; }
  }
}

class TransferService {
  constructor({ resolver, connections, adapter, config, policy } = {}) {
    this.resolver = resolver;
    this.connections = connections;
    this.adapter = adapter;
    this.config = config;
    this.policy = policy;
  }

  async _assertAllowed(path, allowMissing, settings) {
    if (typeof path !== 'string' || !path) throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'localPath 必须是非空本地路径。', { phase: 'validate' });
    const canonical = await canonicalLocalPath(path, { allowMissing });
    const roots = await Promise.all(settings.allowedLocalRoots.map(root => canonicalLocalPath(root, { allowMissing: true })));
    if (!roots.some(root => isWithin(canonical, root))) {
      throw new OperationFailure(ERROR_CODES.TARGET_NOT_ALLOWED, '本地路径不在 allowedLocalRoots 中。', { phase: 'validate' });
    }
    return canonical;
  }

  async handle(args = {}, context = {}) {
    const requestId = createRequestId();
    const startedAt = Date.now();
    const timing = emptyTiming(startedAt);
    let target;
    let warnings = [];
    try {
      if (!['upload', 'download'].includes(args.action)) throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'action 必须为 upload 或 download。', { phase: 'validate' });
      if (!args.target || typeof args.target !== 'string') throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'target 为必填项。', { phase: 'validate' });
      if (typeof args.remotePath !== 'string' || !args.remotePath || args.remotePath.includes('\0')) throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'remotePath 无效。', { phase: 'validate' });
      const settings = await this.config.load();
      let timeoutMs = settings.defaultTimeoutMs;
      if (args.timeoutMs !== undefined) {
        const requested = Number(args.timeoutMs);
        if (!Number.isSafeInteger(requested) || requested < 1) {
          throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'timeoutMs 必须为正整数。', { phase: 'validate' });
        }
        timeoutMs = Math.min(settings.maxTimeoutMs, requested);
      }
      const deadline = createDeadline(timeoutMs, startedAt);
      const localPath = await this._assertAllowed(args.localPath, args.action === 'download', settings);
      if (args.action === 'upload') {
        try { await lstat(localPath); }
        catch { throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, `本地上传路径不存在：${args.localPath}`, { phase: 'validate' }); }
      }
      await this.policy?.check(args.target, 'ssh_transfer', { path: args.remotePath });
      const resolveAt = Date.now();
      target = await this.resolver.resolve(args.target, { signal: context.signal, deadline });
      timing.resolveMs = Date.now() - resolveAt;
      let lease = await this.connections.ensureReady(target, { signal: context.signal, deadline });
      timing.connectionWaitMs = lease.connectionWaitMs;
      timing.connectMs = lease.connectMs;
      timing.connectionReused = lease.connectionReused;
      warnings = [...(target.warnings || [])];
      const executeAt = Date.now();
      let result = await this.adapter.transfer({
        direction: args.action, target, localPath, remotePath: args.remotePath, recursive: Boolean(args.recursive), preserve: Boolean(args.preserve),
        controlPath: lease.controlPath, timeoutMs, deadline, signal: context.signal, onProgress: context.onProgress,
      });
      if (result.masterDegraded) {
        await evictDegradedMaster(this.connections, lease, result, warnings);
        if (args.action === 'download' && result.code !== 0 && !result.cancelled && !result.timedOut) {
          lease = await this.connections.ensureReady(target, { signal: context.signal, deadline, forceCheck: true });
          result = await this.adapter.transfer({
            direction: args.action, target, localPath, remotePath: args.remotePath, recursive: Boolean(args.recursive), preserve: Boolean(args.preserve),
            controlPath: lease.controlPath, timeoutMs, deadline, signal: context.signal, onProgress: context.onProgress,
          });
          await evictDegradedMaster(this.connections, lease, result, warnings);
        }
      }
      timing.executeMs = Date.now() - executeAt;
      timing.totalMs = Date.now() - startedAt;
      if (result.cancelled || result.timedOut) {
        throw new OperationFailure(ERROR_CODES.TRANSFER_FAILED, result.cancelled ? '传输已取消。' : '传输超时。', { phase: 'transfer', retryable: false, mayHaveRun: args.action === 'upload' });
      }
      if (result.code !== 0) throw new OperationFailure(ERROR_CODES.TRANSFER_FAILED, result.stderr || 'scp 传输失败。', { phase: 'transfer', retryable: false, mayHaveRun: args.action === 'upload' });
      let bytesTransferred = null;
      try { bytesTransferred = (await lstat(localPath)).size; } catch {}
      return successResult({ requestId, operation: `transfer.${args.action}`, target: target.id, timing, data: { localPath, remotePath: args.remotePath, recursive: Boolean(args.recursive), bytesTransferred }, warnings });
    } catch (error) {
      timing.totalMs = Date.now() - startedAt;
      return failureResult({ requestId, operation: `transfer.${args.action || 'unknown'}`, target: target?.id || args.target, timing, warnings, error });
    }
  }
}

export { TransferService, isWithin, canonicalLocalPath };
