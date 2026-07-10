import { randomUUID } from 'crypto';
import { shQuote, detectDangerousCommand } from '../shared.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';
import { createRequestId, emptyTiming, successResult, failureResult } from '../domain/result.mjs';
import { summarizeBuffer } from '../core/output-store.mjs';
import { classifySshFailure } from '../adapters/openssh-adapter.mjs';

const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

function validateExecution(args) {
  if (!args || typeof args !== 'object') throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, '参数必须是对象。', { phase: 'validate' });
  if (typeof args.target !== 'string' || !args.target) throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'target 为必填项。', { phase: 'validate' });
  if (typeof args.command !== 'string' || !args.command.trim()) throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'command 必须是非空字符串。', { phase: 'validate' });
  if (args.cwd !== undefined && (typeof args.cwd !== 'string' || !args.cwd.startsWith('/'))) {
    throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'cwd 必须是绝对远程路径。', { phase: 'validate' });
  }
  if (args.env !== undefined && (typeof args.env !== 'object' || Array.isArray(args.env))) {
    throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'env 必须是字符串键值对象。', { phase: 'validate' });
  }
  for (const [key, value] of Object.entries(args.env || {})) {
    if (!ENV_KEY_RE.test(key) || typeof value !== 'string') {
      throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, `无效的环境变量 '${key}'。`, { phase: 'validate' });
    }
  }
}

function boundedTimeout(value, config) {
  if (value === undefined || value === null) return config.defaultTimeoutMs;
  const number = Number(value);
  if (!Number.isFinite(number) || number < 1) throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'timeoutMs 必须为正整数。', { phase: 'validate' });
  return Math.min(Math.floor(number), config.maxTimeoutMs);
}

function boundedOutput(value, config) {
  if (value === undefined || value === null) return config.defaultOutputLimitBytes;
  const number = Number(value);
  if (!Number.isFinite(number) || number < 1) throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'outputLimitBytes 必须为正整数。', { phase: 'validate' });
  return Math.min(Math.floor(number), config.maxOutputLimitBytes);
}

function buildExecutionCommand({ requestId, command, cwd, env }) {
  const stateName = `request-${requestId}`;
  const setup = [
    'set +e',
    'umask 077',
    '__mcp_root="${TMPDIR:-/tmp}/.mcp-ssh"',
    'mkdir -p "$__mcp_root" || exit 125',
    `__mcp_state="$__mcp_root/${stateName}"`,
    'printf "started\\npid=%s\\npgid=%s\\n" "$$" "$(ps -o pgid= -p $$ 2>/dev/null | tr -d \' \' || printf %s $$)" > "$__mcp_state"',
    `printf '%s\\n' ${shQuote(`__MCP_SSH_STARTED_${requestId}`)}`,
  ];
  if (cwd) setup.push(`cd -- ${shQuote(cwd)} || exit 125`);
  for (const [key, value] of Object.entries(env || {})) setup.push(`export ${key}=${shQuote(value)}`);
  return [
    ...setup,
    '(', command, ')',
    '__mcp_rc=$?',
    'printf "completed\\nexitCode=%s\\n" "$__mcp_rc" >> "$__mcp_state"',
    `printf '%s%s\\n' ${shQuote(`__MCP_SSH_EXIT_${requestId}=`)} "$__mcp_rc"`,
    'exit "$__mcp_rc"',
  ].join('\n');
}

function buildDetachCommand({ taskId, command, cwd, env }) {
  const logPath = `$__mcp_root/${taskId}.log`;
  const exitPath = `$__mcp_root/${taskId}.exit`;
  const setup = [
    'set -eu', 'umask 077', '__mcp_root="${HOME}/.mcp-ssh/tasks"', 'mkdir -p "$__mcp_root"',
  ];
  if (cwd) setup.push(`cd -- ${shQuote(cwd)}`);
  for (const [key, value] of Object.entries(env || {})) setup.push(`export ${key}=${shQuote(value)}`);
  const child = `(${command}); __mcp_rc=$?; printf '%s\\n' "$__mcp_rc" > ${exitPath}`;
  return [
    ...setup,
    `(setsid sh -c ${shQuote(child)} > ${logPath} 2>&1 < /dev/null & echo $! > "$__mcp_root/${taskId}.pid") &`,
    'sleep 0.05',
    `__mcp_pid=$(cat "$__mcp_root/${taskId}.pid")`,
    `printf '__MCP_SSH_TASK_${taskId}=%s|%s|%s\\n' "$__mcp_pid" "$__mcp_root/${taskId}.log" "$__mcp_root/${taskId}.exit"`,
  ].join('\n');
}

function removeExecutionMarkers(stdout, requestId) {
  let started = false;
  let completed = false;
  let exitCode;
  const output = [];
  for (const line of String(stdout || '').split(/\r?\n/)) {
    if (line === `__MCP_SSH_STARTED_${requestId}`) { started = true; continue; }
    const exit = line.match(new RegExp(`^__MCP_SSH_EXIT_${requestId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}=(-?\\d+)$`));
    if (exit) { completed = true; exitCode = Number(exit[1]); continue; }
    output.push(line);
  }
  return { stdout: output.join('\n').replace(/\n$/, ''), started, completed, exitCode };
}

function outputData(stdout, stderr, limit, requestId, outputStore) {
  const stdoutBuffer = Buffer.from(stdout || '', 'utf8');
  const stderrBuffer = Buffer.from(stderr || '', 'utf8');
  const total = stdoutBuffer.length + stderrBuffer.length;
  const stdoutLimit = total <= limit ? stdoutBuffer.length : Math.floor(limit * (stdoutBuffer.length / Math.max(1, total)));
  const stderrLimit = Math.max(0, limit - stdoutLimit);
  const out = summarizeBuffer(stdoutBuffer, stdoutLimit);
  const err = summarizeBuffer(stderrBuffer, stderrLimit);
  return Promise.all([
    out.truncated ? outputStore.save(requestId, 'stdout', stdoutBuffer) : null,
    err.truncated ? outputStore.save(requestId, 'stderr', stderrBuffer) : null,
  ]).then(([stdoutRef, stderrRef]) => ({
    stdout: { ...out, ...(stdoutRef ? { outputRef: stdoutRef } : {}) },
    stderr: { ...err, ...(stderrRef ? { outputRef: stderrRef } : {}) },
    totalSize: total,
    truncated: Boolean(out.truncated || err.truncated),
  }));
}

class ExecService {
  constructor({ resolver, connections, adapter, config, outputStore, taskStore, policy } = {}) {
    this.resolver = resolver;
    this.connections = connections;
    this.adapter = adapter;
    this.config = config;
    this.outputStore = outputStore;
    this.taskStore = taskStore;
    this.policy = policy;
  }

  async _prepare(targetId) {
    const resolveStartedAt = Date.now();
    const target = await this.resolver.resolve(targetId);
    const resolveMs = Date.now() - resolveStartedAt;
    const lease = await this.connections.ensureReady(target);
    return { target, lease, resolveMs };
  }

  async execute(args, context = {}) {
    const requestId = createRequestId();
    const startedAt = Date.now();
    let target;
    let timing = emptyTiming(startedAt);
    let partialData = {};
    try {
      validateExecution(args);
      const config = await this.config.load();
      const timeoutMs = boundedTimeout(args.timeoutMs, config);
      const outputLimitBytes = boundedOutput(args.outputLimitBytes, config);
      await this.policy?.check(args.target, 'ssh_exec', { command: args.command });
      const danger = this.policy?.dangerous(args.command) || detectDangerousCommand(args.command);
      if (danger.detected) {
        const approved = context.requestApproval ? await context.requestApproval({ target: args.target, command: args.command, danger }) : false;
        if (!approved) throw new OperationFailure(ERROR_CODES.APPROVAL_REQUIRED, `危险操作需要真实用户批准：${danger.message}`, { phase: 'validate', retryable: false });
      }
      const prepared = await this._prepare(args.target);
      target = prepared.target;
      timing.resolveMs = prepared.resolveMs;
      timing.connectionWaitMs = prepared.lease.connectionWaitMs;
      timing.connectMs = prepared.lease.connectMs;
      timing.connectionReused = prepared.lease.connectionReused;
      if (args.detach) return await this._detach({ args, requestId, startedAt, timing, target, lease: prepared.lease, timeoutMs, context });
      const command = buildExecutionCommand({ requestId, command: args.command, cwd: args.cwd, env: args.env });
      const executeStartedAt = Date.now();
      const transport = await this.adapter.exec({ target, command, controlPath: prepared.lease.controlPath, timeoutMs, signal: context.signal, onProgress: context.onProgress });
      timing.executeMs = Date.now() - executeStartedAt;
      const marker = removeExecutionMarkers(transport.stdout, requestId);
      const output = await outputData(marker.stdout, transport.stderr, outputLimitBytes, requestId, this.outputStore);
      partialData = { output };
      timing.totalMs = Date.now() - startedAt;
      if (transport.timedOut || transport.cancelled) {
        const cleanupStartedAt = Date.now();
        const cleanup = await this._cleanupExecution(target, prepared.lease.controlPath, requestId).catch(() => ({ confirmed: false }));
        timing.cleanupMs = Date.now() - cleanupStartedAt;
        throw new OperationFailure(
          transport.cancelled ? ERROR_CODES.REMOTE_COMMAND_CANCELLED : ERROR_CODES.REMOTE_COMMAND_TIMEOUT,
          transport.cancelled ? '远程命令已取消。' : `远程命令超过 ${timeoutMs}ms。`,
          { phase: 'cleanup', retryable: false, mayHaveRun: marker.started && !cleanup.confirmed }
        );
      }
      if (transport.spawnError) {
        throw new OperationFailure(ERROR_CODES.LOCAL_SPAWN_FAILED, '无法启动本地 ssh 进程。', { phase: 'execute', cause: transport.spawnError });
      }
      if (transport.code === 255 && marker.started && !marker.completed) {
        throw new OperationFailure(ERROR_CODES.EXECUTION_STATE_UNKNOWN, 'SSH 连接在远程命令状态确认前断开。', { phase: 'execute', retryable: false, mayHaveRun: true });
      }
      if (transport.code === 255) {
        const category = classifySshFailure(transport.stderr, 'connect');
        throw new OperationFailure(category.code, transport.stderr || 'SSH 连接失败。', { ...category, mayHaveRun: marker.started });
      }
      const exitCode = marker.exitCode ?? transport.code ?? 255;
      const data = { exitCode, output, ...(transport.signal ? { signal: transport.signal } : {}) };
      partialData = data;
      if (exitCode !== 0) {
        const failure = new OperationFailure(ERROR_CODES.REMOTE_COMMAND_FAILED, `远程命令以退出码 ${exitCode} 结束。`, { phase: 'execute', retryable: false, isProtocolError: false });
        return failureResult({ requestId, operation: 'exec', target: target.id, timing, data, warnings: target.warnings, error: failure });
      }
      return successResult({ requestId, operation: 'exec', target: target.id, timing, data, warnings: target.warnings });
    } catch (error) {
      timing.totalMs = Date.now() - startedAt;
      return failureResult({ requestId, operation: 'exec', target: target?.id || args?.target, timing, data: partialData, error });
    }
  }

  async _detach({ args, requestId, startedAt, timing, target, lease, timeoutMs, context }) {
    const taskId = `task_${randomUUID()}`;
    const executeStartedAt = Date.now();
    const transport = await this.adapter.exec({
      target,
      command: buildDetachCommand({ taskId, command: args.command, cwd: args.cwd, env: args.env }),
      controlPath: lease.controlPath, timeoutMs, signal: context.signal, onProgress: context.onProgress,
    });
    timing.executeMs = Date.now() - executeStartedAt;
    timing.totalMs = Date.now() - startedAt;
    const marker = String(transport.stdout).match(new RegExp(`__MCP_SSH_TASK_${taskId}=([^|]+)\\|([^|]+)\\|([^\\r\\n]+)`));
    if (transport.code !== 0 || !marker) {
      throw new OperationFailure(ERROR_CODES.EXECUTION_STATE_UNKNOWN, '后台任务启动状态无法确认。', { phase: 'execute', retryable: false, mayHaveRun: true });
    }
    const task = {
      taskId, requestId, target: target.id, commandSummary: args.command.slice(0, 200),
      remotePid: Number(marker[1]), processGroupId: Number(marker[1]), logPath: marker[2], exitPath: marker[3],
      createdAt: Date.now(), state: 'running',
    };
    await this.taskStore.create(task);
    return successResult({ requestId, operation: 'exec', target: target.id, timing, data: { detached: true, taskId, remotePid: task.remotePid, processGroupId: task.processGroupId, logRef: `mcp-ssh://tasks/${taskId}/log` }, warnings: target.warnings });
  }

  async _cleanupExecution(target, controlPath, requestId) {
    const command = [
      'set +e', `__mcp_state="${'${TMPDIR:-/tmp}'}/.mcp-ssh/request-${requestId}"`,
      '[ -r "$__mcp_state" ] || exit 0',
      '__mcp_pgid=$(sed -n "s/^pgid=//p" "$__mcp_state" | head -n 1)',
      '[ -n "$__mcp_pgid" ] || exit 1',
      'kill -TERM -- "-$__mcp_pgid" 2>/dev/null', 'sleep 1', 'kill -KILL -- "-$__mcp_pgid" 2>/dev/null',
      'kill -0 -- "-$__mcp_pgid" 2>/dev/null && exit 1 || exit 0',
    ].join('\n');
    const result = await this.adapter.exec({ target, command, controlPath, timeoutMs: 5_000 });
    return { confirmed: result.code === 0 };
  }
}

export { ExecService, validateExecution, buildExecutionCommand, buildDetachCommand, removeExecutionMarkers, boundedTimeout, boundedOutput };
