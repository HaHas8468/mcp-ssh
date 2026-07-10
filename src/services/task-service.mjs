import { shQuote } from '../shared.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';
import { createRequestId, emptyTiming, successResult, failureResult } from '../domain/result.mjs';

function taskLogUri(taskId) { return `mcp-ssh://tasks/${encodeURIComponent(taskId)}/log`; }

function parseTaskState(stdout) {
  const values = {};
  for (const line of String(stdout || '').split(/\r?\n/)) {
    const match = line.match(/^__MCP_TASK_([A-Z_]+)=(.*)$/);
    if (match) values[match[1]] = match[2];
  }
  return values;
}

class TaskService {
  constructor({ taskStore, resolver, connections, adapter, config } = {}) {
    this.taskStore = taskStore;
    this.resolver = resolver;
    this.connections = connections;
    this.adapter = adapter;
    this.config = config;
  }

  async handle(args = {}, context = {}) {
    const requestId = createRequestId();
    const startedAt = Date.now();
    const action = args.action || 'list';
    try {
      let data;
      if (action === 'list') data = { tasks: await this.taskStore.list() };
      else if (action === 'status') data = { task: await this.status(args.taskId) };
      else if (action === 'logs') data = await this.logs(args.taskId, args);
      else if (action === 'stop') data = { task: await this.stop(args.taskId, context) };
      else throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, `不支持的 task action: ${action}`, { phase: 'validate' });
      return successResult({ requestId, operation: `task.${action}`, timing: emptyTiming(startedAt), data });
    } catch (error) {
      return failureResult({ requestId, operation: `task.${action}`, timing: emptyTiming(startedAt), error });
    }
  }

  async reconcile() {
    const tasks = await this.taskStore.list();
    await Promise.all(tasks.map(async task => {
      if (!['starting', 'running', 'unknown'].includes(task.state)) return;
      try { await this.status(task.taskId); }
      catch { await this.taskStore.update(task.taskId, { state: 'unknown' }); }
    }));
  }

  async _task(taskId) {
    if (!taskId || typeof taskId !== 'string') throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'taskId 为必填项。', { phase: 'validate' });
    const task = await this.taskStore.get(taskId);
    if (!task) throw new OperationFailure(ERROR_CODES.TASK_NOT_FOUND, `未找到任务 '${taskId}'。`, { phase: 'validate' });
    return task;
  }

  async _transport(task, command, context = {}) {
    const target = await this.resolver.resolve(task.target);
    const lease = await this.connections.ensureReady(target);
    const settings = await this.config.load();
    const result = await this.adapter.exec({ target, command, controlPath: lease.controlPath, timeoutMs: settings.defaultTimeoutMs, signal: context.signal });
    if (result.code !== 0 && result.code !== 1) {
      throw new OperationFailure(ERROR_CODES.TASK_STATE_UNKNOWN, '无法确认远程任务状态。', { phase: 'execute', retryable: false });
    }
    return result;
  }

  async status(taskId) {
    const task = await this._task(taskId);
    const command = [
      'set +e',
      `if kill -0 -- -${Number(task.processGroupId)} 2>/dev/null; then echo '__MCP_TASK_RUNNING=true'; else echo '__MCP_TASK_RUNNING=false'; fi`,
      `if [ -r ${shQuote(task.exitPath)} ]; then echo "__MCP_TASK_EXIT=$(cat ${shQuote(task.exitPath)})"; fi`,
    ].join('\n');
    const result = await this._transport(task, command);
    const state = parseTaskState(result.stdout);
    const nextState = state.RUNNING === 'true' ? 'running' : (state.EXIT !== undefined ? 'exited' : 'unknown');
    const updated = await this.taskStore.update(taskId, { state: nextState, ...(state.EXIT !== undefined ? { exitCode: Number(state.EXIT) } : {}) });
    return { ...updated, running: nextState === 'running', ...(state.EXIT !== undefined ? { exitCode: Number(state.EXIT) } : {}) };
  }

  async logs(taskId, { offset = 0, limit = 128 * 1024 } = {}) {
    const task = await this._task(taskId);
    const start = Math.max(0, Number(offset) || 0);
    const count = Math.min(2 * 1024 * 1024, Math.max(1, Number(limit) || 1));
    const command = [
      'set +e', `__mcp_log=${shQuote(task.logPath)}`,
      '[ -r "$__mcp_log" ] || exit 0',
      'wc -c < "$__mcp_log" | tr -d " " | sed "s/^/__MCP_TASK_SIZE=/"',
      `dd if="$__mcp_log" bs=1 skip=${start} count=${count} 2>/dev/null | base64 | tr -d '\\n' | sed 's/^/__MCP_TASK_LOG=/'`,
    ].join('\n');
    const result = await this._transport(task, command);
    const state = parseTaskState(result.stdout);
    const size = Number(state.SIZE || 0);
    const content = state.LOG ? Buffer.from(state.LOG, 'base64').toString('utf8') : '';
    return { taskId, offset: start, size, content, truncated: start + Buffer.byteLength(content) < size, logRef: taskLogUri(taskId) };
  }

  async stop(taskId, context = {}) {
    const task = await this._task(taskId);
    const pgid = Number(task.processGroupId);
    if (!Number.isSafeInteger(pgid) || pgid < 1) throw new OperationFailure(ERROR_CODES.TASK_STATE_UNKNOWN, '任务缺少有效的进程组。', { phase: 'cleanup' });
    const command = [
      'set +e', `kill -TERM -- -${pgid} 2>/dev/null`, 'sleep 1',
      `if kill -0 -- -${pgid} 2>/dev/null; then kill -KILL -- -${pgid} 2>/dev/null; sleep 0.2; fi`,
      `if kill -0 -- -${pgid} 2>/dev/null; then echo '__MCP_TASK_STOPPED=false'; exit 1; else echo '__MCP_TASK_STOPPED=true'; exit 0; fi`,
    ].join('\n');
    const result = await this._transport(task, command, context);
    const state = parseTaskState(result.stdout);
    const next = state.STOPPED === 'true' ? 'stopped' : 'still_running';
    return await this.taskStore.update(taskId, { state: next, stopResult: next });
  }
}

export { TaskService, taskLogUri, parseTaskState };
