import { watch } from 'fs';
import { dirname } from 'path';
import { createRequire } from 'module';
import { RuntimeConfig, runtimePaths } from '../adapters/runtime-config.mjs';
import { CredentialProvider } from '../adapters/credential-provider.mjs';
import { AuditLogger } from '../adapters/audit-logger.mjs';
import { OpenSshAdapter } from '../adapters/openssh-adapter.mjs';
import { JsonStateStore } from '../adapters/local-state-store.mjs';
import { TargetCatalog } from '../core/target-catalog.mjs';
import { RouteResolver } from '../core/route-resolver.mjs';
import { ConnectionManager } from '../core/connection-manager.mjs';
import { OutputStore } from '../core/output-store.mjs';
import { TaskStore } from '../core/task-store.mjs';
import { PolicyGuard } from '../services/policy-guard.mjs';
import { TargetService } from '../services/target-service.mjs';
import { ExecService } from '../services/exec-service.mjs';
import { FileService } from '../services/file-service.mjs';
import { TransferService } from '../services/transfer-service.mjs';
import { TaskService } from '../services/task-service.mjs';
import { getToolDefinitions } from './tools.mjs';
import { presentResult } from './presenters.mjs';
import { parseResourceUri, targetUri } from './resources.mjs';
import { redactTarget } from '../domain/target.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';
import { debugLog } from '../shared.mjs';
import { ServiceLifecycle } from '../core/service-lifecycle.mjs';

const require = createRequire(import.meta.url);

function createV3Runtime(overrides = {}) {
  const paths = overrides.paths || runtimePaths();
  const config = overrides.config || new RuntimeConfig(overrides.configPath);
  const adapter = overrides.adapter || new OpenSshAdapter({ config, sshConfigPath: overrides.sshConfigPath });
  const catalog = overrides.catalog || new TargetCatalog({ adapter, config, configPath: overrides.sshConfigPath });
  if (!adapter.credentials) adapter.credentials = overrides.credentials || new CredentialProvider({ catalog });
  const resolver = overrides.resolver || new RouteResolver({ catalog, config });
  const connections = overrides.connections || new ConnectionManager({ adapter, config, controlDirectory: paths.control });
  const lifecycle = overrides.lifecycle || new ServiceLifecycle({ adapter, connections });
  const outputStore = overrides.outputStore || new OutputStore({ directory: paths.outputs });
  const taskStore = overrides.taskStore || new TaskStore({ store: new JsonStateStore(paths.tasks, { defaultValue: { tasks: {} } }) });
  const policy = overrides.policy || new PolicyGuard();
  const audit = overrides.audit || new AuditLogger({ path: paths.audit });
  return {
    paths, config, adapter, catalog, resolver, connections, lifecycle, outputStore, taskStore, policy, audit,
    targets: new TargetService({ catalog, resolver, adapter }),
    exec: new ExecService({ resolver, connections, adapter, config, outputStore, taskStore, policy }),
    file: new FileService({ resolver, connections, adapter, config, policy }),
    transfer: new TransferService({ resolver, connections, adapter, config, policy }),
    task: new TaskService({ taskStore, resolver, connections, adapter, config }),
  };
}

async function requestApproval(server, { target, danger }, signal) {
  try {
    const result = await server.elicitInput({
      mode: 'form', message: `请求在 ${target} 上执行危险操作：${danger.message}`,
      requestedSchema: { type: 'object', properties: { approved: { type: 'boolean', title: '批准执行' } }, required: ['approved'] },
    }, { signal });
    return result.action === 'accept' && result.content?.approved === true;
  } catch {
    return false;
  }
}

async function createServer({ runtime = createV3Runtime(), Server: ServerOverride } = {}) {
  const { Server } = ServerOverride ? { Server: ServerOverride } : require('@modelcontextprotocol/sdk/server/index.js');
  const { CallToolRequestSchema, ListToolsRequestSchema, ListResourcesRequestSchema, ReadResourceRequestSchema } = require('@modelcontextprotocol/sdk/types.js');
  const server = new Server({ name: 'mcp-ssh', version: '3.0.0' }, { capabilities: { tools: {}, resources: {} } });
  if (!runtime.lifecycle) runtime.lifecycle = new ServiceLifecycle({ adapter: runtime.adapter, connections: runtime.connections });
  const outputCleanup = runtime.outputStore?.cleanup?.();
  outputCleanup?.catch(error => debugLog(`输出缓存清理失败：${error.message}\n`));
  const registry = new Map([
    ['ssh_targets', (args, context) => runtime.targets.handle(args, context)],
    ['ssh_exec', (args, context) => runtime.exec.execute(args, context)],
    ['ssh_file', (args, context) => runtime.file.handle(args, context)],
    ['ssh_transfer', (args, context) => runtime.transfer.handle(args, context)],
    ['ssh_task', (args, context) => runtime.task.handle(args, context)],
  ]);

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: getToolDefinitions() }));
  server.setRequestHandler(CallToolRequestSchema, async (request, extra = {}) => {
    const name = request.params.name;
    const handler = registry.get(name);
    if (!handler) return presentResult({ ok: false, requestId: 'unknown', operation: name, timing: {}, data: {}, warnings: [], error: { code: ERROR_CODES.INVALID_ARGUMENT, message: `未知工具：${name}`, phase: 'validate', retryable: false } });
    const progressToken = request.params?._meta?.progressToken;
    const onProgress = progressToken && extra.sendNotification
      ? (progress, total, message) => extra.sendNotification({ method: 'notifications/progress', params: { progressToken, progress, ...(total === undefined ? {} : { total }), ...(message ? { message } : {}) } }).catch(() => {})
      : undefined;
    const operation = runtime.lifecycle.track(extra.signal);
    let result;
    try {
      result = await handler(request.params.arguments || {}, {
        signal: operation.signal,
        onProgress,
        requestApproval: input => requestApproval(server, input, operation.signal),
      });
    } finally {
      operation.done();
    }
    runtime.audit?.log?.({
      requestId: result.requestId, operation: result.operation, target: result.target,
      ok: result.ok, errorCode: result.error?.code, connectionReused: result.timing?.connectionReused,
      totalMs: result.timing?.totalMs,
    });
    return presentResult(result);
  });
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    const targets = await runtime.catalog.list();
    return { resources: targets.map(({ id }) => ({ uri: targetUri(id), name: id, description: `SSH 目标：${id}`, mimeType: 'application/json' })) };
  });
  server.setRequestHandler(ReadResourceRequestSchema, async request => {
    const parsed = parseResourceUri(request.params.uri);
    if (!parsed) throw new Error(`未知资源：${request.params.uri}`);
    if (parsed.kind === 'target') {
      const target = await runtime.resolver.resolve(parsed.target);
      return { contents: [{ uri: request.params.uri, mimeType: 'application/json', text: JSON.stringify(redactTarget(target), null, 2) }] };
    }
    if (parsed.kind === 'output') {
      const output = await runtime.outputStore.read(parsed.requestId, parsed.stream);
      return { contents: [{ uri: request.params.uri, mimeType: 'text/plain', text: output.content }] };
    }
    const log = await runtime.task.logs(parsed.taskId, {});
    return { contents: [{ uri: request.params.uri, mimeType: 'text/plain', text: log.content }] };
  });
  return { server, runtime };
}

async function main() {
  try {
    const { server, runtime } = await createServer();
    const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
    runtime.catalog.subscribe(() => {
      server.notification?.({ method: 'notifications/resources/list_changed' }).catch?.(() => {});
    });
    let configWatcher;
    try {
      const source = runtime.catalog.configPath;
      configWatcher = watch(dirname(source), () => { runtime.catalog.invalidate(); runtime.config.invalidate(); });
    } catch (error) { debugLog(`无法监听 SSH 配置变化：${error.message}\n`); }
    runtime.task.reconcile().catch(error => debugLog(`后台任务协调失败：${error.message}\n`));
    const transport = new StdioServerTransport();
    let shuttingDown = false;
    const shutdown = async signal => {
      if (shuttingDown) return;
      shuttingDown = true;
      debugLog(`mcp-ssh 收到 ${signal}，正在清理活动 SSH 操作。\n`);
      configWatcher?.close();
      await runtime.lifecycle.shutdown(signal);
      try { await server.close(); } catch {}
    };
    for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.once(signal, () => { shutdown(signal).finally(() => { process.exitCode = 0; }); });
    process.on('SIGCONT', () => {
      debugLog('mcp-ssh 收到 SIGCONT，将恢复子进程并强制复检连接。\n');
      runtime.lifecycle.resume();
    });
    const previousClose = transport.onclose;
    transport.onclose = () => {
      previousClose?.();
      shutdown('STDIO_CLOSED').catch(error => debugLog(`stdio 清理失败：${error.message}\n`));
    };
    await server.connect(transport);
    debugLog('mcp-ssh v3.0.0 已就绪。\n');
  } catch (error) {
    debugLog(`mcp-ssh 启动失败：${error.message}\n`);
    process.exitCode = 1;
  }
}

export { createV3Runtime, createServer, main, requestApproval };
