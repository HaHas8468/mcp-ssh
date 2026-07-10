import { describe, expect, it, vi } from 'vitest';
import { mkdtemp, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { TargetCatalog } from './core/target-catalog.mjs';
import { RouteResolver } from './core/route-resolver.mjs';
import { ConnectionManager, controlFileName } from './core/connection-manager.mjs';
import { parseProxyJump } from './core/route-resolver.mjs';
import { configFingerprint } from './domain/target.mjs';
import { removeExecutionMarkers } from './services/exec-service.mjs';
import { summarizeBuffer } from './core/output-store.mjs';
import { getToolDefinitions } from './mcp/tools.mjs';
import { EventEmitter } from 'events';
import { OpenSshAdapter, extractMuxDiagnostics } from './adapters/openssh-adapter.mjs';
import { ExecService, buildDetachCommand, buildExecutionCommand } from './services/exec-service.mjs';
import { FileService } from './services/file-service.mjs';
import { ServiceLifecycle } from './core/service-lifecycle.mjs';
import { throwIfAborted } from './core/operation-control.mjs';

const config = { load: async () => ({ maxRouteDepth: 8, sshConfigCacheTtlMs: 60_000, connectionHealthTtlMs: 60_000, controlMaster: true }) };

describe('v3 route and connection core', () => {
  it('only discovers explicit aliases, including Include files', async () => {
    const root = await mkdtemp(join(tmpdir(), 'mcp-ssh-catalog-'));
    const included = join(root, 'included.conf');
    const main = join(root, 'config');
    await writeFile(included, 'Host target\n  HostName target.internal\nHost *.wild\n  HostName ignored\n');
    await writeFile(main, `Include ${included}\nHost jump\n  HostName jump.internal\nHost *\n  HostName ignored\n`);
    const catalog = new TargetCatalog({ configPath: main, config, adapter: { resolve: async id => ({ stdout: `hostname ${id}.internal\nport 22\n` }) } });
    expect((await catalog.list()).map(item => item.id)).toEqual(['jump', 'target']);
  });

  it('resolves comma-separated recursive ProxyJump routes without exposing proxy commands', async () => {
    const effective = new Map([
      ['target', { config: { hostname: 'target.internal', port: '22', proxyjump: 'jump1,jump2', proxycommand: 'none' }, fingerprint: 'target' }],
      ['jump1', { config: { hostname: 'jump1.internal', port: '2222', proxyjump: 'none', proxycommand: 'none' }, fingerprint: 'jump1' }],
      ['jump2', { config: { hostname: 'jump2.internal', port: '22', proxyjump: 'none', proxycommand: 'none' }, fingerprint: 'jump2' }],
    ]);
    const catalog = { subscribe: () => {}, list: async () => [...effective.keys()].map(id => ({ id })), effective: async id => ({ id, ...effective.get(id) }) };
    const resolver = new RouteResolver({ catalog, config });
    const resolved = await resolver.resolve('target');
    expect(resolved.route.map(hop => hop.alias)).toEqual(['jump1', 'jump2', 'target']);
    expect(resolved.route.map(hop => hop.depth)).toEqual([0, 1, 2]);
    expect(resolved.proxyMode).toBe('jump');
  });

  it('parses user@host:port ProxyJump entries and fingerprints normalized ssh -G output', () => {
    expect(parseProxyJump('alice@jump:2200,jump2')).toEqual([
      { alias: 'jump', hostname: 'jump', user: 'alice', port: 2200 },
      { alias: 'jump2', hostname: 'jump2', user: undefined, port: undefined },
    ]);
    expect(configFingerprint('host x\r\nport 22\r\n')).toBe(configFingerprint('host x\nport 22\n'));
  });

  it('uses one ControlMaster creation for concurrent cold operations', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-control-'));
    let opens = 0;
    const manager = new ConnectionManager({
      config,
      controlDirectory: directory,
      adapter: {
        openMaster: async () => { opens++; await new Promise(resolve => setTimeout(resolve, 10)); },
        checkMaster: async () => ({ ok: true }), closeMaster: async () => ({ ok: true }),
      },
    });
    const target = { id: 'target', configFingerprint: 'a' };
    const leases = await Promise.all(Array.from({ length: 10 }, () => manager.ensureReady(target)));
    expect(opens).toBe(1);
    expect(leases.filter(lease => lease.connectionReused).length).toBe(9);
  });

  it('adopts a healthy socket from a previous process and rebuilds a stale socket once', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-control-'));
    const target = { id: 'target', configFingerprint: 'adopt' };
    const controlPath = join(directory, controlFileName(target));
    await writeFile(controlPath, 'socket-placeholder');
    let opens = 0;
    let checks = 0;
    const healthy = new ConnectionManager({
      config, controlDirectory: directory,
      adapter: {
        checkMaster: async () => { checks++; return { ok: true }; },
        openMaster: async () => { opens++; }, closeMaster: async () => ({ ok: true }),
      },
    });
    const adopted = await healthy.ensureReady(target);
    expect(adopted.connectionReused).toBe(true);
    expect(checks).toBe(1);
    expect(opens).toBe(0);

    const staleTarget = { id: 'target', configFingerprint: 'stale' };
    const stalePath = join(directory, controlFileName(staleTarget));
    await writeFile(stalePath, 'stale-placeholder');
    const adapter = {
      checkMaster: async () => ({ ok: false }),
      openMaster: async (_target, path) => { opens++; await writeFile(path, 'new-socket'); },
      closeMaster: async () => ({ ok: true }),
    };
    const manager = new ConnectionManager({ config, controlDirectory: directory, adapter });
    await Promise.all([manager.ensureReady(staleTarget), manager.ensureReady(staleTarget)]);
    expect(opens).toBe(1);
  });

  it('serializes two managers that share one ControlPath', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-control-'));
    const target = { id: 'target', configFingerprint: 'shared' };
    let opens = 0;
    const adapter = {
      checkMaster: async () => ({ ok: true }),
      openMaster: async (_target, path) => {
        opens++;
        await new Promise(resolve => setTimeout(resolve, 20));
        await writeFile(path, 'socket');
      },
      closeMaster: async () => ({ ok: true }),
    };
    const first = new ConnectionManager({ config, controlDirectory: directory, adapter });
    const second = new ConnectionManager({ config, controlDirectory: directory, adapter });
    const [a, b] = await Promise.all([first.ensureReady(target), second.ensureReady(target)]);
    expect(opens).toBe(1);
    expect([a.connectionReused, b.connectionReused].filter(Boolean)).toHaveLength(1);
  });

  it('does not let an old lease evict a newer master generation', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-control-'));
    const target = { id: 'target', configFingerprint: 'generation' };
    const adapter = {
      checkMaster: async () => ({ ok: true }),
      openMaster: async (_target, path) => writeFile(path, 'socket'),
      closeMaster: async () => ({ ok: true }),
    };
    const manager = new ConnectionManager({ config, controlDirectory: directory, adapter });
    const oldLease = await manager.ensureReady(target);
    expect(await manager.invalidate(oldLease)).toBe(true);
    const newLease = await manager.ensureReady(target);
    expect(newLease.generation).toBeGreaterThan(oldLease.generation);
    expect(await manager.invalidate(oldLease)).toBe(false);
    expect(manager.list()[0].state).toBe('ready');
  });

  it('lets connection waiters cancel independently and aborts creation only after the last waiter leaves', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-control-'));
    let release;
    let sharedSignal;
    let markEntered;
    const entered = new Promise(resolve => { markEntered = resolve; });
    const manager = new ConnectionManager({
      config, controlDirectory: directory,
      adapter: {
        openMaster: async (_target, _path, { signal }) => {
          sharedSignal = signal;
          markEntered();
          await new Promise(resolve => { release = resolve; });
        },
        checkMaster: async () => ({ ok: true }), closeMaster: async () => ({ ok: true }),
      },
    });
    const target = { id: 'target', configFingerprint: 'waiters' };
    const firstController = new AbortController();
    const secondController = new AbortController();
    const first = manager.ensureReady(target, { signal: firstController.signal });
    const second = manager.ensureReady(target, { signal: secondController.signal });
    await entered;
    firstController.abort();
    await expect(first).rejects.toMatchObject({ operationError: { code: 'REMOTE_COMMAND_CANCELLED' } });
    expect(sharedSignal.aborted).toBe(false);
    release();
    await expect(second).resolves.toMatchObject({ state: 'ready' });

    let aborted = false;
    let markOnlyEntered;
    const onlyEntered = new Promise(resolve => { markOnlyEntered = resolve; });
    const manager2 = new ConnectionManager({
      config, controlDirectory: await mkdtemp(join(tmpdir(), 'mcp-ssh-control-')),
      adapter: {
        openMaster: async (_target, _path, { signal }) => new Promise((resolve, reject) => {
          markOnlyEntered();
          signal.addEventListener('abort', () => { aborted = true; reject(new Error('aborted')); }, { once: true });
        }),
        checkMaster: async () => ({ ok: true }), closeMaster: async () => ({ ok: true }),
      },
    });
    const onlyController = new AbortController();
    const only = manager2.ensureReady({ id: 'target', configFingerprint: 'last' }, { signal: onlyController.signal });
    await onlyEntered;
    onlyController.abort();
    await expect(only).rejects.toMatchObject({ operationError: { code: 'REMOTE_COMMAND_CANCELLED' } });
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(aborted).toBe(true);
  });

  it('uses harmless route probes to identify a failed non-opaque hop', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-control-'));
    const manager = new ConnectionManager({
      config, controlDirectory: directory,
      adapter: {
        openMaster: async () => { throw Object.assign(new Error('connection refused'), { operationError: { code: 'SSH_HOP_UNREACHABLE', message: '连接失败', phase: 'connect', retryable: true } }); },
        probe: async alias => ({ ok: alias !== 'jump1' }), checkMaster: async () => ({ ok: true }), closeMaster: async () => ({ ok: true }),
      },
    });
    await expect(manager.ensureReady({ id: 'target', configFingerprint: 'failed', proxyMode: 'jump', route: [{ alias: 'jump1', depth: 0 }, { alias: 'target', depth: 1 }] })).rejects.toMatchObject({ operationError: { hop: { alias: 'jump1', depth: 0 } } });
  });

  it('removes execution metadata and makes oversized output addressable', () => {
    expect(removeExecutionMarkers('__MCP_SSH_STARTED_x\nhello\n__MCP_SSH_EXIT_x=0\n', 'x')).toMatchObject({ stdout: 'hello', started: true, completed: true, exitCode: 0 });
    expect(summarizeBuffer(Buffer.from('abcdef'), 4)).toMatchObject({ head: 'ab', tail: 'ef', size: 6, truncated: true });
  });

  it('declares exactly the five v3 tools and output schemas', () => {
    const tools = getToolDefinitions();
    expect(tools.map(tool => tool.name)).toEqual(['ssh_targets', 'ssh_exec', 'ssh_file', 'ssh_transfer', 'ssh_task']);
    expect(tools.every(tool => tool.outputSchema)).toBe(true);
    expect(tools.find(tool => tool.name === 'ssh_exec').inputSchema.properties.confirmed).toBeUndefined();
  });

  it('passes SSH commands via argv with an option terminator and no local shell', async () => {
    let invocation;
    const adapter = new OpenSshAdapter({
      config: { load: async () => ({ strictHostKeyChecking: 'accept-new' }) },
      credentials: { environment: async () => ({ MCP_SSH_PASS: 'not-in-argv' }) },
      spawn: (binary, args, options) => {
        invocation = { binary, args, options };
        const child = new EventEmitter();
        child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = { end: () => {} };
        child.kill = () => {};
        setTimeout(() => child.emit('close', 0, null), 0);
        return child;
      },
    });
    await adapter.exec({ target: { id: 'safe-target' }, command: 'echo $(untrusted)', timeoutMs: 1000 });
    expect(invocation.options.shell).toBe(false);
    expect(invocation.args).toContain('--');
    expect(invocation.args.slice(-2)).toEqual(['safe-target', 'echo $(untrusted)']);
    expect(JSON.stringify(invocation.args)).not.toContain('not-in-argv');
  });

  it('cancels before spawn and terminates the whole POSIX process group with escalation', async () => {
    let spawns = 0;
    const before = new AbortController();
    before.abort();
    const adapterBefore = new OpenSshAdapter({
      config: { load: async () => ({ strictHostKeyChecking: 'accept-new' }) },
      spawn: () => { spawns++; },
    });
    await expect(adapterBefore.exec({ target: { id: 'target' }, command: 'true', timeoutMs: 1000, signal: before.signal })).rejects.toMatchObject({ operationError: { code: 'REMOTE_COMMAND_CANCELLED' } });
    expect(spawns).toBe(0);

    vi.useFakeTimers();
    try {
      const signals = [];
      let child;
      const adapter = new OpenSshAdapter({
        config: { load: async () => ({ strictHostKeyChecking: 'accept-new' }) },
        platform: 'linux',
        descendantPids: () => [43212],
        killProcess: (pid, signal) => {
          signals.push([pid, signal]);
          if (signal === 'SIGKILL') queueMicrotask(() => child.emit('close', null, 'SIGKILL'));
        },
        spawn: () => {
          child = new EventEmitter();
          child.pid = 43210;
          child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = { end: () => {} };
          return child;
        },
      });
      const controller = new AbortController();
      const running = adapter.exec({ target: { id: 'target' }, command: 'sleep 10', timeoutMs: 10_000, signal: controller.signal });
      await vi.advanceTimersByTimeAsync(0);
      controller.abort();
      await vi.advanceTimersByTimeAsync(1_001);
      await expect(running).resolves.toMatchObject({ cancelled: true, signal: 'SIGKILL' });
      expect(signals).toEqual([
        [-43212, 'SIGTERM'], [43212, 'SIGTERM'], [-43210, 'SIGTERM'],
        [-43212, 'SIGKILL'], [43212, 'SIGKILL'], [-43210, 'SIGKILL'],
      ]);
      expect(adapter.activeProcessCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('strips local mux diagnostics and never fires a stale escalation timer after normal close', async () => {
    const mux = extractMuxDiagnostics('mux_client_request_session: session request failed: Session open refused by peer\nremote warning');
    expect(mux).toMatchObject({ degraded: true, stderr: 'remote warning' });
    vi.useFakeTimers();
    try {
      const signals = [];
      const adapter = new OpenSshAdapter({
        config: { load: async () => ({ strictHostKeyChecking: 'accept-new' }) },
        platform: 'linux', killProcess: (pid, signal) => signals.push([pid, signal]),
        spawn: () => {
          const child = new EventEmitter();
          child.pid = 43211;
          child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.stdin = { end: () => {} };
          queueMicrotask(() => child.emit('close', 0, null));
          return child;
        },
      });
      await adapter.exec({ target: { id: 'target' }, command: 'true', timeoutMs: 1000 });
      await vi.advanceTimersByTimeAsync(2_000);
      expect(signals).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('finishes cancellation on child exit even when a mux master keeps stdio open', async () => {
    vi.useFakeTimers();
    try {
      const signals = [];
      let child;
      const adapter = new OpenSshAdapter({
        config: { load: async () => ({ strictHostKeyChecking: 'accept-new' }) },
        platform: 'linux', descendantPids: () => [],
        killProcess: (pid, signal) => {
          signals.push([pid, signal]);
          if (signal === 'SIGTERM') queueMicrotask(() => child.emit('exit', null, 'SIGTERM'));
        },
        spawn: () => {
          child = new EventEmitter();
          child.pid = 43213;
          child.stdout = Object.assign(new EventEmitter(), { destroy: vi.fn() });
          child.stderr = Object.assign(new EventEmitter(), { destroy: vi.fn() });
          child.stdin = { end: () => {} };
          return child;
        },
      });
      const controller = new AbortController();
      const running = adapter.exec({ target: { id: 'target' }, command: 'sleep 10', timeoutMs: 10_000, signal: controller.signal });
      await vi.advanceTimersByTimeAsync(0);
      controller.abort();
      await expect(running).resolves.toMatchObject({ cancelled: true, signal: 'SIGTERM' });
      await vi.advanceTimersByTimeAsync(2_000);
      expect(signals).toEqual([[-43213, 'SIGTERM']]);
      expect(child.stdout.destroy).toHaveBeenCalledOnce();
      expect(child.stderr.destroy).toHaveBeenCalledOnce();
      expect(adapter.activeProcessCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('evicts a degraded master without replaying a completed command', async () => {
    const target = { id: 'target', configFingerprint: 'a', warnings: [] };
    let executions = 0;
    let invalidations = 0;
    const service = new ExecService({
      resolver: { resolve: async () => target },
      connections: {
        ensureReady: async () => ({ key: 'k', generation: 1, generationToken: 'g', controlPath: '/tmp/c', connectionReused: true, connectMs: 0, connectionWaitMs: 0 }),
        invalidate: async () => { invalidations++; },
      },
      adapter: { exec: async ({ command }) => {
        executions++;
        const id = command.match(/__MCP_SSH_STARTED_([a-f0-9-]+)/)[1];
        return { code: 0, stdout: `__MCP_SSH_STARTED_${id}\nok\n__MCP_SSH_EXIT_${id}=0\n`, stderr: '', masterDegraded: true };
      } },
      outputStore: { save: async () => null }, taskStore: {}, policy: { check: async () => {}, dangerous: () => ({ detected: false }) },
      config: { load: async () => ({ defaultTimeoutMs: 1000, maxTimeoutMs: 1000, defaultOutputLimitBytes: 1024, maxOutputLimitBytes: 1024 }) },
    });
    const result = await service.execute({ target: 'target', command: 'true' });
    expect(result.ok).toBe(true);
    expect(executions).toBe(1);
    expect(invalidations).toBe(1);
    expect(result.warnings).toContainEqual(expect.objectContaining({ code: 'SSH_MASTER_DEGRADED' }));
  });

  it('trusts a completed execution marker even when ssh exits 255', async () => {
    const target = { id: 'target', configFingerprint: 'a', warnings: [] };
    let executions = 0;
    const service = new ExecService({
      resolver: { resolve: async () => target },
      connections: { ensureReady: async () => ({ key: 'k', generation: 1, generationToken: 'g', controlPath: '/tmp/c', connectionReused: true, connectMs: 0, connectionWaitMs: 0 }) },
      adapter: { exec: async ({ command }) => {
        executions++;
        const id = command.match(/__MCP_SSH_STARTED_([a-f0-9-]+)/)[1];
        return { code: 255, stdout: `__MCP_SSH_STARTED_${id}\nfinished\n__MCP_SSH_EXIT_${id}=0\n`, stderr: 'connection closed' };
      } },
      outputStore: { save: async () => null }, taskStore: {}, policy: { check: async () => {}, dangerous: () => ({ detected: false }) },
      config: { load: async () => ({ defaultTimeoutMs: 1000, maxTimeoutMs: 1000, defaultOutputLimitBytes: 1024, maxOutputLimitBytes: 1024 }) },
    });
    const result = await service.execute({ target: 'target', command: 'true' });
    expect(result.ok).toBe(true);
    expect(result.data.exitCode).toBe(0);
    expect(executions).toBe(1);
  });

  it('retries a mux failure once before started and never replays after started', async () => {
    const target = { id: 'target', configFingerprint: 'a', warnings: [] };
    let executions = 0;
    const connections = {
      ensureReady: async () => ({ key: 'k', generation: executions + 1, generationToken: `g${executions + 1}`, controlPath: '/tmp/c', connectionReused: executions > 0, connectMs: 0, connectionWaitMs: 0 }),
      invalidate: async () => true,
    };
    const base = {
      resolver: { resolve: async () => target }, connections,
      outputStore: { save: async () => null }, taskStore: {}, policy: { check: async () => {}, dangerous: () => ({ detected: false }) },
      config: { load: async () => ({ defaultTimeoutMs: 1000, maxTimeoutMs: 1000, defaultOutputLimitBytes: 1024, maxOutputLimitBytes: 1024 }) },
    };
    const retrying = new ExecService({ ...base, adapter: { exec: async ({ command }) => {
      executions++;
      if (executions === 1) return { code: 255, stdout: '', stderr: '', masterDegraded: true };
      const id = command.match(/__MCP_SSH_STARTED_([a-f0-9-]+)/)[1];
      return { code: 0, stdout: `__MCP_SSH_STARTED_${id}\n__MCP_SSH_EXIT_${id}=0\n`, stderr: '' };
    } } });
    expect((await retrying.execute({ target: 'target', command: 'true' })).ok).toBe(true);
    expect(executions).toBe(2);

    executions = 0;
    const uncertain = new ExecService({ ...base, adapter: { exec: async ({ command }) => {
      executions++;
      const id = command.match(/__MCP_SSH_STARTED_([a-f0-9-]+)/)[1];
      return { code: 255, stdout: `__MCP_SSH_STARTED_${id}\n`, stderr: '', masterDegraded: true };
    } } });
    const result = await uncertain.execute({ target: 'target', command: 'true' });
    expect(result.ok).toBe(false);
    expect(result.error).toMatchObject({ code: 'EXECUTION_STATE_UNKNOWN', mayHaveRun: true });
    expect(executions).toBe(1);
  });

  it('resumes child groups, marks connections for recheck, and shuts down active operations', async () => {
    const calls = [];
    const lifecycle = new ServiceLifecycle({
      adapter: { resumeActiveProcesses: () => calls.push('resume'), shutdown: async () => calls.push('shutdown') },
      connections: { markForRecheck: () => calls.push('recheck') },
    });
    const operation = lifecycle.track();
    lifecycle.resume();
    const shutdown = lifecycle.shutdown('SIGTERM');
    expect(operation.signal.aborted).toBe(true);
    operation.done();
    await shutdown;
    expect(calls).toEqual(['resume', 'recheck', 'shutdown']);
  });

  it('keeps exec cwd/env request-local and preserves output behind execution metadata', async () => {
    const outputStore = { save: async requestId => `mcp-ssh://outputs/${requestId}/stdout` };
    const target = { id: 'target', configFingerprint: 'a', warnings: [] };
    const adapter = {
      exec: async ({ command }) => {
        const start = command.match(/__MCP_SSH_STARTED_([a-f0-9-]+)/)[1];
        return { code: 0, stdout: `__MCP_SSH_STARTED_${start}\nhello\n__MCP_SSH_EXIT_${start}=0\n`, stderr: '' };
      },
    };
    const service = new ExecService({
      resolver: { resolve: async () => target }, connections: { ensureReady: async () => ({ controlPath: null, connectionReused: false, connectMs: 0, connectionWaitMs: 0 }) },
      adapter, outputStore, taskStore: {}, policy: { check: async () => {}, dangerous: () => ({ detected: false }) },
      config: { load: async () => ({ defaultTimeoutMs: 1000, maxTimeoutMs: 1000, defaultOutputLimitBytes: 1024, maxOutputLimitBytes: 1024 }) },
    });
    const result = await service.execute({ target: 'target', command: 'pwd', cwd: '/work', env: { NODE_ENV: 'test' } });
    expect(result.ok).toBe(true);
    expect(result.data.output.stdout.content).toBe('hello');
    expect(buildExecutionCommand({ requestId: 'id', command: 'true', cwd: '/one', env: { FOO: 'bar' } })).toContain("export FOO='bar'");
    const detached = buildDetachCommand({ taskId: 'task_id', command: 'true', cwd: '/one', env: { FOO: 'bar' } });
    expect(detached).toContain('setsid "${SHELL:-/bin/sh}" -c');
    expect(detached).toContain("cd -- '/one'");
    expect(detached).toContain("export FOO='bar'");
  });

  it('applies timeoutMs to target resolution before connection or execution', async () => {
    let connected = false;
    let executed = false;
    const service = new ExecService({
      resolver: { resolve: async (_target, options) => {
        await new Promise(resolve => setTimeout(resolve, 10));
        throwIfAborted({ ...options, phase: 'resolve' });
      } },
      connections: { ensureReady: async () => { connected = true; } },
      adapter: { exec: async () => { executed = true; } },
      outputStore: {}, taskStore: {}, policy: { check: async () => {}, dangerous: () => ({ detected: false }) },
      config: { load: async () => ({ defaultTimeoutMs: 5, maxTimeoutMs: 5, defaultOutputLimitBytes: 1024, maxOutputLimitBytes: 1024 }) },
    });
    const result = await service.execute({ target: 'target', command: 'true', timeoutMs: 5 });
    expect(result.error).toMatchObject({ code: 'REMOTE_COMMAND_TIMEOUT', phase: 'resolve' });
    expect(connected).toBe(false);
    expect(executed).toBe(false);
  });

  it('streams file bodies over SSH stdin and reports optimistic-write conflicts', async () => {
    const target = { id: 'target', warnings: [] };
    const captured = [];
    const service = new FileService({
      resolver: { resolve: async () => target }, connections: { ensureReady: async () => ({ controlPath: null, connectionReused: false, connectMs: 0, connectionWaitMs: 0 }) },
      config: { load: async () => ({ defaultTimeoutMs: 1000, defaultOutputLimitBytes: 1024, maxOutputLimitBytes: 1024 }) },
      policy: { check: async () => {} },
      adapter: { exec: async request => { captured.push(request); return { code: 0, stdout: '', stderr: '' }; } },
    });
    const written = await service.handle({ action: 'write', target: 'target', path: '/tmp/example', content: 'hello' });
    expect(written.ok).toBe(true);
    expect(captured[0].stdin).toEqual(Buffer.from('hello'));
    expect(captured[0].command).toContain('cat > "$__mcp_tmp"');
    service.adapter.exec = async () => ({ code: 46, stdout: '', stderr: '' });
    const conflict = await service.handle({ action: 'write', target: 'target', path: '/tmp/example', content: 'hello', expectedSha256: 'a'.repeat(64) });
    expect(conflict.error.code).toBe('FILE_CHANGED');
  });
});
