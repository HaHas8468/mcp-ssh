import { describe, expect, it } from 'vitest';
import { mkdtemp, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { TargetCatalog } from './core/target-catalog.mjs';
import { RouteResolver } from './core/route-resolver.mjs';
import { ConnectionManager } from './core/connection-manager.mjs';
import { parseProxyJump } from './core/route-resolver.mjs';
import { configFingerprint } from './domain/target.mjs';
import { removeExecutionMarkers } from './services/exec-service.mjs';
import { summarizeBuffer } from './core/output-store.mjs';
import { getToolDefinitions } from './mcp/tools.mjs';
import { EventEmitter } from 'events';
import { OpenSshAdapter } from './adapters/openssh-adapter.mjs';
import { ExecService, buildExecutionCommand } from './services/exec-service.mjs';
import { FileService } from './services/file-service.mjs';

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
