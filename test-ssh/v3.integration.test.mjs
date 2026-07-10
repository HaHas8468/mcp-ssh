import { describe, expect, it } from 'vitest';
import { readFile, chmod, mkdir, mkdtemp, readdir, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFile as execFileCallback } from 'child_process';
import { promisify } from 'util';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const execFile = promisify(execFileCallback);

// The compose topology is intentionally opt-in: CI enables it on Ubuntu after
// Docker is available, while normal local unit runs do not need a daemon.
describe('三级 ProxyJump Docker 拓扑', () => {
  it('只将 jump1 暴露给测试客户端', async () => {
    const compose = await readFile(new URL('./docker-compose.yml', import.meta.url), 'utf8');
    expect(compose).toMatch(/jump1:[\s\S]*ports:/);
    expect(compose).not.toMatch(/jump2:[\s\S]*ports:/);
    expect(compose).not.toMatch(/target:[\s\S]*ports:/);
    expect(compose).toContain('jump1_net');
    expect(compose).toContain('jump2_net');
  });

  it.skipIf(process.env.MCP_SSH_RUN_DOCKER !== 'true')('由 CI 运行真实三级 SSH 路由', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-three-hop-'));
    const config = join(directory, 'config');
    const askpass = join(directory, 'askpass.sh');
    const knownHosts = join(directory, 'known_hosts');
    const sshConfig = [
      'Host jump1', '  HostName 127.0.0.1', '  Port 2222', '  User test', '',
      'Host jump2', '  HostName jump2', '  User test', '',
      'Host target', '  HostName target', '  User test', '  ProxyJump jump1,jump2', '',
      'Host *', '  StrictHostKeyChecking accept-new', `  UserKnownHostsFile ${knownHosts}`, '',
    ].join('\n');
    await writeFile(config, sshConfig);
    await writeFile(askpass, '#!/bin/sh\nprintf %s "$MCP_SSH_PASS"\n');
    await chmod(config, 0o600);
    await chmod(askpass, 0o700);
    const env = { ...process.env, MCP_SSH_PASS: 'hello123', SSH_ASKPASS: askpass, SSH_ASKPASS_REQUIRE: 'force' };
    const controlPath = join(directory, 'control-%C');
    const common = ['-F', config, '-o', 'StrictHostKeyChecking=accept-new', '-o', `ControlPath=${controlPath}`];
    await execFile('ssh', ['-M', '-N', '-f', '-o', 'ControlMaster=yes', '-o', 'ControlPersist=60', ...common, 'target'], { env, timeout: 30_000 });
    const first = await execFile('ssh', [...common, 'target', 'printf three-hop-ok'], { env, timeout: 30_000 });
    const second = await execFile('ssh', [...common, 'target', 'true'], { env, timeout: 30_000 });
    expect(first.stdout).toBe('three-hop-ok');
    expect(second.stderr).toBe('');
    await execFile('ssh', ['-O', 'exit', ...common, 'target'], { env, timeout: 10_000 });
  });

  it.skipIf(process.env.MCP_SSH_RUN_DOCKER !== 'true')('MCP 自愈、取消、双实例与 SIGCONT 端到端回归', async () => {
    // Keep ControlPath short enough for OpenSSH's temporary socket suffix.
    const home = await mkdtemp(join(tmpdir(), 'mm-'));
    const sshDirectory = join(home, '.ssh');
    const runtimeDirectory = join(home, '.mcp-ssh');
    const controlDirectory = join(runtimeDirectory, 'runtime', 'control');
    const config = join(sshDirectory, 'config');
    const knownHosts = join(sshDirectory, 'known_hosts');
    await mkdir(sshDirectory, { recursive: true });
    await mkdir(runtimeDirectory, { recursive: true });
    await writeFile(config, [
      'Host jump1', '  HostName 127.0.0.1', '  Port 2222', '  User test', '# @password: hello123', '',
      'Host jump2', '  HostName jump2', '  User test', '# @password: hello123', '',
      'Host target', '  HostName target', '  User test', '  ProxyJump jump1,jump2', '# @password: hello123', '',
      'Host *', '  StrictHostKeyChecking accept-new', `  UserKnownHostsFile ${knownHosts}`, '',
    ].join('\n'));
    await writeFile(join(runtimeDirectory, 'config.json'), JSON.stringify({
      defaultTimeoutMs: 15_000,
      maxTimeoutMs: 30_000,
      connectionHealthTtlMs: 60_000,
      allowedLocalRoots: [home],
    }));
    await chmod(config, 0o600);

    const clients = [];
    const startClient = async name => {
      const transport = new StdioClientTransport({
        command: process.execPath,
        args: [new URL('../bin/mcp-ssh.js', import.meta.url).pathname],
        cwd: new URL('..', import.meta.url).pathname,
        env: { ...process.env, HOME: home },
        stderr: 'pipe',
      });
      const stderr = [];
      transport.stderr?.on('data', chunk => stderr.push(String(chunk)));
      const client = new Client({ name, version: '1.0.0' });
      await client.connect(transport);
      clients.push({ client, transport, stderr });
      return { client, transport, stderr };
    };
    const callExec = async (client, command, options) => {
      const result = await client.callTool({ name: 'ssh_exec', arguments: { target: 'target', command, timeoutMs: 15_000 } }, undefined, options);
      return result.structuredContent;
    };

    let stoppedPid;
    try {
      const first = await startClient('integration-one');
      expect((await callExec(first.client, 'printf hot-ok')).ok).toBe(true);
      const sockets = (await readdir(controlDirectory)).filter(name => !name.endsWith('.generation') && !name.endsWith('.lock'));
      expect(sockets).toHaveLength(1);
      const controlPath = join(controlDirectory, sockets[0]);

      await execFile('ssh', ['-F', config, '-O', 'exit', '-o', `ControlPath=${controlPath}`, '--', 'target'], { timeout: 10_000 });
      await writeFile(controlPath, 'stale');
      const recovered = await callExec(first.client, 'printf recovered');
      expect(recovered.ok).toBe(true);
      expect(recovered.warnings).not.toContainEqual(expect.objectContaining({ code: 'SSH_MASTER_DEGRADED' }));

      const second = await startClient('integration-two');
      const dual = await Promise.all([callExec(first.client, 'true'), callExec(second.client, 'true')]);
      expect(dual.every(result => result.ok)).toBe(true);

      const cancellation = new AbortController();
      const sleeping = callExec(first.client, 'sleep 60 & echo $! > /tmp/mcp-ssh-cancel-pid; wait', { signal: cancellation.signal });
      await new Promise(resolve => setTimeout(resolve, 500));
      cancellation.abort();
      await expect(sleeping).rejects.toBeTruthy();
      let cleaned;
      for (let attempt = 0; attempt < 10; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 500));
        cleaned = await callExec(first.client, 'pid=$(cat /tmp/mcp-ssh-cancel-pid 2>/dev/null || true); stat=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d " "); [ -z "$stat" ] || case "$stat" in Z*) true;; *) false;; esac');
        if (cleaned.ok) break;
      }
      expect(cleaned.ok).toBe(true);

      stoppedPid = first.transport.pid;
      process.kill(stoppedPid, 'SIGSTOP');
      await execFile('ssh', ['-F', config, '-O', 'exit', '-o', `ControlPath=${controlPath}`, '--', 'target'], { timeout: 10_000 }).catch(() => {});
      await writeFile(controlPath, 'stale-after-stop');
      process.kill(stoppedPid, 'SIGCONT');
      stoppedPid = undefined;
      const resumed = await callExec(first.client, 'printf resumed');
      expect(resumed.ok).toBe(true);
      expect(resumed.warnings).not.toContainEqual(expect.objectContaining({ code: 'SSH_MASTER_DEGRADED' }));
      expect(first.stderr.join('')).not.toMatch(/mux_client|Session open refused|ControlSocket already exists/i);
      expect(second.stderr.join('')).not.toMatch(/mux_client|Session open refused|ControlSocket already exists/i);
    } finally {
      if (stoppedPid) {
        try { process.kill(stoppedPid, 'SIGCONT'); } catch {}
      }
      await Promise.allSettled(clients.map(({ client }) => client.close()));
      try {
        for (const name of await readdir(controlDirectory)) {
          if (name.endsWith('.generation') || name.endsWith('.lock')) continue;
          const socket = join(controlDirectory, name);
          await execFile('ssh', ['-F', config, '-O', 'exit', '-o', `ControlPath=${socket}`, '--', 'target'], { timeout: 10_000 }).catch(() => {});
        }
      } catch {}
      await rm(home, { recursive: true, force: true });
    }
  }, 120_000);
});
