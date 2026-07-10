import { describe, expect, it } from 'vitest';
import { readFile, chmod, mkdtemp, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFile as execFileCallback } from 'child_process';
import { promisify } from 'util';

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
});
