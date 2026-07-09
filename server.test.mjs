import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createRequire } from 'module';
import { EventEmitter } from 'events';

const require = createRequire(import.meta.url);
const sshConfigLib = require('ssh-config');

vi.mock('fs/promises', async () => {
  const actual = await vi.importActual('fs/promises');
  return {
    ...actual,
    readFile: vi.fn(),
    stat: vi.fn(),
    writeFile: vi.fn(),
    chmod: vi.fn(),
    unlink: vi.fn(),
    appendFile: vi.fn(),
    mkdir: vi.fn(),
  };
});

import { readFile, stat, writeFile, chmod } from 'fs/promises';
import {
  SSHConfigParser, SSHClient, SessionManager, TaskManager,
  AuditLogger, PermissionGuard, McpConfig, RateLimiter,
  detectDangerousCommand, shQuote, validateFileMode, main
} from './server.mjs';

function createMockSpawn({ stdout = '', stderr = '', code = 0, error = null } = {}) {
  return vi.fn(() => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.stdin = { write: vi.fn(), end: vi.fn() };
    child.kill = vi.fn(() => {
      setTimeout(() => child.emit('close', null), 2);
    });
    setTimeout(() => {
      if (error) { child.emit('error', error); return; }
      if (stdout) child.stdout.emit('data', Buffer.from(stdout));
      if (stderr) child.stderr.emit('data', Buffer.from(stderr));
      child.emit('close', code);
    }, 5);
    return child;
  });
}

function createMockExecFileAsync({ error = null } = {}) {
  return vi.fn(async () => {
    if (error) throw error;
    return { stdout: '', stderr: '' };
  });
}

function buildBatchOutput(marker, records) {
  return records.map((record, index) => [
    `${marker}_STDOUT_${index}=${Buffer.from(record.stdout || '', 'utf-8').toString('base64')}`,
    `${marker}_STDERR_${index}=${Buffer.from(record.stderr || '', 'utf-8').toString('base64')}`,
    `${marker}_RC_${index}=${record.code}`,
  ].join('\n')).join('\n') + '\n';
}

function mockBatchRun(client, records) {
  return vi.spyOn(client, 'runRemoteCommand').mockImplementation(async (_hostAlias, command) => {
    const marker = command.match(/(MCP_BATCH_[A-Za-z0-9_]+)_STDOUT_0=/)[1];
    return {
      success: true,
      code: 0,
      stdout: buildBatchOutput(marker, records),
      stderr: '',
      duration: 12,
      timedOut: false,
      truncated: false,
      originalStdoutSize: 0,
      originalStderrSize: 0,
    };
  });
}

const SAMPLE_SSH_CONFIG = `
Host prod
    HostName 157.90.89.149
    Port 42077
    User trashmail

Host mail
    HostName 88.198.170.88
    Port 42078
    User saf
    # @password: killer99

Host nohost
    User nobody
`;

const SAMPLE_KNOWN_HOSTS = `157.90.89.149 ssh-ed25519 AAAAC3Nz...
88.198.170.88 ssh-ed25519 AAAAC3Nz...
10.0.0.1 ssh-rsa AAAAB3Nz...
`;

// =============================================================================
// SessionManager Tests
// =============================================================================
describe('SessionManager', () => {
  it('should generate ControlMaster args', () => {
    const sm = new SessionManager();
    const args = sm.getControlArgs();
    if (process.platform === 'win32') {
      expect(args).toEqual([]);
    } else {
      expect(args).toContain('ControlMaster=auto');
      expect(args).toContain('ControlPersist=300');
      expect(args.some(a => a.includes('ControlPath='))).toBe(true);
    }
  });

  it('should generate ControlMaster args when explicitly enabled', () => {
    const config = new McpConfig();
    config._config = { ...config._defaults, controlMaster: true };
    const sm = new SessionManager(config);
    const args = sm.getControlArgs();
    expect(args).toContain('ControlMaster=auto');
    expect(args).toContain('ControlPersist=300');
    expect(args.some(a => a.includes('ControlPath='))).toBe(true);
  });

  it('should create and retrieve sessions', async () => {
    const sm = new SessionManager();
    const session = await sm.getSession('prod');
    expect(session.cwd).toBeNull();
    expect(session.env.size).toBe(0);
    expect(session.lastUsed).toBeDefined();
  });

  it('should build command with cwd and env state', async () => {
    const sm = new SessionManager();
    const session = await sm.getSession('prod');
    session.cwd = '/app';
    session.env.set('NODE_ENV', 'production');
    const cmd = sm.buildCommandWithState('prod', 'npm test');
    expect(cmd).toContain("cd '/app'");
    expect(cmd).toContain("export NODE_ENV='production'");
    expect(cmd).toContain('npm test');
  });

  it('should return original command when no session exists', () => {
    const sm = new SessionManager();
    expect(sm.buildCommandWithState('unknown', 'ls')).toBe('ls');
  });

  it('should update cwd from cd commands', async () => {
    const sm = new SessionManager();
    await sm.getSession('prod');
    sm.updateStateFromCommand('prod', 'cd /var/log', 0);
    expect(sm.sessions.get('prod').cwd).toBe('/var/log');
  });

  it('should not update cwd on failed commands', async () => {
    const sm = new SessionManager();
    await sm.getSession('prod');
    sm.updateStateFromCommand('prod', 'cd /nonexistent', 1);
    expect(sm.sessions.get('prod').cwd).toBeNull();
  });

  it('should track export commands', async () => {
    const sm = new SessionManager();
    await sm.getSession('prod');
    sm.updateStateFromCommand('prod', 'export FOO=bar', 0);
    expect(sm.sessions.get('prod').env.get('FOO')).toBe('bar');
  });

  it('should clear sessions', async () => {
    const sm = new SessionManager();
    await sm.getSession('prod');
    sm.clearSession('prod');
    expect(sm.sessions.has('prod')).toBe(false);
  });

  it('should list sessions', async () => {
    const sm = new SessionManager();
    await sm.getSession('prod');
    await sm.getSession('dev');
    const list = sm.listSessions();
    expect(list).toHaveLength(2);
    expect(list[0].hostAlias).toBe('prod');
  });

  it('should mark session unhealthy and healthy', async () => {
    const sm = new SessionManager();
    await sm.getSession('prod');
    sm.markUnhealthy('prod');
    expect(sm.sessions.get('prod').connectionHealthy).toBe(false);
    sm.markHealthy('prod');
    expect(sm.sessions.get('prod').connectionHealthy).toBe(true);
    expect(sm.sessions.get('prod').retryCount).toBe(0);
  });

  it('should retry with exponential backoff on connection_failed', async () => {
    const sm = new SessionManager();
    let attempts = 0;
    const fn = async () => {
      attempts++;
      if (attempts < 3) {
        const err = new Error('Connection refused');
        err.errorType = 'connection_failed';
        throw err;
      }
      return { success: true };
    };
    const result = await sm.retryWithBackoff(fn, 'prod', { maxRetries: 3, retryDelay: 1, retryBackoffMultiplier: 1 });
    expect(attempts).toBe(3);
    expect(result.success).toBe(true);
  });

  it('should not retry on non-retryable errors', async () => {
    const sm = new SessionManager();
    let attempts = 0;
    const fn = async () => {
      attempts++;
      const err = new Error('Command not found');
      err.errorType = 'command_not_found';
      throw err;
    };
    await expect(sm.retryWithBackoff(fn, 'prod', { maxRetries: 3 })).rejects.toThrow('Command not found');
    expect(attempts).toBe(1);
  });

  it('should throw after max retries', async () => {
    const sm = new SessionManager();
    let attempts = 0;
    const fn = async () => {
      attempts++;
      const err = new Error('Connection refused');
      err.errorType = 'connection_failed';
      throw err;
    };
    await expect(sm.retryWithBackoff(fn, 'prod', { maxRetries: 2, retryDelay: 1, retryBackoffMultiplier: 1 })).rejects.toThrow('Connection refused');
    expect(attempts).toBe(3); // 1 initial + 2 retries
  });

  it('should reset stale ControlMaster before retrying ssh transport errors', async () => {
    const sm = new SessionManager();
    const resetSpy = vi.spyOn(sm, 'resetControlMaster').mockResolvedValue({
      attempted: true,
      ok: true,
      reason: 'local_control_connection',
    });
    let attempts = 0;
    const fn = async () => {
      attempts++;
      if (attempts === 1) {
        const err = new Error('mux_client_request_session: read from master failed');
        err.errorType = 'ssh_error';
        err.sshError = { category: 'local_control_connection', retryable: true };
        err.retryable = true;
        throw err;
      }
      return { success: true };
    };

    const result = await sm.retryWithBackoff(fn, 'prod', { maxRetries: 1, retryDelay: 1, retryBackoffMultiplier: 1 });
    expect(result.success).toBe(true);
    expect(result.retried).toBe(true);
    expect(result.recoveryActions[0].action).toBe('reset_control_master');
    expect(resetSpy).toHaveBeenCalledWith('prod', 'local_control_connection');
  });
});

// =============================================================================
// McpConfig Tests
// =============================================================================
describe('McpConfig', () => {
  it('should load defaults when no config file exists', async () => {
    readFile.mockRejectedValueOnce(new Error('ENOENT'));
    const config = new McpConfig('/nonexistent/config.json');
    const cfg = await config.load();
    expect(cfg.controlPersist).toBe(300);
    expect(cfg.defaultTimeout).toBe(120000);
    expect(cfg.maxRetries).toBe(3);
  });

  it('should load custom values from config file', async () => {
    readFile.mockResolvedValueOnce(JSON.stringify({
      controlPersist: 600,
      maxRetries: 5,
      defaultTimeout: 60000,
    }));
    const config = new McpConfig('/test/config.json');
    const cfg = await config.load();
    expect(cfg.controlPersist).toBe(600);
    expect(cfg.maxRetries).toBe(5);
    expect(cfg.defaultTimeout).toBe(60000);
  });

  it('should merge custom values with defaults', async () => {
    readFile.mockResolvedValueOnce(JSON.stringify({ controlPersist: 120 }));
    const config = new McpConfig('/test/config.json');
    await config.load();
    // Custom value
    expect(config.get('controlPersist')).toBe(120);
    // Default value not overridden
    expect(config.get('maxRetries')).toBe(3);
  });
});

// =============================================================================
// RateLimiter Tests
// =============================================================================
describe('RateLimiter', () => {
  it('should allow requests under the limit', () => {
    const rl = new RateLimiter();
    expect(() => rl.check('host1')).not.toThrow();
    expect(() => rl.check('host1')).not.toThrow();
  });

  it('should track separate buckets per host', () => {
    const rl = new RateLimiter();
    expect(() => rl.check('host1')).not.toThrow();
    expect(() => rl.check('host2')).not.toThrow();
  });

  it('should throw when rate limit exceeded', () => {
    const rl = new RateLimiter();
    // Exhaust the bucket
    for (let i = 0; i < 60; i++) rl.check('limited-host');
    // Next request should throw
    expect(() => rl.check('limited-host')).toThrow(/Rate limit exceeded/);
  });
});

// =============================================================================
// Content Type Detection Tests (via SSHClient)
// =============================================================================
describe('Content type detection', () => {
  let client;
  beforeEach(() => {
    client = new SSHClient();
    client.sessionManager.config._config = { ...client.sessionManager.config._defaults, maxRetries: 0, retryDelay: 1 };
    vi.clearAllMocks();
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
  });

  it('should detect JSON output', async () => {
    client._spawn = createMockSpawn({ stdout: '{"key":"value"}\n', code: 0 });
    const result = await client.runRemoteCommand('test', 'cat config.json');
    expect(result.contentType).toBe('json');
  });

  it('should detect text output', async () => {
    client._spawn = createMockSpawn({ stdout: 'Hello World\n', code: 0 });
    const result = await client.runRemoteCommand('test', 'echo hello');
    expect(result.contentType).toBe('text');
  });

  it('should detect empty output', async () => {
    client._spawn = createMockSpawn({ stdout: '', code: 0 });
    const result = await client.runRemoteCommand('test', 'true');
    expect(result.contentType).toBe('empty');
  });
});

// =============================================================================
// combineOutput (stdout/stderr interleave) Tests
// =============================================================================
describe('combineOutput', () => {
  let client;
  beforeEach(() => {
    client = new SSHClient();
    client.sessionManager.config._config = { ...client.sessionManager.config._defaults, maxRetries: 0, retryDelay: 1 };
    vi.clearAllMocks();
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
  });

  it('should return combined output when combineOutput=true', async () => {
    client._spawn = vi.fn(() => {
      const child = new EventEmitter();
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      child.kill = vi.fn();
      setTimeout(() => {
        child.stdout.emit('data', Buffer.from('stdout-line\n'));
        child.stderr.emit('data', Buffer.from('stderr-line\n'));
        child.emit('close', 0);
      }, 5);
      return child;
    });
    const result = await client.runRemoteCommand('test', 'make', { combineOutput: true });
    expect(result.combined).toBeDefined();
    expect(result.combined).toContain('stdout-line');
    expect(result.combined).toContain('stderr-line');
  });

  it('should not return combined output when combineOutput=false (default)', async () => {
    client._spawn = createMockSpawn({ stdout: 'hello\n', code: 0 });
    const result = await client.runRemoteCommand('test', 'echo hello');
    expect(result.combined).toBeUndefined();
  });
});

// =============================================================================
// Dangerous Command Confirmation (Elicitation) Tests
// =============================================================================
describe('Dangerous command confirmation', () => {
  let client;
  beforeEach(() => {
    client = new SSHClient();
    client.sessionManager.config._config = { ...client.sessionManager.config._defaults, maxRetries: 0, retryDelay: 1 };
    vi.clearAllMocks();
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
  });

  it('should require confirmation for dangerous commands', async () => {
    client._spawn = createMockSpawn({ stdout: '', code: 0 });
    const result = await client.runRemoteCommand('test', 'rm -rf /');
    expect(result.success).toBe(false);
    expect(result.confirmationRequired).toBe(true);
    expect(result.danger.level).toBe('critical');
    expect(client._spawn).not.toHaveBeenCalled();
  });

  it('should execute when confirmed=true', async () => {
    client._spawn = createMockSpawn({ stdout: '', code: 0 });
    const result = await client.runRemoteCommand('test', 'rm -rf /', { confirmed: true });
    expect(result.success).toBe(true);
    expect(client._spawn).toHaveBeenCalled();
  });

  it('should not block safe commands', async () => {
    client._spawn = createMockSpawn({ stdout: 'hello\n', code: 0 });
    const result = await client.runRemoteCommand('test', 'echo hello');
    expect(result.success).toBe(true);
    expect(result.confirmationRequired).toBeUndefined();
  });
});

// =============================================================================
// Keychain fallback Tests
// =============================================================================
describe('Keychain integration', () => {
  let client;
  beforeEach(() => {
    client = new SSHClient();
    client.sessionManager.config._config = { ...client.sessionManager.config._defaults, maxRetries: 0, retryDelay: 1 };
    vi.clearAllMocks();
    stat.mockResolvedValue({ mode: 0o100600 });
  });

  it('should fall back to @password annotation when keytar is not available', async () => {
    readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
    const password = await client.getPasswordForHost('mail');
    // keytar is not installed in test env, should fall back to @password
    expect(password).toBe('killer99');
  });
});

// =============================================================================
// DangerousCommandDetector Tests
// =============================================================================
describe('detectDangerousCommand', () => {
  it('should detect rm -rf /', () => {
    const result = detectDangerousCommand('rm -rf /');
    expect(result.detected).toBe(true);
    expect(result.level).toBe('critical');
  });

  it('should detect rm -rf /*', () => {
    const result = detectDangerousCommand('rm -rf /*');
    expect(result.detected).toBe(true);
  });

  it('should detect mkfs', () => {
    const result = detectDangerousCommand('mkfs.ext4 /dev/sda1');
    expect(result.detected).toBe(true);
    expect(result.level).toBe('critical');
  });

  it('should detect dd to device', () => {
    const result = detectDangerousCommand('dd if=/dev/zero of=/dev/sda bs=1M');
    expect(result.detected).toBe(true);
  });

  it('should detect drop table', () => {
    const result = detectDangerousCommand('mysql -e "drop table users"');
    expect(result.detected).toBe(true);
    expect(result.level).toBe('high');
  });

  it('should detect shutdown', () => {
    const result = detectDangerousCommand('shutdown -h now');
    expect(result.detected).toBe(true);
  });

  it('should detect chmod 777 /', () => {
    const result = detectDangerousCommand('chmod -R 777 /');
    expect(result.detected).toBe(true);
  });

  it('should not flag safe commands', () => {
    expect(detectDangerousCommand('ls -la').detected).toBe(false);
    expect(detectDangerousCommand('cat /etc/hosts').detected).toBe(false);
    expect(detectDangerousCommand('npm install').detected).toBe(false);
    expect(detectDangerousCommand('git pull').detected).toBe(false);
    expect(detectDangerousCommand('rm -rf /tmp/build').detected).toBe(false);
  });
});

// =============================================================================
// Shell quoting / validation Tests
// =============================================================================
describe('shell helpers', () => {
  it('should single-quote shell values safely', () => {
    expect(shQuote('/tmp/a b')).toBe("'/tmp/a b'");
    expect(shQuote("/tmp/it's-here")).toBe("'/tmp/it'\\''s-here'");
    expect(shQuote('/tmp/$(touch pwned)`x`')).toBe("'/tmp/$(touch pwned)`x`'");
  });

  it('should validate octal file modes', () => {
    expect(validateFileMode('644')).toBe('644');
    expect(validateFileMode('0755')).toBe('0755');
    expect(() => validateFileMode('644; rm -rf /')).toThrow(/Invalid file mode/);
  });
});

// =============================================================================
// AuditLogger Tests
// =============================================================================
describe('AuditLogger', () => {
  it('should be enabled by default', () => {
    const logger = new AuditLogger();
    expect(logger.enabled).toBe(true);
  });

  it('should respect MCP_SSH_AUDIT=false', () => {
    const original = process.env.MCP_SSH_AUDIT;
    process.env.MCP_SSH_AUDIT = 'false';
    const logger = new AuditLogger();
    expect(logger.enabled).toBe(false);
    process.env.MCP_SSH_AUDIT = original;
  });
});

// =============================================================================
// PermissionGuard Tests
// =============================================================================
describe('PermissionGuard', () => {
  it('should allow all when no policy exists', async () => {
    const guard = new PermissionGuard('/nonexistent/path.json');
    await expect(guard.check('prod', 'runRemoteCommand', { command: 'ls' })).resolves.not.toThrow();
  });

  it('should block disallowed tools', async () => {
    readFile.mockResolvedValue(JSON.stringify({
      prod: { allowedTools: ['readFile'] }
    }));
    const guard = new PermissionGuard();
    guard._policies = null;
    await guard._loadPolicies();
    await expect(guard.check('prod', 'runRemoteCommand', { command: 'ls' })).rejects.toThrow('not allowed');
  });

  it('should block denied command patterns', async () => {
    readFile.mockResolvedValue(JSON.stringify({
      prod: { allowedTools: '*', denyPatterns: ['rm\\s+-rf'] }
    }));
    const guard = new PermissionGuard();
    guard._policies = null;
    await guard._loadPolicies();
    await expect(guard.check('prod', 'runRemoteCommand', { command: 'rm -rf /tmp' })).rejects.toThrow('blocked by deny');
  });

  it('should match wildcard host patterns', async () => {
    readFile.mockResolvedValue(JSON.stringify({
      'dev-*': { allowedTools: ['runRemoteCommand'] }
    }));
    const guard = new PermissionGuard();
    guard._policies = null;
    await guard._loadPolicies();
    await expect(guard.check('dev-web1', 'runRemoteCommand', {})).resolves.not.toThrow();
    await expect(guard.check('dev-web1', 'writeFile', {})).rejects.toThrow('not allowed');
  });
});

// =============================================================================
// SSHConfigParser Tests (backward compatible)
// =============================================================================
describe('SSHConfigParser', () => {
  let parser;
  beforeEach(() => {
    parser = new SSHConfigParser();
    vi.clearAllMocks();
  });

  it('should parse hosts with hostname, user, port', () => {
    const config = sshConfigLib.parse(SAMPLE_SSH_CONFIG);
    const hosts = parser.extractHostsFromConfig(config, '/home/test/.ssh/config');
    expect(hosts).toHaveLength(2);
    expect(hosts[0]).toMatchObject({ alias: 'prod', hostname: '157.90.89.149', port: 42077, user: 'trashmail' });
  });

  it('should parse @password annotation', () => {
    const config = sshConfigLib.parse(SAMPLE_SSH_CONFIG);
    const hosts = parser.extractHostsFromConfig(config, '/test');
    expect(hosts.find(h => h.alias === 'mail')._password).toBe('killer99');
  });

  it('should skip hosts without hostname', () => {
    const config = sshConfigLib.parse(SAMPLE_SSH_CONFIG);
    const hosts = parser.extractHostsFromConfig(config, '/test');
    expect(hosts.find(h => h.alias === 'nohost')).toBeUndefined();
  });

  it('should cache known hosts within the TTL', async () => {
    stat.mockResolvedValue({ mode: 0o100600 });
    readFile
      .mockResolvedValueOnce(SAMPLE_SSH_CONFIG)
      .mockResolvedValueOnce(SAMPLE_KNOWN_HOSTS);

    const first = await parser.getAllKnownHosts();
    const second = await parser.getAllKnownHosts();

    expect(first.find(h => h.alias === 'prod')).toBeDefined();
    expect(second.find(h => h.alias === 'prod')).toBeDefined();
    expect(readFile).toHaveBeenCalledTimes(2);
  });

  it('should refresh known hosts after cache invalidation', async () => {
    stat.mockResolvedValue({ mode: 0o100600 });
    readFile
      .mockResolvedValueOnce(`Host first\n    HostName 1.1.1.1\n`)
      .mockResolvedValueOnce('')
      .mockResolvedValueOnce(`Host second\n    HostName 2.2.2.2\n`)
      .mockResolvedValueOnce('');

    const first = await parser.getAllKnownHosts();
    parser.invalidateCache();
    const second = await parser.getAllKnownHosts();

    expect(first.find(h => h.alias === 'first')).toBeDefined();
    expect(second.find(h => h.alias === 'second')).toBeDefined();
    expect(readFile).toHaveBeenCalledTimes(4);
  });
});

// =============================================================================
// SSHClient Tests
// =============================================================================
describe('SSHClient', () => {
  let client;
  beforeEach(() => {
    client = new SSHClient();
    // Disable auto-retry for unit tests (retries are tested separately)
    client.sessionManager.config._config = { ...client.sessionManager.config._defaults, maxRetries: 0, retryDelay: 1 };
    vi.clearAllMocks();
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
  });

  describe('runRemoteCommand — exit code fixes', () => {
    it('should return structured result with success/code/errorType', async () => {
      client._spawn = createMockSpawn({ stdout: 'hello\n', code: 0 });
      const result = await client.runRemoteCommand('test', 'echo hello');
      expect(result.success).toBe(true);
      expect(result.code).toBe(0);
      expect(result.errorType).toBeNull();
      expect(result.duration).toBeDefined();
      expect(result.timedOut).toBe(false);
      expect(result.signal).toBeNull();
    });

    it('should return code 1 for null exit code (not 0)', async () => {
      client._spawn = vi.fn(() => {
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();
        setTimeout(() => child.emit('close', null, null), 5);
        return child;
      });
      const result = await client.runRemoteCommand('test', 'cmd');
      expect(result.code).toBe(1);
      expect(result.code).not.toBe(0);
    });

    it('should return 128+signal for signal termination', async () => {
      client._spawn = vi.fn(() => {
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();
        setTimeout(() => child.emit('close', null, 'SIGKILL'), 5);
        return child;
      });
      const result = await client.runRemoteCommand('test', 'cmd');
      expect(result.code).toBe(137);
      expect(result.signal).toBe('SIGKILL');
    });

    it('should return 124 for timeout', async () => {
      let spawnCount = 0;
      client._spawn = vi.fn(() => {
        spawnCount++;
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        if (spawnCount === 1) {
          child.kill = vi.fn(() => {
            setTimeout(() => child.emit('close', null), 2);
          });
        } else {
          child.kill = vi.fn();
          setTimeout(() => {
            child.stdout.emit('data', Buffer.from('MATCHED 12345\nAFTER_TERM \nREMAINING \n'));
            child.emit('close', 0);
          }, 2);
        }
        return child;
      });
      const result = await client.runRemoteCommand('test', 'sleep 999', { timeout: 10 });
      expect(result.code).toBe(124);
      expect(result.timedOut).toBe(true);
      expect(result.errorType).toBe('timeout');
      expect(result.stderr).toContain('timed out');
      expect(result.remoteState.cleanup.terminated).toBe(true);
      expect(result.remoteState.cleanup.matchedPids).toEqual([12345]);
      expect(client._spawn).toHaveBeenCalledTimes(2);
      const cleanupCommand = client._spawn.mock.calls[1][1].at(-1);
      expect(cleanupCommand).toMatch(/pgrep -f "\$__mcp_pattern"/);
      expect(cleanupCommand).toMatch(/__mcp_pattern='\[M\]CP_/);
    });

    it('should classify auth errors', async () => {
      client._spawn = createMockSpawn({ stderr: 'Permission denied (publickey)', code: 255 });
      const result = await client.runRemoteCommand('test', 'ls');
      expect(result.errorType).toBe('auth_failed');
    });

    it('should classify connection errors', async () => {
      client._spawn = createMockSpawn({ stderr: 'Connection refused', code: 255 });
      const result = await client.runRemoteCommand('test', 'ls');
      expect(result.errorType).toBe('connection_failed');
      expect(result.sshError.category).toBe('target_unreachable');
    });

    it('should classify key-exchange closure separately from target unreachable', async () => {
      client._spawn = createMockSpawn({ stderr: 'kex_exchange_identification: Connection closed by remote host', code: 255 });
      const result = await client.runRemoteCommand('test', 'ls');
      expect(result.errorType).toBe('ssh_error');
      expect(result.sshError.category).toBe('remote_exchange_closed');
    });

    it('should classify command not found', async () => {
      client._spawn = createMockSpawn({ stderr: 'not found', code: 127 });
      const result = await client.runRemoteCommand('test', 'badcmd');
      expect(result.errorType).toBe('command_not_found');
    });

    it('should classify marker-derived command exit code', async () => {
      client._spawn = vi.fn((bin, args) => {
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();
        const wrappedCommand = args.at(-1);
        const marker = wrappedCommand.match(/printf '%s\\n' '(MCP_[^']+)START'/)[1];
        setTimeout(() => {
          child.stdout.emit('data', Buffer.from(`${marker}START\n${marker}_RC=127\n`));
          child.emit('close', 0);
        }, 5);
        return child;
      });
      const result = await client.runRemoteCommand('test', 'badcmd');
      expect(result.code).toBe(127);
      expect(result.errorType).toBe('command_not_found');
    });

    it('should keep exit marker on a new line after here-doc commands', async () => {
      client._spawn = vi.fn((_bin, args) => {
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();
        const wrappedCommand = args.at(-1);
        expect(wrappedCommand).toContain("cat <<'PY'\nprint('ok')\nPY\n__mcp_ssh_rc=$?");
        expect(wrappedCommand).not.toContain("PY; echo");
        const marker = wrappedCommand.match(/printf '%s\\n' '(MCP_[^']+)START'/)[1];
        setTimeout(() => {
          child.stdout.emit('data', Buffer.from(`${marker}START\nok\n${marker}_RC=0\n`));
          child.emit('close', 0);
        }, 5);
        return child;
      });

      const script = "cat <<'PY'\nprint('ok')\nPY";
      const result = await client.runRemoteCommand('test', script);
      expect(result.success).toBe(true);
      expect(result.stdout).toBe('ok\n');
    });

    it('should classify generic command failure', async () => {
      client._spawn = createMockSpawn({ stderr: 'error', code: 1 });
      const result = await client.runRemoteCommand('test', 'cmd');
      expect(result.errorType).toBe('command_failed');
    });

    it('should include truncated flag and originalSize', async () => {
      client._spawn = vi.fn(() => {
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();
        setTimeout(() => {
          child.stdout.emit('data', Buffer.from('x'.repeat(10 * 1024 * 1024 + 100)));
          child.emit('close', 0);
        }, 5);
        return child;
      });
      const result = await client.runRemoteCommand('test', 'bigcmd');
      expect(result.truncated).toBe(true);
      expect(result.originalStdoutSize).toBeGreaterThan(10 * 1024 * 1024);
    });
  });

  describe('runRemoteCommand — security', () => {
    it('should reject hostAlias starting with -', async () => {
      client._spawn = createMockSpawn();
      await expect(client.runRemoteCommand('-oProxyCommand=evil', 'ls')).rejects.toThrow(/Invalid hostAlias/);
    });

    it('should reject unknown hostAlias', async () => {
      readFile.mockResolvedValueOnce(`Host test\n    HostName 1.2.3.4\n`).mockResolvedValueOnce('');
      client._spawn = createMockSpawn();
      await expect(client.runRemoteCommand('unknown.com', 'ls')).rejects.toThrow(/Unknown hostAlias/);
    });

    it('should inject ControlMaster args', async () => {
      client.sessionManager.config._config = { ...client.sessionManager.config._defaults, controlMaster: true };
      client._spawn = createMockSpawn({ stdout: '', code: 0 });
      await client.runRemoteCommand('test', 'ls');
      const args = client._spawn.mock.calls[0][1];
      expect(args).toContain('ControlMaster=auto');
      expect(args.some(a => a.includes('ControlPath='))).toBe(true);
    });
  });

  describe('runRemoteCommand — MCP cancellation', () => {
    it('should return cancelled result when signal is already aborted', async () => {
      const controller = new AbortController();
      controller.abort();
      client._spawn = createMockSpawn({ stdout: '', code: 0 });
      const result = await client.runRemoteCommand('test', 'ls', { signal: controller.signal });
      expect(result.errorType).toBe('cancelled');
      expect(result.success).toBe(false);
      expect(client._spawn).not.toHaveBeenCalled();
    });

    it('should kill child process when signal aborts mid-execution', async () => {
      const controller = new AbortController();
      const mockChild = new EventEmitter();
      mockChild.stdout = new EventEmitter();
      mockChild.stderr = new EventEmitter();
      mockChild.kill = vi.fn(() => {
        setTimeout(() => mockChild.emit('close', null, 'SIGTERM'), 2);
      });
      client._spawn = vi.fn(() => mockChild);

      const promise = client.runRemoteCommand('test', 'sleep 100', { signal: controller.signal, timeout: 10000 });

      // Abort after a short delay
      setTimeout(() => controller.abort(), 10);

      const result = await promise;
      expect(result.errorType).toBe('cancelled');
      expect(mockChild.kill).toHaveBeenCalled();
    });
  });

  describe('runRemoteCommand — MCP progress', () => {
    it('should call onProgress callback with bytes received', async () => {
      const progressCalls = [];
      const onProgress = (progress, total, message) => progressCalls.push({ progress, total, message });

      client._spawn = vi.fn(() => {
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();
        setTimeout(() => {
          child.stdout.emit('data', Buffer.from('line1\n'));
          child.stdout.emit('data', Buffer.from('line2\n'));
          child.emit('close', 0);
        }, 5);
        return child;
      });

      await client.runRemoteCommand('test', 'ls', { onProgress });
      expect(progressCalls.length).toBeGreaterThanOrEqual(2);
      expect(progressCalls[0].progress).toBe(6); // 'line1\n' = 6 bytes
      expect(progressCalls[1].progress).toBe(12); // total 12 bytes
    });
  });

  describe('runRemoteCommand — session state', () => {
    it('should track cwd across commands', async () => {
      client._spawn = createMockSpawn({ stdout: '', code: 0 });
      await client.runRemoteCommand('test', 'cd /app');
      client._spawn = createMockSpawn({ stdout: '', code: 0 });
      await client.runRemoteCommand('test', 'ls');
      const cmd = client._spawn.mock.calls[0][1];
      // The second command should include cd /app prefix
      const sshArgsStr = cmd.join(' ');
      // ControlMaster is on, so the second call should have cd prefix in the command
      expect(client.sessionManager.sessions.get('test').cwd).toBe('/app');
    });

    it('should use useSession=false to skip state', async () => {
      client._spawn = createMockSpawn({ stdout: '', code: 0 });
      await client.runRemoteCommand('test', 'cd /app', { useSession: false });
      expect(client.sessionManager.sessions.has('test')).toBe(false);
    });

    it('should return session context delta when requested', async () => {
      client._spawn = createMockSpawn({ stdout: '', code: 0 });
      const result = await client.runRemoteCommand('test', 'cd /srv && export FOO=bar', { showSessionContext: true });
      expect(result.sessionContext.useSession).toBe(true);
      expect(result.sessionContext.delta.cwdChanged).toBe(true);
      expect(result.sessionContext.delta.cwdAfter).toBe('/srv');
      expect(result.sessionContext.delta.envAdded.FOO).toBe('bar');
    });
  });

  describe('File operations', () => {
    it('readFile should decode base64 content', async () => {
      const content = 'Hello World';
      const encoded = Buffer.from(content).toString('base64');
      client._spawn = createMockSpawn({ stdout: encoded + '\n', code: 0 });
      const result = await client.readFile('test', '/etc/hosts');
      expect(result.success).toBe(true);
      expect(result.content).toBe(content);
      expect(result.size).toBe(content.length);
    });

    it('readFile should handle errors', async () => {
      client._spawn = createMockSpawn({ stderr: 'No such file', code: 1 });
      const result = await client.readFile('test', '/nonexistent');
      expect(result.success).toBe(false);
      expect(result.error).toContain('No such file');
    });

    it('readFile should reject truncated command output', async () => {
      vi.spyOn(client, 'runRemoteCommand').mockResolvedValue({
        code: 0,
        stdout: 'SGVsbG8=',
        stderr: '',
        truncated: true,
        originalStdoutSize: 10 * 1024 * 1024 + 1,
        originalStderrSize: 0,
      });
      const result = await client.readFile('test', '/large-file');
      expect(result.success).toBe(false);
      expect(result.errorType).toBe('output_truncated');
      expect(result.truncated).toBe(true);
    });

    it('writeFile should pipe base64 to stdin', async () => {
      const mockChild = new EventEmitter();
      mockChild.stdout = new EventEmitter();
      mockChild.stderr = new EventEmitter();
      mockChild.stdin = { write: vi.fn(), end: vi.fn() };
      mockChild.kill = vi.fn();
      client._spawn = vi.fn(() => {
        setTimeout(() => mockChild.emit('close', 0), 5);
        return mockChild;
      });
      const result = await client.writeFile('test', '/tmp/test.txt', 'Hello');
      expect(result.success).toBe(true);
      expect(result.bytesWritten).toBe(5);
      // Verify base64 was written to stdin
      expect(mockChild.stdin.write).toHaveBeenCalledWith(
        Buffer.from('Hello', 'utf-8').toString('base64')
      );
    });

    it('editFile should apply replacements', async () => {
      const original = 'listen 80;\nserver_name localhost;';
      const encoded = Buffer.from(original).toString('base64');
      // First call: readFile
      client._spawn = createMockSpawn({ stdout: encoded + '\n', code: 0 });
      // We need to mock the writeFile call too
      const writeChild = new EventEmitter();
      writeChild.stdout = new EventEmitter();
      writeChild.stderr = new EventEmitter();
      writeChild.stdin = { write: vi.fn(), end: vi.fn() };
      writeChild.kill = vi.fn();
      let callCount = 0;
      client._spawn = vi.fn(() => {
        callCount++;
        if (callCount === 1) {
          // readFile call
          const c = new EventEmitter();
          c.stdout = new EventEmitter();
          c.stderr = new EventEmitter();
          c.stdin = { write: vi.fn(), end: vi.fn() };
          c.kill = vi.fn();
          setTimeout(() => {
            c.stdout.emit('data', Buffer.from(encoded + '\n'));
            c.emit('close', 0);
          }, 5);
          return c;
        } else {
          // writeFile call
          setTimeout(() => writeChild.emit('close', 0), 5);
          return writeChild;
        }
      });
      const result = await client.editFile('test', '/etc/nginx.conf', [
        { oldText: 'listen 80;', newText: 'listen 443 ssl;' },
      ]);
      expect(result.success).toBe(true);
      expect(result.editsApplied).toBe(1);
    });

    it('listDir should return structured entries', async () => {
      const output = 'f|1024|1700000000.000000000|/test/file.txt\nd|4096|1700000000.000000000|/test/subdir\n';
      client._spawn = createMockSpawn({ stdout: output, code: 0 });
      const result = await client.listDir('test', '/test');
      expect(result.success).toBe(true);
      expect(result.entries).toHaveLength(2);
      expect(result.entries[0].type).toBe('file');
      expect(result.entries[1].type).toBe('directory');
      expect(client._spawn.mock.calls[0][1].at(-1)).toContain('-mindepth 1 -maxdepth 1');
    });

    it('stat should return file metadata', async () => {
      client._spawn = createMockSpawn({ stdout: '1024|644|1700000000|regular file\n', code: 0 });
      const result = await client.stat('test', '/etc/hosts');
      expect(result.success).toBe(true);
      expect(result.size).toBe(1024);
      expect(result.mode).toBe('644');
    });

    it('mkdir should create directories', async () => {
      client._spawn = createMockSpawn({ stdout: '', code: 0 });
      const result = await client.mkdir('test', '/tmp/newdir');
      expect(result.success).toBe(true);
    });

    it('move should rename files', async () => {
      client._spawn = createMockSpawn({ stdout: '', code: 0 });
      const result = await client.move('test', '/tmp/a', '/tmp/b');
      expect(result.success).toBe(true);
    });

    it('remove should detect dangerous paths', async () => {
      client._spawn = createMockSpawn({ stdout: '', code: 0 });
      const result = await client.remove('test', '/');
      expect(result.success).toBe(false);
      expect(result.danger).toBeDefined();
      expect(result.danger.level).toBe('critical');
    });

    it('remove should allow with force=true', async () => {
      client._spawn = createMockSpawn({ stdout: '', code: 0 });
      const result = await client.remove('test', '/tmp/build', { force: true });
      expect(result.success).toBe(true);
    });
  });

  describe('File transfer — error context', () => {
    it('uploadFile should return full error context on failure', async () => {
      const error = new Error('scp failed');
      error.stderr = 'Permission denied';
      client._execFileAsync = createMockExecFileAsync({ error });
      const result = await client.uploadFile('test', '/local', '/remote');
      expect(result.success).toBe(false);
      expect(result.error).toBe('scp failed');
      expect(result.stderr).toBe('Permission denied');
      expect(result.errorType).toBeDefined();
      expect(result.duration).toBeDefined();
    });

    it('uploadFile should return bytesTransferred on success', async () => {
      stat.mockResolvedValue({ size: 1024 });
      client._execFileAsync = createMockExecFileAsync();
      const result = await client.uploadFile('test', '/local', '/remote');
      expect(result.success).toBe(true);
      expect(result.bytesTransferred).toBe(1024);
      expect(result.duration).toBeDefined();
    });

    it('downloadFile should return full error context on failure', async () => {
      const error = new Error('scp failed');
      error.stderr = 'No such file';
      client._execFileAsync = createMockExecFileAsync({ error });
      const result = await client.downloadFile('test', '/remote', '/local');
      expect(result.success).toBe(false);
      expect(result.errorType).toBe('not_found');
    });

    it('uploadDir should use scp -r', async () => {
      client._execFileAsync = createMockExecFileAsync();
      const result = await client.uploadDir('test', '/local/dir', '/remote/dir');
      expect(result.success).toBe(true);
      const scpArgs = client._execFileAsync.mock.calls[0][1];
      expect(scpArgs).toContain('-r');
    });

    it('downloadDir should use scp -r', async () => {
      client._execFileAsync = createMockExecFileAsync();
      const result = await client.downloadDir('test', '/remote/dir', '/local/dir');
      expect(result.success).toBe(true);
      const scpArgs = client._execFileAsync.mock.calls[0][1];
      expect(scpArgs).toContain('-r');
    });

    it('should support preservePermissions option', async () => {
      stat.mockResolvedValue({ size: 100 });
      client._execFileAsync = createMockExecFileAsync();
      await client.uploadFile('test', '/local', '/remote', { preservePermissions: true });
      const scpArgs = client._execFileAsync.mock.calls[0][1];
      expect(scpArgs).toContain('-p');
    });
  });

  describe('runCommandBatch — enhanced', () => {
    it('should return aggregate summary', async () => {
      const runSpy = mockBatchRun(client, [
        { stdout: 'out1\n', code: 0 },
        { stdout: 'out2\n', code: 0 },
      ]);
      const result = await client.runCommandBatch('test', ['cmd1', 'cmd2']);
      expect(result.success).toBe(true);
      expect(result.summary.total).toBe(2);
      expect(result.summary.succeeded).toBe(2);
      expect(result.summary.failed).toBe(0);
      expect(result.summary.totalDuration).toBeDefined();
      expect(result.summary.singleConnection).toBe(true);
      expect(result.results).toHaveLength(2);
      expect(result.results[0].stdout).toBe('out1\n');
      expect(runSpy).toHaveBeenCalledTimes(1);
    });

    it('should stop on first error in stopOnError mode', async () => {
      mockBatchRun(client, [
        { stderr: 'failed\n', code: 1 },
      ]);
      const result = await client.runCommandBatch('test', ['fail', 'pass'], { mode: 'stopOnError' });
      expect(result.success).toBe(false);
      expect(result.results).toHaveLength(1); // only 1 executed
      expect(result.summary.firstFailure.index).toBe(0);
    });

    it('should continue on error in sequential mode', async () => {
      mockBatchRun(client, [
        { stderr: 'failed\n', code: 1 },
        { stdout: 'ok\n', code: 0 },
      ]);
      const result = await client.runCommandBatch('test', ['fail', 'pass'], { mode: 'sequential' });
      expect(result.results).toHaveLength(2);
      expect(result.summary.failed).toBe(1);
    });

    it('should keep legacy per-command execution when singleConnection=false', async () => {
      let callCount = 0;
      client._spawn = vi.fn(() => {
        callCount++;
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();
        setTimeout(() => {
          child.stdout.emit('data', Buffer.from(`legacy${callCount}\n`));
          child.emit('close', 0);
        }, 5);
        return child;
      });
      const result = await client.runCommandBatch('test', ['cmd1', 'cmd2'], { singleConnection: false });
      expect(result.results).toHaveLength(2);
      expect(client._spawn).toHaveBeenCalledTimes(2);
    });

    it('should run in parallel mode', async () => {
      let callCount = 0;
      client._spawn = vi.fn(() => {
        callCount++;
        const child = new EventEmitter();
        child.stdout = new EventEmitter();
        child.stderr = new EventEmitter();
        child.kill = vi.fn();
        setTimeout(() => {
          child.stdout.emit('data', Buffer.from(`out\n`));
          child.emit('close', 0);
        }, 5);
        return child;
      });
      const result = await client.runCommandBatch('test', ['a', 'b', 'c'], { mode: 'parallel', concurrency: 3 });
      expect(result.success).toBe(true);
      expect(result.summary.mode).toBe('parallel');
      expect(result.summary.concurrency).toBe(3);
      expect(result.results).toHaveLength(3);
    });
  });

  describe('Background tasks', () => {
    it('startBackground should return taskId and remotePid', async () => {
      client._spawn = createMockSpawn({ stdout: '12345\n', code: 0 });
      const result = await client.startBackground('test', 'sleep 100');
      expect(result.success).toBe(true);
      expect(result.taskId).toBeDefined();
      expect(result.remotePid).toBe(12345);
      expect(result.processGroupId).toBe(12345);
      expect(client.taskManager.get(result.taskId)).toMatchObject({
        hostAlias: 'test',
        remotePid: 12345,
        processGroupId: 12345,
        command: 'sleep 100',
        logFile: result.logFile,
      });
    });

    it('startBackground should pass through startup timeout', async () => {
      const runSpy = vi.spyOn(client, 'runRemoteCommand').mockResolvedValue({ code: 0, stdout: '12345\n', stderr: '' });
      const result = await client.startBackground('test', 'sleep 100', { timeout: 45678 });
      expect(result.success).toBe(true);
      expect(runSpy).toHaveBeenCalledWith('test', expect.any(String), { useSession: false, timeout: 45678 });
    });

    it('getTaskStatus should return running state', async () => {
      // Register a task first
      client.taskManager.tasks.set('task_test', {
        hostAlias: 'test', remotePid: 12345, command: 'sleep 100',
        startedAt: Date.now(), logFile: '/tmp/mcp-task-task_test.log',
      });
      const runSpy = vi.spyOn(client, 'runRemoteCommand').mockImplementation(async (_hostAlias, command) => {
        const marker = command.match(/(MCP_TASK_\d+_\d+_[a-z0-9]+)/)[1];
        expect(command).toContain('tail -n 200');
        return {
          code: 0,
          stdout: [
            `${marker}_PROCESS_START`,
            '12345 1 12345 S 00:01 sleep',
            'GROUP 12345 sleep 100',
            `${marker}_PROCESS_END`,
            `${marker}_LOG_START`,
            'task log',
            `${marker}_LOG_END`,
          ].join('\n'),
          stderr: '',
          duration: 5,
        };
      });
      const result = await client.getTaskStatus('task_test', { logLines: 200 });
      expect(result.success).toBe(true);
      expect(result.running).toBe(true);
      expect(result.recentLog).toBe('task log');
      expect(result.processGroupId).toBe(12345);
      expect(runSpy).toHaveBeenCalledTimes(1);
    });

    it('getTaskStatus should return structured health, filtered logs, and readiness', async () => {
      client.taskManager.tasks.set('task_health', {
        hostAlias: 'test', remotePid: 12345, processGroupId: 12345, command: 'vllm serve model',
        startedAt: Date.now(), logFile: '/tmp/mcp-task-task_health.log', exitFile: '/tmp/mcp-task-task_health.exit',
      });
      vi.spyOn(client, 'runRemoteCommand').mockImplementation(async (_hostAlias, command) => {
        const marker = command.match(/(MCP_TASK_\d+_\d+_[a-z0-9]+)/)[1];
        expect(command).toContain('grep -E --');
        expect(command).toContain('grep -Ev --');
        expect(command).toContain('tail -c 4096');
        expect(command).toContain('awk -v max=120');
        return {
          code: 0,
          stdout: [
            `${marker}_PROCESS_START`,
            '12345 1 12345 S 00:01 python',
            `${marker}_PROCESS_END`,
            `${marker}_TREE_START`,
            '12345|1|12345|S|00:01|12.5|3.5|204800|python|python -m vllm.entrypoints.openai.api_server',
            `${marker}_TREE_END`,
            `${marker}_PORT_START`,
            'LISTEN 0 4096 0.0.0.0:8000 0.0.0.0:* users:(("python",pid=12345,fd=42))',
            `${marker}_PORT_END`,
            `${marker}_EXIT_START`,
            'exitCode=',
            `${marker}_EXIT_END`,
            `${marker}_LOG_META_START`,
            'size=100',
            'start=0',
            'end=100',
            'onlyNew=false',
            `${marker}_LOG_META_END`,
            `${marker}_LOG_START`,
            'OpenAI API server ready',
            `${marker}_LOG_END`,
          ].join('\n'),
          stderr: '',
          duration: 5,
        };
      });

      const result = await client.getTaskStatus('task_health', {
        grep: 'ready',
        exclude: 'tqdm',
        tailBytes: 4096,
        maxLogLineLength: 120,
        readyPattern: 'ready',
        ports: [8000],
      });
      expect(result.success).toBe(true);
      expect(result.health.ready).toBe(true);
      expect(result.processTree[0].pid).toBe(12345);
      expect(result.resources.rssKb).toBe(204800);
      expect(result.portsListening[0].port).toBe(8000);
      expect(result.log.tailBytes).toBe(4096);
    });

    it('listTasks should return running tasks', async () => {
      client.taskManager.tasks.set('task_1', {
        hostAlias: 'test', remotePid: 123, command: 'ls',
        startedAt: Date.now(), logFile: '/tmp/log',
      });
      client._spawn = createMockSpawn({ stdout: '123 S 00:01 sleep\n', code: 0 });
      const result = await client.listTasks();
      expect(result.tasks).toHaveLength(1);
      expect(result.tasks[0].taskId).toBe('task_1');
      expect(result.tasks[0].running).toBe(true);
      expect(result.tasks[0].processGroupId).toBe(123);
    });

    it('listTasks should prune exited tasks', async () => {
      client.taskManager.tasks.set('task_done', {
        hostAlias: 'test', remotePid: 123, command: 'sleep 1',
        startedAt: Date.now(), logFile: '/tmp/log',
      });
      client._spawn = createMockSpawn({ stdout: 'EXITED\n', code: 0 });
      const result = await client.listTasks();
      expect(result.tasks).toHaveLength(0);
      expect(client.taskManager.get('task_done')).toBeNull();
    });

    it('stopTask should kill process group and remove task after verification', async () => {
      client.taskManager.tasks.set('task_stop', {
        hostAlias: 'test', remotePid: 12345, processGroupId: 12345, command: 'sleep 100',
        startedAt: Date.now(), logFile: '/tmp/log',
      });
      const runSpy = vi.spyOn(client, 'runRemoteCommand').mockImplementation(async (_hostAlias, command) => {
        expect(command).toContain('kill -TERM -- "-$pgid"');
        expect(command).toContain('kill -KILL -- "-$pgid"');
        return { code: 0, stdout: 'STOPPED\n', stderr: '', duration: 5 };
      });

      const result = await client.stopTask('task_stop');
      expect(result.success).toBe(true);
      expect(result.stopped).toBe(true);
      expect(result.processGroupId).toBe(12345);
      expect(client.taskManager.get('task_stop')).toBeNull();
      expect(runSpy).toHaveBeenCalledTimes(1);
    });

    it('stopTask should keep task when remote verification finds remaining processes', async () => {
      client.taskManager.tasks.set('task_stuck', {
        hostAlias: 'test', remotePid: 12345, processGroupId: 12345, command: 'sleep 100',
        startedAt: Date.now(), logFile: '/tmp/log',
      });
      vi.spyOn(client, 'runRemoteCommand').mockResolvedValue({
        code: 0, stdout: 'REMAINING 12345\n', stderr: '', duration: 5,
      });

      const result = await client.stopTask('task_stuck');
      expect(result.success).toBe(false);
      expect(result.errorType).toBe('process_still_running');
      expect(client.taskManager.get('task_stuck')).not.toBeNull();
    });
  });

  describe('Session management', () => {
    it('openSession should establish session', async () => {
      client._spawn = createMockSpawn({ stdout: 'session_opened\n', code: 0 });
      const result = await client.openSession('test');
      expect(result.opened).toBe(true);
    });

    it('listSessions should return active sessions', async () => {
      client._spawn = createMockSpawn({ stdout: '', code: 0 });
      await client.runRemoteCommand('test', 'cd /app');
      const sessions = client.listSessions();
      expect(sessions).toHaveLength(1);
      expect(sessions[0].hostAlias).toBe('test');
      expect(sessions[0].cwd).toBe('/app');
    });
  });

  describe('getHostInfo — backward compatible', () => {
    it('should strip passwords', async () => {
      readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
      stat.mockResolvedValue({ mode: 0o100600 });
      const info = await client.getHostInfo('mail');
      expect(info._password).toBeUndefined();
      expect(info.passwordAuth).toBe(true);
    });
  });

  describe('checkConnectivity — enhanced', () => {
    it('should include latency', async () => {
      client._spawn = createMockSpawn({ stdout: 'connected\n', code: 0 });
      const status = await client.checkConnectivity('test');
      expect(status.connected).toBe(true);
      expect(status.latency).toBeDefined();
    });

    it('should pass through custom timeout', async () => {
      const runSpy = vi.spyOn(client, 'runRemoteCommand').mockResolvedValue({
        code: 0, stdout: 'connected\n', stderr: '', duration: 123,
      });
      const status = await client.checkConnectivity('test', { timeout: 60000 });
      expect(status.connected).toBe(true);
      expect(runSpy).toHaveBeenCalledWith('test', 'echo connected', { useSession: false, timeout: 60000 });
    });
  });

  describe('inspectRemote', () => {
    it('should filter the MCP wrapper process and return matching ports', async () => {
      const runSpy = vi.spyOn(client, 'runRemoteCommand').mockImplementation(async (_hostAlias, command) => {
        const marker = command.match(/(MCP_INSPECT_\d+_\d+_[a-z0-9]+)/)[1];
        return {
          code: 0,
          stdout: [
            `${marker}_PROCESS_START`,
            `999|1|999|S|00:01|0.1|0.1|1000|bash|bash -c ${marker}`,
            '12345|1|12345|S|00:02|4.0|2.0|50000|python|python -m vllm.entrypoints.openai.api_server',
            `${marker}_PROCESS_END`,
            `${marker}_PORT_START`,
            'LISTEN 0 4096 127.0.0.1:8000 0.0.0.0:* users:(("python",pid=12345,fd=7))',
            `${marker}_PORT_END`,
          ].join('\n'),
          stderr: '',
          remotePid: 999,
        };
      });

      const result = await client.inspectRemote('test', { processPattern: 'vllm', ports: [8000] });
      expect(result.success).toBe(true);
      expect(result.processes).toHaveLength(1);
      expect(result.processes[0].pid).toBe(12345);
      expect(result.portsListening[0].port).toBe(8000);
      expect(result.summary.wrapperFiltered).toBe(true);
      expect(runSpy).toHaveBeenCalledTimes(1);
    });
  });
});

// =============================================================================
// MCP Server Handler Tests
// =============================================================================
describe('MCP Server Handlers', () => {
  let server;
  let handlers;
  let origSpawn;

  beforeEach(async () => {
    vi.clearAllMocks();
    handlers = {};

    const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
    const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');

    const origSetRequestHandler = Server.prototype.setRequestHandler;
    const origConnect = Server.prototype.connect;
    origSpawn = SSHClient.prototype._spawn;

    Server.prototype.setRequestHandler = function(schema, handler) {
      if (schema === require('@modelcontextprotocol/sdk/types.js').ListToolsRequestSchema) {
        handlers.listTools = handler;
      } else if (schema === require('@modelcontextprotocol/sdk/types.js').CallToolRequestSchema) {
        handlers.callTool = handler;
      }
    };
    Server.prototype.connect = vi.fn().mockResolvedValue();
    SSHClient.prototype._spawn = createMockSpawn({ stdout: 'connected\n', code: 0 });

    readFile.mockResolvedValue(SAMPLE_SSH_CONFIG);
    stat.mockResolvedValue({ mode: 0o100600 });

    await main();

    Server.prototype.setRequestHandler = origSetRequestHandler;
    Server.prototype.connect = origConnect;
  });

  afterEach(() => {
    SSHClient.prototype._spawn = origSpawn;
  });

  it('should register exactly 6 merged tools', async () => {
    const result = await handlers.listTools();
    expect(result.tools).toHaveLength(6);
    const names = result.tools.map(t => t.name);
    expect(names).toContain('ssh_hosts');
    expect(names).toContain('ssh_exec');
    expect(names).toContain('ssh_file');
    expect(names).toContain('ssh_fs');
    expect(names).toContain('ssh_transfer');
    expect(names).toContain('ssh_task');
  });

  it('tool descriptions should include examples and action docs', async () => {
    const result = await handlers.listTools();
    const exec = result.tools.find(t => t.name === 'ssh_exec');
    expect(exec.description).toContain('errorType');
    expect(exec.description).toContain('Example:');
    expect(exec.description).toContain('code 0');
    const file = result.tools.find(t => t.name === 'ssh_file');
    expect(file.description).toContain('read');
    expect(file.description).toContain('write');
    expect(file.description).toContain('edit');
    const hosts = result.tools.find(t => t.name === 'ssh_hosts');
    expect(hosts.inputSchema.properties.timeout).toBeDefined();
  });

  it('should handle ssh_hosts action=list', async () => {
    readFile.mockResolvedValueOnce(SAMPLE_SSH_CONFIG).mockResolvedValueOnce(SAMPLE_KNOWN_HOSTS);
    const result = await handlers.callTool({ params: { name: 'ssh_hosts', arguments: { action: 'list' } } });
    const hosts = JSON.parse(result.content[0].text);
    expect(Array.isArray(hosts)).toBe(true);
    for (const host of hosts) expect(host._password).toBeUndefined();
  });

  it('should handle ssh_hosts action=check', async () => {
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
    const result = await handlers.callTool({ params: { name: 'ssh_hosts', arguments: { action: 'check', hostAlias: 'test', timeout: 100 } } });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('connected');
  });

  it('should handle ssh_hosts action=sessions', async () => {
    const result = await handlers.callTool({ params: { name: 'ssh_hosts', arguments: { action: 'sessions' } } });
    const parsed = JSON.parse(result.content[0].text);
    expect(Array.isArray(parsed)).toBe(true);
  });

  it('should handle ssh_hosts action=warmup', async () => {
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
    const result = await handlers.callTool({ params: { name: 'ssh_hosts', arguments: { action: 'warmup', hostAlias: 'test', timeout: 100 } } });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.warmed).toBe(true);
    expect(parsed.session.hostAlias).toBe('test');
  });

  it('should handle ssh_hosts action=closeSession', async () => {
    const result = await handlers.callTool({ params: { name: 'ssh_hosts', arguments: { action: 'closeSession', hostAlias: 'test' } } });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.closed).toBe(true);
  });

  it('should handle ssh_exec with single command', async () => {
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
    const result = await handlers.callTool({ params: { name: 'ssh_exec', arguments: { hostAlias: 'test', command: 'echo hi', timeout: 100 } } });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('code');
  });

  it('should handle ssh_exec with commands array (batch)', async () => {
    readFile.mockResolvedValue(`Host test\n    HostName 1.2.3.4\n`);
    const result = await handlers.callTool({ params: { name: 'ssh_exec', arguments: { hostAlias: 'test', commands: ['echo a', 'echo b'], timeout: 100 } } });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed).toHaveProperty('summary');
    expect(parsed).toHaveProperty('results');
  });

  it('should handle ssh_task action=list', async () => {
    const result = await handlers.callTool({ params: { name: 'ssh_task', arguments: { action: 'list' } } });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.tasks).toBeDefined();
  });

  it('should handle unknown tool gracefully', async () => {
    const result = await handlers.callTool({ params: { name: 'unknownTool', arguments: {} } });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.success).toBe(false);
    expect(parsed.error).toContain('Unknown tool');
  });

  it('should handle unknown action gracefully', async () => {
    const result = await handlers.callTool({ params: { name: 'ssh_hosts', arguments: { action: 'invalid' } } });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.success).toBe(false);
    expect(parsed.error).toContain("Unknown action 'invalid'");
  });
});

// =============================================================================
// main() error handling
// =============================================================================
describe('main() error handling', () => {
  it('should handle startup errors gracefully', async () => {
    const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
    const origConnect = Server.prototype.connect;
    Server.prototype.connect = vi.fn().mockRejectedValue(new Error('transport failed'));
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation(() => {});
    await main();
    expect(exitSpy).toHaveBeenCalledWith(1);
    Server.prototype.connect = origConnect;
    exitSpy.mockRestore();
  });
});
