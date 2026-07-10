import { homedir } from 'os';
import { readFile } from 'fs/promises';
import { join, resolve } from 'path';
import { isWindows } from '../shared.mjs';

const DEFAULTS = Object.freeze({
  connectionPersistMs: 30 * 60 * 1000,
  connectionHealthTtlMs: 10_000,
  defaultTimeoutMs: 120_000,
  maxTimeoutMs: 300_000,
  defaultOutputLimitBytes: 128 * 1024,
  maxOutputLimitBytes: 2 * 1024 * 1024,
  allowedLocalRoots: [process.cwd()],
  allowKnownHostsTargets: false,
  maxRouteDepth: 8,
  sshConfigCacheTtlMs: 5_000,
  strictHostKeyChecking: 'accept-new',
  outputTtlMs: 24 * 60 * 60 * 1000,
});

class RuntimeConfig {
  constructor(configPath = join(homedir(), '.mcp-ssh', 'config.json'), defaults = {}) {
    this.configPath = configPath;
    this.defaults = { ...DEFAULTS, ...defaults };
    this.value = null;
  }

  async load() {
    if (this.value) return this.value;
    try {
      const parsed = JSON.parse(await readFile(this.configPath, 'utf8'));
      this.value = normalizeConfig({ ...this.defaults, ...parsed });
    } catch {
      this.value = normalizeConfig(this.defaults);
    }
    return this.value;
  }

  async get(key) {
    return (await this.load())[key];
  }

  invalidate() { this.value = null; }
}

function normalizeConfig(config) {
  const number = (name, minimum, fallback) => {
    const value = Number(config[name]);
    return Number.isFinite(value) && value >= minimum ? Math.floor(value) : fallback;
  };
  return {
    ...config,
    connectionPersistMs: number('connectionPersistMs', 0, DEFAULTS.connectionPersistMs),
    connectionHealthTtlMs: number('connectionHealthTtlMs', 0, DEFAULTS.connectionHealthTtlMs),
    defaultTimeoutMs: number('defaultTimeoutMs', 1, DEFAULTS.defaultTimeoutMs),
    maxTimeoutMs: number('maxTimeoutMs', 1, DEFAULTS.maxTimeoutMs),
    defaultOutputLimitBytes: number('defaultOutputLimitBytes', 1, DEFAULTS.defaultOutputLimitBytes),
    maxOutputLimitBytes: number('maxOutputLimitBytes', 1, DEFAULTS.maxOutputLimitBytes),
    maxRouteDepth: number('maxRouteDepth', 1, DEFAULTS.maxRouteDepth),
    sshConfigCacheTtlMs: number('sshConfigCacheTtlMs', 0, DEFAULTS.sshConfigCacheTtlMs),
    outputTtlMs: number('outputTtlMs', 1, DEFAULTS.outputTtlMs),
    allowedLocalRoots: Array.isArray(config.allowedLocalRoots) && config.allowedLocalRoots.length
      ? config.allowedLocalRoots.map(path => resolve(String(path))) : [process.cwd()],
    controlMaster: !isWindows,
  };
}

function runtimePaths(home = homedir()) {
  const root = join(home, '.mcp-ssh');
  return {
    root,
    runtime: join(root, 'runtime'),
    control: join(root, 'runtime', 'control'),
    outputs: join(root, 'runtime', 'outputs'),
    state: join(root, 'state'),
    tasks: join(root, 'state', 'tasks.json'),
    audit: join(root, 'state', 'audit.log'),
  };
}

export { DEFAULTS, RuntimeConfig, runtimePaths };
