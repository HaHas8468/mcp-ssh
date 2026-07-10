import { readFile } from 'fs/promises';
import { homedir } from 'os';
import { join } from 'path';
import { detectDangerousCommand } from '../shared.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';

class PolicyGuard {
  constructor({ path = join(homedir(), '.mcp-ssh', 'permissions.json') } = {}) {
    this.path = path;
    this.policies = null;
  }

  async _load() {
    if (this.policies) return this.policies;
    try { this.policies = JSON.parse(await readFile(this.path, 'utf8')); }
    catch { this.policies = {}; }
    return this.policies;
  }

  async policyFor(target) {
    const policies = await this._load();
    if (policies[target]) return policies[target];
    for (const [pattern, policy] of Object.entries(policies)) {
      if (!pattern.includes('*')) continue;
      const patternRe = new RegExp(`^${pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*')}$`);
      if (patternRe.test(target)) return policy;
    }
    return null;
  }

  async check(target, operation, { command, path } = {}) {
    const policy = await this.policyFor(target);
    if (!policy) return;
    if (policy.allowedTools && policy.allowedTools !== '*' && !policy.allowedTools.includes(operation)) {
      throw new OperationFailure(ERROR_CODES.TARGET_NOT_ALLOWED, `策略不允许在 '${target}' 上执行 ${operation}。`, { phase: 'validate' });
    }
    for (const pattern of policy.denyPatterns || []) {
      try {
        if (command && new RegExp(pattern).test(command)) {
          throw new OperationFailure(ERROR_CODES.TARGET_NOT_ALLOWED, '命令被本地策略拒绝。', { phase: 'validate' });
        }
      } catch (error) {
        if (error instanceof OperationFailure) throw error;
      }
    }
    for (const protectedPath of policy.protectedPaths || []) {
      if (path && (path === protectedPath || path.startsWith(`${protectedPath}/`))) {
        throw new OperationFailure(ERROR_CODES.TARGET_NOT_ALLOWED, `策略保护路径 '${protectedPath}'。`, { phase: 'validate' });
      }
    }
  }

  dangerous(command) { return detectDangerousCommand(command); }
}

export { PolicyGuard };
