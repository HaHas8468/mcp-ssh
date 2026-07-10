import { redactTarget } from '../domain/target.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';
import { createRequestId, emptyTiming, successResult, failureResult } from '../domain/result.mjs';

class TargetService {
  constructor({ catalog, resolver, adapter } = {}) {
    this.catalog = catalog;
    this.resolver = resolver;
    this.adapter = adapter;
  }

  async handle(args = {}) {
    const requestId = createRequestId();
    const startedAt = Date.now();
    const action = args.action || 'list';
    try {
      if (action === 'list') {
        const targets = await this.catalog.list();
        return successResult({ requestId, operation: 'targets.list', timing: emptyTiming(startedAt), data: { targets: targets.map(({ id }) => ({ id })) } });
      }
      if (!args.target) throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'describe 和 diagnose 需要 target。', { phase: 'validate' });
      const target = await this.resolver.resolve(args.target);
      if (action === 'describe') {
        return successResult({ requestId, operation: 'targets.describe', target: target.id, timing: emptyTiming(startedAt), data: { target: redactTarget(target) } });
      }
      if (action !== 'diagnose') throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, `不支持的 targets action: ${action}`, { phase: 'validate' });
      const report = { target: redactTarget(target), networkProbed: Boolean(args.networkProbe), hops: [] };
      if (args.networkProbe) {
        const probes = target.proxyMode === 'opaque-command'
          ? [target.route.at(-1)] : target.route;
        for (const hop of probes) {
          const result = await this.adapter.probe(hop.alias, { timeoutMs: 10_000 });
          report.hops.push({ alias: hop.alias, depth: hop.depth, ok: result.ok, durationMs: result.durationMs, ...(result.ok ? {} : { error: result.stderr }) });
          if (!result.ok) {
            report.failedHop = { alias: hop.alias, depth: hop.depth };
            break;
          }
        }
      }
      return successResult({ requestId, operation: 'targets.diagnose', target: target.id, timing: emptyTiming(startedAt), data: report, warnings: target.warnings });
    } catch (error) {
      return failureResult({ requestId, operation: `targets.${action}`, target: args.target, timing: emptyTiming(startedAt), error });
    }
  }
}

export { TargetService };
