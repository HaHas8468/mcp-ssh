import { configValue } from '../domain/target.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';

function parseJumpSpec(value) {
  const text = String(value || '').trim();
  const at = text.lastIndexOf('@');
  const user = at > 0 ? text.slice(0, at) : undefined;
  const hostAndPort = at > 0 ? text.slice(at + 1) : text;
  // OpenSSH ProxyJump accepts bracketed IPv6. Keep unbracketed host forms intact.
  const bracketed = hostAndPort.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketed) return { alias: bracketed[1], hostname: bracketed[1], user, port: bracketed[2] ? Number(bracketed[2]) : undefined };
  const colon = hostAndPort.match(/^([^:]+):(\d+)$/);
  return { alias: colon ? colon[1] : hostAndPort, hostname: colon ? colon[1] : hostAndPort, user, port: colon ? Number(colon[2]) : undefined };
}

function parseProxyJump(value) {
  if (!value || /^none$/i.test(String(value).trim())) return [];
  return String(value).split(',').map(item => item.trim()).filter(Boolean).map(parseJumpSpec);
}

class RouteResolver {
  constructor({ catalog, config } = {}) {
    this.catalog = catalog;
    this.config = config;
    this.cache = new Map();
    this.catalog?.subscribe(() => this.cache.clear());
  }

  async resolve(target) {
    const cached = this.cache.get(target);
    if (cached) return cached;
    const value = await this._resolveTarget(target, [], []);
    this.cache.set(target, value);
    return value;
  }

  async _resolveTarget(target, stack, accumulated) {
    const settings = await this.config.load();
    if (stack.includes(target)) {
      throw new OperationFailure(ERROR_CODES.ROUTE_CYCLE, `检测到 ProxyJump 循环：${[...stack, target].join(' → ')}`, { phase: 'resolve' });
    }
    if (stack.length >= settings.maxRouteDepth) {
      throw new OperationFailure(ERROR_CODES.ROUTE_TOO_DEEP, `SSH 路由超过最大深度 ${settings.maxRouteDepth}。`, { phase: 'resolve' });
    }
    const effective = await this.catalog.effective(target);
    const cfg = effective.config;
    const proxyCommand = configValue(cfg, 'proxycommand', 'none');
    const proxyJumps = parseProxyJump(configValue(cfg, 'proxyjump', 'none'));
    const destination = {
      hostname: configValue(cfg, 'hostname', target),
      ...(configValue(cfg, 'user') ? { user: configValue(cfg, 'user') } : {}),
      port: Number(configValue(cfg, 'port', 22)) || 22,
    };
    const currentHop = { alias: target, hostname: destination.hostname, ...(destination.user ? { user: destination.user } : {}), port: destination.port, depth: accumulated.length };
    if (proxyCommand && !/^none$/i.test(String(proxyCommand))) {
      return this._buildResolved(target, destination, [...accumulated, currentHop], 'opaque-command', effective, cfg);
    }

    let route = [...accumulated];
    for (const jump of proxyJumps) {
      if (stack.includes(jump.alias) || jump.alias === target) {
        throw new OperationFailure(ERROR_CODES.ROUTE_CYCLE, `检测到 ProxyJump 循环：${[...stack, target, jump.alias].join(' → ')}`, { phase: 'resolve' });
      }
      if (route.length >= settings.maxRouteDepth) {
        throw new OperationFailure(ERROR_CODES.ROUTE_TOO_DEEP, `SSH 路由超过最大深度 ${settings.maxRouteDepth}。`, { phase: 'resolve' });
      }
      const explicit = await this.catalog.list();
      if (explicit.some(entry => entry.id === jump.alias)) {
        const nested = await this._resolveTarget(jump.alias, [...stack, target], route);
        // _resolveTarget receives the already-built prefix. Only append its new
        // hops; otherwise multi-hop routes would duplicate earlier jumps.
        const appended = nested.route.slice(route.length).map((hop, index) => ({ ...hop, depth: route.length + index }));
        route.push(...appended);
        const last = route.at(-1);
        if (jump.user) last.user = jump.user;
        if (jump.port) last.port = jump.port;
      } else {
        route.push({ alias: jump.alias, hostname: jump.hostname, ...(jump.user ? { user: jump.user } : {}), port: jump.port || 22, depth: route.length });
      }
    }
    if (route.length >= settings.maxRouteDepth) {
      throw new OperationFailure(ERROR_CODES.ROUTE_TOO_DEEP, `SSH 路由超过最大深度 ${settings.maxRouteDepth}。`, { phase: 'resolve' });
    }
    route.push({ ...currentHop, depth: route.length });
    return this._buildResolved(target, destination, route, proxyJumps.length ? 'jump' : 'none', effective, cfg);
  }

  _buildResolved(id, destination, route, proxyMode, effective, cfg) {
    const identityFile = configValue(cfg, 'identityfile');
    const identityAgent = configValue(cfg, 'identityagent');
    return {
      id,
      destination,
      route,
      proxyMode,
      configFingerprint: effective.fingerprint,
      auth: {
        method: identityAgent && identityAgent !== 'none' ? 'agent' : (identityFile ? 'identity-file' : 'unknown'),
        secretAvailable: false,
      },
      warnings: proxyMode === 'opaque-command' ? [{ code: 'OPAQUE_PROXY_COMMAND', message: 'ProxyCommand 由 OpenSSH 执行，无法逐跳诊断。' }] : [],
      effectiveConfig: cfg,
    };
  }
}

export { RouteResolver, parseJumpSpec, parseProxyJump };
