import { createHash } from 'crypto';
import { ERROR_CODES, OperationFailure } from './errors.mjs';

const TARGET_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.@:-]*$/;

function assertTargetId(target) {
  if (typeof target !== 'string' || !TARGET_ID_RE.test(target) || target.startsWith('-')) {
    throw new OperationFailure(
      ERROR_CODES.INVALID_ARGUMENT,
      'target 必须是已配置的 SSH 别名，且不能以 "-" 开头。',
      { phase: 'validate' }
    );
  }
  return target;
}

function configFingerprint(rawConfig) {
  const normalized = String(rawConfig || '').replace(/\r\n/g, '\n').replace(/[ \t]+$/gm, '').trimEnd() + '\n';
  return createHash('sha256').update(normalized).digest('hex');
}

function parseSshG(stdout) {
  const config = {};
  for (const line of String(stdout || '').split(/\r?\n/)) {
    const separator = line.indexOf(' ');
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (!key) continue;
    if (config[key] === undefined) config[key] = value;
    else if (Array.isArray(config[key])) config[key].push(value);
    else config[key] = [config[key], value];
  }
  return config;
}

function configValue(config, key, fallback = undefined) {
  const value = config?.[key.toLowerCase()];
  return Array.isArray(value) ? value[0] : (value ?? fallback);
}

function redactTarget(target) {
  return {
    id: target.id,
    destination: { ...target.destination },
    route: target.route.map(({ alias, hostname, user, port, depth }) => ({ alias, hostname, ...(user ? { user } : {}), port, depth })),
    proxyMode: target.proxyMode,
    configFingerprint: target.configFingerprint,
    auth: { ...target.auth },
    warnings: [...target.warnings],
  };
}

export { TARGET_ID_RE, assertTargetId, configFingerprint, parseSshG, configValue, redactTarget };
