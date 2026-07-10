import { randomUUID } from 'crypto';
import { shQuote, validateFileMode } from '../shared.mjs';
import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';
import { createRequestId, emptyTiming, successResult, failureResult } from '../domain/result.mjs';

const SHA256_RE = /^[a-f0-9]{64}$/i;

function assertPath(path) {
  if (typeof path !== 'string' || !path || path.includes('\0')) {
    throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'path 必须是非空且不含 NUL 的远程路径。', { phase: 'validate' });
  }
}

function number(value, name, fallback, maximum) {
  if (value === undefined || value === null) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, `${name} 必须是非负整数。`, { phase: 'validate' });
  return Math.min(parsed, maximum);
}

function parseMarked(stdout, marker) {
  const values = {};
  for (const line of String(stdout || '').split(/\r?\n/)) {
    const match = line.match(new RegExp(`^${marker}_([A-Z_]+)=(.*)$`));
    if (match) values[match[1]] = match[2];
  }
  return values;
}

function shaCommand(path) {
  return `(sha256sum -- ${shQuote(path)} 2>/dev/null || shasum -a 256 -- ${shQuote(path)} 2>/dev/null) | awk '{print $1}'`;
}

function decodeContent(content, encoding) {
  if (typeof content !== 'string') throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'write 与 append 需要 content。', { phase: 'validate' });
  if (encoding === 'base64') {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(content) || content.length % 4 === 1) {
      throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'base64 content 格式无效。', { phase: 'validate' });
    }
    return Buffer.from(content, 'base64');
  }
  if (encoding && encoding !== 'utf-8') throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, `不支持的 encoding '${encoding}'。`, { phase: 'validate' });
  return Buffer.from(content, 'utf8');
}

class FileService {
  constructor({ resolver, connections, adapter, config, policy } = {}) {
    this.resolver = resolver;
    this.connections = connections;
    this.adapter = adapter;
    this.config = config;
    this.policy = policy;
  }

  async handle(args = {}, context = {}) {
    const requestId = createRequestId();
    const startedAt = Date.now();
    const action = args.action;
    let target;
    const timing = emptyTiming(startedAt);
    try {
      if (!['read', 'write', 'append', 'stat'].includes(action)) {
        throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'action 必须为 read、write、append 或 stat。', { phase: 'validate' });
      }
      if (typeof args.target !== 'string' || !args.target) throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'target 为必填项。', { phase: 'validate' });
      assertPath(args.path);
      await this.policy?.check(args.target, `ssh_file.${action}`, { path: args.path });
      const resolvedAt = Date.now();
      target = await this.resolver.resolve(args.target);
      timing.resolveMs = Date.now() - resolvedAt;
      const lease = await this.connections.ensureReady(target);
      timing.connectionWaitMs = lease.connectionWaitMs;
      timing.connectMs = lease.connectMs;
      timing.connectionReused = lease.connectionReused;
      const executeAt = Date.now();
      let data;
      if (action === 'read') data = await this._read(target, lease, args, context);
      else if (action === 'stat') data = await this._stat(target, lease, args, context);
      else if (action === 'write') data = await this._write(target, lease, args, context);
      else data = await this._append(target, lease, args, context);
      timing.executeMs = Date.now() - executeAt;
      timing.totalMs = Date.now() - startedAt;
      return successResult({ requestId, operation: `file.${action}`, target: target.id, timing, data, warnings: target.warnings });
    } catch (error) {
      timing.totalMs = Date.now() - startedAt;
      return failureResult({ requestId, operation: `file.${action || 'unknown'}`, target: target?.id || args.target, timing, error });
    }
  }

  async _exec(target, lease, command, context, stdin) {
    const settings = await this.config.load();
    const result = await this.adapter.exec({ target, command, controlPath: lease.controlPath, timeoutMs: settings.defaultTimeoutMs, signal: context.signal, stdin });
    if (result.timedOut || result.cancelled) throw new OperationFailure(result.cancelled ? ERROR_CODES.REMOTE_COMMAND_CANCELLED : ERROR_CODES.REMOTE_COMMAND_TIMEOUT, '文件操作未在规定时间完成。', { phase: 'execute', mayHaveRun: true });
    return result;
  }

  async _read(target, lease, args, context) {
    const settings = await this.config.load();
    const offset = number(args.offset, 'offset', 0, Number.MAX_SAFE_INTEGER);
    const limit = number(args.limit, 'limit', settings.defaultOutputLimitBytes, settings.maxOutputLimitBytes);
    const marker = `__MCP_FILE_${randomUUID().replaceAll('-', '')}`;
    const command = [
      'set +e', `__mcp_path=${shQuote(args.path)}`,
      '[ -e "$__mcp_path" ] || exit 44',
      `printf '${marker}_SIZE=%s\\n' "$(stat -c '%s' -- "$__mcp_path" 2>/dev/null || stat -f '%z' "$__mcp_path")"`,
      `printf '${marker}_SHA=%s\\n' "$(${shaCommand(args.path)})"`,
      `dd if="$__mcp_path" bs=1 skip=${offset} count=${limit} 2>/dev/null | base64 | tr -d '\\n' | sed 's/^/${marker}_CONTENT=/'`,
    ].join('\n');
    const result = await this._exec(target, lease, command, context);
    if (result.code === 44) throw new OperationFailure(ERROR_CODES.FILE_NOT_FOUND, `远程文件不存在：${args.path}`, { phase: 'execute', retryable: false });
    if (result.code !== 0) throw new OperationFailure(ERROR_CODES.FILE_PERMISSION_DENIED, result.stderr || '无法读取远程文件。', { phase: 'execute' });
    const values = parseMarked(result.stdout, marker);
    const raw = Buffer.from(values.CONTENT || '', 'base64');
    const encoding = args.encoding || 'utf-8';
    if (!['utf-8', 'base64'].includes(encoding)) throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'encoding 必须为 utf-8 或 base64。', { phase: 'validate' });
    const size = Number(values.SIZE || raw.length);
    return {
      path: args.path, size, sha256: values.SHA || null, encoding,
      content: encoding === 'base64' ? raw.toString('base64') : raw.toString('utf8'),
      offset, limit: raw.length, truncated: offset + raw.length < size,
    };
  }

  async _stat(target, lease, args, context) {
    const marker = `__MCP_FILE_${randomUUID().replaceAll('-', '')}`;
    const command = [
      'set +e', `__mcp_path=${shQuote(args.path)}`, '[ -e "$__mcp_path" ] || exit 44',
      `printf '${marker}_SIZE=%s\\n' "$(stat -c '%s' -- "$__mcp_path" 2>/dev/null || stat -f '%z' "$__mcp_path")"`,
      `printf '${marker}_SHA=%s\\n' "$(${shaCommand(args.path)})"`,
      `printf '${marker}_MODE=%s\\n' "$(stat -c '%a' -- "$__mcp_path" 2>/dev/null || stat -f '%Lp' "$__mcp_path")"`,
      `printf '${marker}_MODIFIED_AT=%s\\n' "$(stat -c '%Y' -- "$__mcp_path" 2>/dev/null || stat -f '%m' "$__mcp_path")"`,
      `printf '${marker}_TYPE=%s\\n' "$(if [ -d "$__mcp_path" ]; then printf directory; elif [ -f "$__mcp_path" ]; then printf file; else printf other; fi)"`,
    ].join('\n');
    const result = await this._exec(target, lease, command, context);
    if (result.code === 44) throw new OperationFailure(ERROR_CODES.FILE_NOT_FOUND, `远程文件不存在：${args.path}`, { phase: 'execute' });
    if (result.code !== 0) throw new OperationFailure(ERROR_CODES.FILE_PERMISSION_DENIED, result.stderr || '无法读取远程文件元数据。', { phase: 'execute' });
    const values = parseMarked(result.stdout, marker);
    return { path: args.path, size: Number(values.SIZE || 0), sha256: values.SHA || null, mode: values.MODE || null, modifiedAt: values.MODIFIED_AT ? new Date(Number(values.MODIFIED_AT) * 1000).toISOString() : null, type: values.TYPE || 'other' };
  }

  async _write(target, lease, args, context) {
    const data = decodeContent(args.content, args.encoding || 'utf-8');
    if (args.expectedSha256 !== undefined && !SHA256_RE.test(args.expectedSha256)) {
      throw new OperationFailure(ERROR_CODES.INVALID_ARGUMENT, 'expectedSha256 必须是 SHA-256 十六进制摘要。', { phase: 'validate' });
    }
    const mode = validateFileMode(args.mode);
    const marker = `__MCP_FILE_${randomUUID().replaceAll('-', '')}`;
    const tempSuffix = randomUUID().replaceAll('-', '');
    const expectedCheck = args.expectedSha256
      ? [
          '[ -e "$__mcp_path" ] || exit 46',
          `__mcp_current=$(${shaCommand(args.path)})`,
          `[ "$__mcp_current" = ${shQuote(args.expectedSha256.toLowerCase())} ] || exit 46`,
        ] : [];
    const command = [
      'set -eu', `__mcp_path=${shQuote(args.path)}`, '__mcp_dir=$(dirname -- "$__mcp_path")', '__mcp_base=$(basename -- "$__mcp_path")',
      ...expectedCheck,
      `__mcp_tmp="$__mcp_dir/.$__mcp_base.mcp-ssh-${tempSuffix}"`,
      "trap 'rm -f -- \"$__mcp_tmp\"' EXIT",
      'cat > "$__mcp_tmp"',
      ...(mode ? [`chmod ${shQuote(mode)} -- "$__mcp_tmp"`] : []),
      'mv -f -- "$__mcp_tmp" "$__mcp_path"', 'trap - EXIT',
      `printf '${marker}_SIZE=%s\\n' "$(wc -c < "$__mcp_path" | tr -d ' ')"`,
      `printf '${marker}_SHA=%s\\n' "$(${shaCommand(args.path)})"`,
    ].join('\n');
    const result = await this._exec(target, lease, command, context, data);
    if (result.code === 46) throw new OperationFailure(ERROR_CODES.FILE_CHANGED, '远程文件已变化，拒绝覆盖。', { phase: 'execute', retryable: false });
    if (result.code !== 0) throw new OperationFailure(ERROR_CODES.FILE_PERMISSION_DENIED, result.stderr || '无法原子写入远程文件。', { phase: 'execute', mayHaveRun: true });
    const values = parseMarked(result.stdout, marker);
    return { path: args.path, written: Number(values.SIZE || data.length), sha256: values.SHA || null, atomic: true, ...(mode ? { mode } : {}) };
  }

  async _append(target, lease, args, context) {
    const data = decodeContent(args.content, args.encoding || 'utf-8');
    const marker = `__MCP_FILE_${randomUUID().replaceAll('-', '')}`;
    const command = [
      'set -eu', `__mcp_path=${shQuote(args.path)}`, 'cat >> "$__mcp_path"',
      `printf '${marker}_SIZE=%s\\n' "$(wc -c < "$__mcp_path" | tr -d ' ')"`,
      `printf '${marker}_SHA=%s\\n' "$(${shaCommand(args.path)})"`,
    ].join('\n');
    const result = await this._exec(target, lease, command, context, data);
    if (result.code !== 0) throw new OperationFailure(ERROR_CODES.FILE_PERMISSION_DENIED, result.stderr || '无法追加远程文件。', { phase: 'execute', mayHaveRun: true });
    const values = parseMarked(result.stdout, marker);
    return { path: args.path, appended: data.length, size: Number(values.SIZE || 0), sha256: values.SHA || null };
  }
}

export { FileService, assertPath, decodeContent, parseMarked };
