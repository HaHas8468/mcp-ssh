import { statSync } from 'fs';
import { join } from 'path';

const isWindows = process.platform === 'win32';

function resolveExecutable(name) {
  if (!isWindows) return name;
  const pathDirs = (process.env.PATH || process.env.Path || '').split(';');
  const exts = (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';');
  for (const dir of pathDirs) {
    if (!dir) continue;
    for (const ext of exts) {
      const candidate = join(dir, name + ext);
      try {
        if (statSync(candidate).isFile()) return candidate;
      } catch {}
    }
  }
  return name + '.exe';
}

const SSH_BIN = resolveExecutable('ssh');
const SCP_BIN = resolveExecutable('scp');

const SILENT_MODE = process.env.MCP_SILENT === 'true' || process.argv.includes('--silent');

function debugLog(message) {
  if (!SILENT_MODE) {
    process.stderr.write(message);
  }
}

const MAX_OUTPUT_SIZE = 10 * 1024 * 1024;
const DEFAULT_TIMEOUT = 120000;
const MAX_TIMEOUT = 300000;
const DEFAULT_SSH_CONFIG_CACHE_TTL = 5000;
const DEFAULT_TASK_LOG_TAIL_BYTES = 256 * 1024;
const MAX_TASK_LOG_TAIL_BYTES = 2 * 1024 * 1024;
const DEFAULT_TASK_LOG_LINE_LENGTH = 1000;
const MAX_TASK_LOG_LINE_LENGTH = 20000;

function shQuote(value) {
  return `'${String(value ?? '').replace(/'/g, `'\\''`)}'`;
}

function validateFileMode(mode) {
  if (mode === undefined || mode === null || mode === '') return null;
  const normalized = String(mode);
  if (!/^[0-7]{3,4}$/.test(normalized)) {
    throw new Error(`Invalid file mode '${normalized}'. Expected octal permissions like 644 or 0755.`);
  }
  return normalized;
}

function nonNegativeInteger(value, name) {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 0) {
    throw new Error(`${name} must be a non-negative integer`);
  }
  return normalized;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizeStringList(value) {
  if (value === undefined || value === null || value === '') return [];
  return Array.isArray(value) ? value.filter(v => v !== undefined && v !== null && v !== '').map(String) : [String(value)];
}

function clampNonNegativeInteger(value, name, min, max) {
  const normalized = nonNegativeInteger(value, name);
  return Math.min(Math.max(normalized, min), max);
}

function diagnoseSshTransportError(stderr = '') {
  const text = String(stderr || '');
  if (/permission denied|authentication failed|too many authentication failures/i.test(text)) {
    return {
      category: 'auth_failed',
      retryable: false,
      detail: 'SSH authentication failed.',
    };
  }
  if (/host key verification failed|remote host identification has changed/i.test(text)) {
    return {
      category: 'host_key_mismatch',
      retryable: false,
      detail: 'SSH host key verification failed.',
    };
  }
  if (/mux_client|control socket|controlpath|controlmaster|master.*(?:dead|broken|refused)|broken pipe/i.test(text)) {
    return {
      category: 'local_control_connection',
      retryable: true,
      detail: 'The local SSH ControlMaster/ControlPath connection appears stale or broken.',
    };
  }
  if (/channel \d+: open failed: connect failed|connect failed|connection refused|connection timed out|operation timed out|no route to host|network is unreachable|could not resolve hostname|name or service not known|temporary failure in name resolution/i.test(text)) {
    return {
      category: 'target_unreachable',
      retryable: true,
      detail: 'The target host or proxied destination appears unreachable.',
    };
  }
  if (/kex_exchange_identification:.*connection closed|connection closed by remote host|connection reset by peer/i.test(text)) {
    return {
      category: 'remote_exchange_closed',
      retryable: true,
      detail: 'The SSH key exchange was closed by the remote endpoint or proxy; a stale multiplexed connection is possible.',
    };
  }
  return {
    category: 'unknown_ssh_error',
    retryable: true,
    detail: 'SSH exited with a transport-level error.',
  };
}

function parsePidList(value) {
  return String(value || '')
    .split(/\s+/)
    .map(v => Number.parseInt(v, 10))
    .filter(v => Number.isSafeInteger(v) && v > 0);
}

// Signal name → number mapping for exit code computation
const SIGNAL_NUMBERS = {
  SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
  SIGBUS: 7, SIGFPE: 8, SIGKILL: 9, SIGUSR1: 10, SIGSEGV: 11, SIGUSR2: 12,
  SIGPIPE: 13, SIGALRM: 14, SIGTERM: 15,
};
function signalToNum(signal) {
  if (!signal) return 0;
  if (typeof signal === 'number') return signal;
  return SIGNAL_NUMBERS[signal] || 0;
}

// =============================================================================
// DangerousCommandDetector — pattern-based detection of risky commands
// =============================================================================
const DANGER_PATTERNS = [
  { pattern: /rm\s+-rf?\s+\/(?:\s|$|\*)/, level: 'critical', msg: '递归删除根路径' },
  { pattern: /mkfs(\.\w+)?\s+\/dev\//, level: 'critical', msg: '格式化磁盘' },
  { pattern: /dd\s+.*of=\/dev\//, level: 'critical', msg: 'dd 写入设备' },
  { pattern: /:\(\)\s*\{.*\|.*&\s*\};:/, level: 'critical', msg: 'fork 炸弹' },
  { pattern: /chmod\s+-R?\s+777\s+\//, level: 'high', msg: '全权限开放根路径' },
  { pattern: /(drop|truncate)\s+(table|database)\s/i, level: 'high', msg: '数据库删除' },
  { pattern: /systemctl\s+(stop|restart|disable)\s/, level: 'medium', msg: '服务管理' },
  { pattern: /shutdown|reboot|halt|poweroff/, level: 'high', msg: '系统关机/重启' },
  { pattern: />\s*\/dev\/sd[a-z]/, level: 'critical', msg: '覆写磁盘设备' },
  { pattern: /iptables\s+.*--flush|iptables\s+-F/, level: 'high', msg: '清空防火墙规则' },
];

function detectDangerousCommand(command) {
  for (const { pattern, level, msg } of DANGER_PATTERNS) {
    if (pattern.test(command)) {
      return { detected: true, level, message: msg, pattern: pattern.source };
    }
  }
  return { detected: false };
}

export {
  isWindows,
  SSH_BIN,
  SCP_BIN,
  SILENT_MODE,
  debugLog,
  MAX_OUTPUT_SIZE,
  DEFAULT_TIMEOUT,
  MAX_TIMEOUT,
  DEFAULT_SSH_CONFIG_CACHE_TTL,
  DEFAULT_TASK_LOG_TAIL_BYTES,
  MAX_TASK_LOG_TAIL_BYTES,
  DEFAULT_TASK_LOG_LINE_LENGTH,
  MAX_TASK_LOG_LINE_LENGTH,
  shQuote,
  validateFileMode,
  nonNegativeInteger,
  escapeRegExp,
  normalizeStringList,
  clampNonNegativeInteger,
  diagnoseSshTransportError,
  parsePidList,
  signalToNum,
  detectDangerousCommand,
};
