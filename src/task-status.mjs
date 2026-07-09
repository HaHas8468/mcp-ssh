import {
  DEFAULT_TASK_LOG_LINE_LENGTH,
  DEFAULT_TASK_LOG_TAIL_BYTES,
  MAX_TASK_LOG_LINE_LENGTH,
  MAX_TASK_LOG_TAIL_BYTES,
  clampNonNegativeInteger,
  nonNegativeInteger,
  normalizeStringList,
  shQuote,
} from './shared.mjs';

function normalizeTaskStatusOptions(options = {}) {
  const logLines = clampNonNegativeInteger(options.logLines ?? 50, 'logLines', 1, 1000);
  const tailBytes = clampNonNegativeInteger(options.tailBytes ?? DEFAULT_TASK_LOG_TAIL_BYTES, 'tailBytes', 1, MAX_TASK_LOG_TAIL_BYTES);
  const maxLogLineLength = clampNonNegativeInteger(options.maxLogLineLength ?? DEFAULT_TASK_LOG_LINE_LENGTH, 'maxLogLineLength', 80, MAX_TASK_LOG_LINE_LENGTH);
  return {
    logLines,
    tailBytes,
    maxLogLineLength,
    grep: normalizeStringList(options.grep),
    exclude: normalizeStringList(options.exclude),
    onlyNew: Boolean(options.onlyNew),
    readyPattern: options.readyPattern ? String(options.readyPattern) : null,
    ports: normalizeStringList(options.ports).map(v => Number.parseInt(v, 10)).filter(v => Number.isSafeInteger(v) && v > 0 && v <= 65535),
  };
}

function buildTaskLogPipeline(statusOptions) {
  const filters = [];
  filters.push(`tr '\\r' '\\n'`);
  for (const pattern of statusOptions.grep) {
    filters.push(`grep -E -- ${shQuote(pattern)}`);
  }
  for (const pattern of statusOptions.exclude) {
    filters.push(`grep -Ev -- ${shQuote(pattern)}`);
  }
  filters.push(`tail -n ${statusOptions.logLines}`);
  filters.push(`awk -v max=${statusOptions.maxLogLineLength} '{ if (length($0) > max) { print substr($0, 1, max) " ... [truncated " (length($0) - max) " chars]"; } else { print $0; } }'`);
  return filters.join(' | ');
}

function buildTaskStatusCommand(task, statusOptions, markers) {
  const remotePid = nonNegativeInteger(task.remotePid, 'remotePid');
  const processGroupId = nonNegativeInteger(task.processGroupId ?? task.remotePid, 'processGroupId');
  const lastLogOffset = nonNegativeInteger(task.lastLogOffset || 0, 'lastLogOffset');
  const logPipeline = buildTaskLogPipeline(statusOptions);
  const sourceCommand = statusOptions.onlyNew
    ? `tail -c +$((__mcp_log_start + 1)) "$__mcp_log" 2>/dev/null`
    : `tail -c ${statusOptions.tailBytes} "$__mcp_log" 2>/dev/null`;

  return [
    `pid=${remotePid}`,
    `pgid=${processGroupId}`,
    `__mcp_log=${shQuote(task.logFile)}`,
    `__mcp_exit=${shQuote(task.exitFile || `/tmp/mcp-task-${task.taskId || 'unknown'}.exit`)}`,
    `__mcp_pids_space="$( { ps -p "$pid" -o pid= 2>/dev/null; pgrep -g "$pgid" 2>/dev/null; } | awk 'NF' | sort -n | uniq | tr '\\n' ' ' )"`,
    `__mcp_pids_csv="$(printf '%s\\n' "$__mcp_pids_space" | tr ' ' '\\n' | awk 'NF { printf "%s%s", sep, $1; sep="," }')"`,
    `printf '%s\\n' ${shQuote(markers.processStart)}`,
    `if ps -p "$pid" >/dev/null 2>&1; then ps -p "$pid" -o pid,ppid,pgid,stat,etime,comm --no-headers 2>/dev/null; elif [ -n "$__mcp_pids_space" ]; then printf 'GROUP_RUNNING %s\\n' "$__mcp_pids_space"; else echo "EXITED"; fi`,
    `printf '%s\\n' ${shQuote(markers.processEnd)}`,
    `printf '%s\\n' ${shQuote(markers.treeStart)}`,
    `if [ -n "$__mcp_pids_csv" ]; then ps -p "$__mcp_pids_csv" -o pid= -o ppid= -o pgid= -o stat= -o etime= -o pcpu= -o pmem= -o rss= -o comm= -o args= 2>/dev/null | awk '{pid=$1; ppid=$2; pgid=$3; stat=$4; etime=$5; cpu=$6; mem=$7; rss=$8; comm=$9; $1=$2=$3=$4=$5=$6=$7=$8=$9=""; sub(/^ +/, ""); print pid "|" ppid "|" pgid "|" stat "|" etime "|" cpu "|" mem "|" rss "|" comm "|" $0}' ; fi`,
    `printf '%s\\n' ${shQuote(markers.treeEnd)}`,
    `printf '%s\\n' ${shQuote(markers.portStart)}`,
    `if command -v ss >/dev/null 2>&1 && [ -n "$__mcp_pids_space" ]; then ss -H -ltnp 2>/dev/null | awk -v pids="$__mcp_pids_space" 'BEGIN { split(pids, a, " "); for (i in a) if (a[i] != "") want[a[i]]=1 } { for (pid in want) if (index($0, "pid=" pid ",") > 0) print $0 }' | sort -u; elif command -v lsof >/dev/null 2>&1 && [ -n "$__mcp_pids_space" ]; then for p in $__mcp_pids_space; do lsof -Pan -p "$p" -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print}'; done; fi`,
    `printf '%s\\n' ${shQuote(markers.portEnd)}`,
    `__mcp_exit_code=""`,
    `if [ -r "$__mcp_exit" ]; then __mcp_exit_code="$(tail -n 1 "$__mcp_exit" 2>/dev/null | tr -dc '0-9')"; fi`,
    `printf '%s\\n' ${shQuote(markers.exitStart)}`,
    `printf 'exitCode=%s\\n' "$__mcp_exit_code"`,
    `printf '%s\\n' ${shQuote(markers.exitEnd)}`,
    `__mcp_log_size=0`,
    `if [ -r "$__mcp_log" ]; then __mcp_log_size="$(wc -c < "$__mcp_log" 2>/dev/null | awk '{print $1 + 0}')"; fi`,
    `__mcp_log_start=${statusOptions.onlyNew ? lastLogOffset : 0}`,
    `if [ "$__mcp_log_start" -gt "$__mcp_log_size" ]; then __mcp_log_start=0; fi`,
    statusOptions.onlyNew
      ? `true`
      : `if [ "$__mcp_log_size" -gt ${statusOptions.tailBytes} ]; then __mcp_log_start=$((__mcp_log_size - ${statusOptions.tailBytes})); fi`,
    `printf '%s\\n' ${shQuote(markers.logMetaStart)}`,
    `printf 'size=%s\\nstart=%s\\nend=%s\\nonlyNew=%s\\n' "$__mcp_log_size" "$__mcp_log_start" "$__mcp_log_size" ${statusOptions.onlyNew ? "'true'" : "'false'"}`,
    `printf '%s\\n' ${shQuote(markers.logMetaEnd)}`,
    `printf '%s\\n' ${shQuote(markers.logStart)}`,
    `if [ -r "$__mcp_log" ]; then ${sourceCommand} | ${logPipeline}; else echo "(no log yet)"; fi`,
    `printf '%s\\n' ${shQuote(markers.logEnd)}`,
  ].join('\n');
}

function parseKeyValueBlock(text) {
  const parsed = {};
  for (const line of String(text || '').split(/\r?\n/)) {
    const match = line.match(/^([^=]+)=(.*)$/);
    if (match) parsed[match[1]] = match[2];
  }
  return parsed;
}

function parseProcessTree(text) {
  return String(text || '').split(/\r?\n/).filter(Boolean).map(line => {
    const parts = line.split('|');
    if (parts.length < 10) return null;
    return {
      pid: Number.parseInt(parts[0], 10),
      ppid: Number.parseInt(parts[1], 10),
      pgid: Number.parseInt(parts[2], 10),
      stat: parts[3],
      elapsed: parts[4],
      cpuPercent: Number.parseFloat(parts[5]) || 0,
      memPercent: Number.parseFloat(parts[6]) || 0,
      rssKb: Number.parseInt(parts[7], 10) || 0,
      command: parts[8],
      args: parts.slice(9).join('|'),
    };
  }).filter(Boolean);
}

function summarizeResources(processTree) {
  return processTree.reduce((summary, proc) => ({
    cpuPercent: Number((summary.cpuPercent + proc.cpuPercent).toFixed(2)),
    memPercent: Number((summary.memPercent + proc.memPercent).toFixed(2)),
    rssKb: summary.rssKb + proc.rssKb,
  }), { cpuPercent: 0, memPercent: 0, rssKb: 0 });
}

function parseListeningPorts(text, allowedPids = [], portsFilter = []) {
  const allowed = new Set(allowedPids);
  const wantedPorts = new Set(portsFilter);
  const ports = [];
  for (const line of String(text || '').split(/\r?\n/).filter(Boolean)) {
    const pids = [...line.matchAll(/pid=(\d+)/g)].map(m => Number.parseInt(m[1], 10));
    if (allowed.size > 0 && pids.length > 0 && !pids.some(pid => allowed.has(pid))) continue;
    const columns = line.trim().split(/\s+/);
    const localAddress = columns[3] || columns[2] || '';
    const portMatch = localAddress.match(/:(\d+)$/);
    const port = portMatch ? Number.parseInt(portMatch[1], 10) : null;
    if (wantedPorts.size > 0 && (!port || !wantedPorts.has(port))) continue;
    ports.push({
      protocol: 'tcp',
      localAddress,
      port,
      pids,
      raw: line,
    });
  }
  return ports;
}

function safeRegexTest(pattern, text) {
  try {
    return new RegExp(pattern).test(text);
  } catch {
    return false;
  }
}

export {
  buildTaskStatusCommand,
  normalizeTaskStatusOptions,
  parseKeyValueBlock,
  parseListeningPorts,
  parseProcessTree,
  safeRegexTest,
  summarizeResources,
};
