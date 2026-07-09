import {
  DEFAULT_TASK_LOG_LINE_LENGTH,
  DEFAULT_TASK_LOG_TAIL_BYTES,
} from './shared.mjs';

// =============================================================================
// Tool definitions — 6 action-based tools (simplified from 26)
// =============================================================================
function getToolDefinitions() {
  return [
    {
      name: "ssh_hosts",
      description: `Manage SSH hosts: list known hosts, get host info, check connectivity, inspect processes/ports, or list active sessions.

Actions:
- "list": List all known SSH hosts from ~/.ssh/config and ~/.ssh/known_hosts
- "info": Get detailed config for a specific host (hostname, user, port, key). Passwords never exposed.
- "check": Test SSH connectivity to a host, returns {connected, latency, errorType}
- "inspect": Inspect remote processes/listening ports with MCP wrapper process filtering
- "sessions": List active SSH sessions with their cwd and env state
- "warmup": Pre-open and warm the SSH session/ControlMaster connection for a host
- "closeSession": Close the SSH ControlMaster/session state for a host

Example: ssh_hosts({ action: "list" })
Example: ssh_hosts({ action: "check", hostAlias: "prod" })
Example: ssh_hosts({ action: "inspect", hostAlias: "prod", processPattern: "vllm|bench serve", ports: [8000] })
Example: ssh_hosts({ action: "warmup", hostAlias: "prod" })`,
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["list", "info", "check", "inspect", "sessions", "warmup", "closeSession"], description: "Action to perform", default: "list" },
          hostAlias: { type: "string", description: "Host alias (required for 'info', 'check', 'inspect', 'warmup', and 'closeSession')" },
          timeout: { type: "number", description: "Connectivity/warmup timeout ms (default: 15000, max: 300000)", default: 15000 },
          processPattern: { type: "string", description: "Regex/literal pattern for inspect action process matching" },
          ports: { type: "array", items: { type: "number" }, description: "Listening TCP ports to filter for inspect/status actions" },
          maxProcesses: { type: "number", description: "Max processes returned for inspect action (default: 50, max: 500)", default: 50 },
        },
        required: ["action"],
      },
    },
    {
      name: "ssh_exec",
      description: `Execute commands on remote SSH host(s). Supports single command, batch (multiple commands on one host), or parallel (same command on multiple hosts).

Parameters:
- command (string): Single command to execute
- commands (array): Multiple commands — runs as batch with mode selection
- hosts (array of {hostAlias, command}): Run different commands on different hosts in parallel

Returns: { success, code, stdout, stderr, errorType, duration, contentType, ... }
- code 0=success, 124=timeout, 127=not found, 255=SSH error, 130=cancelled
- errorType: null|timeout|auth_failed|connection_failed|command_not_found|command_failed|cancelled
- Session state (cwd, env) auto-preserved between calls on same host
- Set showSessionContext=true to return cwd/env before/after and delta; set useSession=false for one-shot non-persistent commands
- Dangerous commands (rm -rf /, mkfs, etc.) require confirmed=true

Example:
- ssh_exec({ hostAlias: "prod", command: "df -h" })
- ssh_exec({ hostAlias: "prod", commands: ["cd /app", "npm test"], mode: "stopOnError" })
- ssh_exec({ hosts: [{hostAlias:"web1",command:"uptime"},{hostAlias:"web2",command:"uptime"}] })`,
      inputSchema: {
        type: "object",
        properties: {
          hostAlias: { type: "string", description: "Target host (for single/batch command)" },
          command: { type: "string", description: "Single command to execute" },
          commands: { type: "array", items: { type: "string" }, description: "Multiple commands for batch execution" },
          hosts: { type: "array", items: { type: "object", properties: { hostAlias: { type: "string" }, command: { type: "string" } }, required: ["hostAlias", "command"] }, description: "Requests for parallel execution across hosts" },
          mode: { type: "string", enum: ["sequential", "stopOnError", "parallel"], description: "Batch mode (default: sequential)", default: "sequential" },
          timeout: { type: "number", description: "Per-command timeout ms (default: 120000, max: 300000)", default: 120000 },
          combineOutput: { type: "boolean", description: "Interleave stdout+stderr by timestamp", default: false },
          confirmed: { type: "boolean", description: "Confirm dangerous operation", default: false },
          useSession: { type: "boolean", description: "Use session state (default: true)", default: true },
          showSessionContext: { type: "boolean", description: "Return session cwd/env before/after and delta", default: false },
          singleConnection: { type: "boolean", description: "Run sequential/stopOnError command batches over one SSH connection (default: true)", default: true },
        },
      },
    },
    {
      name: "ssh_file",
      description: `Read, write, edit, or append remote file content via SSH (base64-encoded, binary-safe). No download/upload needed.

Actions:
- "read": Read file content. Supports offset/limit for partial reads. Returns {content, size, contentType}
- "write": Write content to file (creates/overwrites). Optional mode setting (e.g. "644", "755")
- "edit": Apply search-replace edits in-place. Use read first to see content. Returns diff preview.
- "append": Append content to file (creates if not exists)

Examples:
- ssh_file({ action: "read", hostAlias: "prod", path: "/etc/nginx/nginx.conf" })
- ssh_file({ action: "edit", hostAlias: "prod", path: "/etc/nginx/nginx.conf", edits: [{oldText:"listen 80;", newText:"listen 443 ssl;"}] })
- ssh_file({ action: "write", hostAlias: "prod", path: "/app/config.json", content: "{\\"debug\\":true}", mode: "644" })`,
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["read", "write", "edit", "append"], description: "File operation" },
          hostAlias: { type: "string", description: "Target host" },
          path: { type: "string", description: "Remote file path" },
          content: { type: "string", description: "Content to write/append (for write/append actions)" },
          edits: { type: "array", items: { type: "object", properties: { oldText: { type: "string" }, newText: { type: "string" } }, required: ["oldText", "newText"] }, description: "Search-replace edits (for edit action)" },
          mode: { type: "string", description: "File permissions e.g. '644', '755' (for write action)" },
          offset: { type: "number", description: "Byte offset to start reading (for read action)" },
          limit: { type: "number", description: "Max bytes to read (for read action)" },
          createIfMissing: { type: "boolean", description: "Create file if not exists (for edit action)", default: false },
        },
        required: ["action", "hostAlias", "path"],
      },
    },
    {
      name: "ssh_fs",
      description: `Remote filesystem operations: list directory, stat file, mkdir, remove, move.

Actions:
- "list": List directory contents. Returns structured entries {name, type, size, modifiedAt}
- "stat": Get file metadata {size, mode, modifiedAt, type}
- "mkdir": Create directory (parents=true by default, like mkdir -p)
- "rm": Remove file/directory (recursive by default). Dangerous paths require force=true.
- "mv": Move/rename file or directory

Examples:
- ssh_fs({ action: "list", hostAlias: "prod", path: "/var/log" })
- ssh_fs({ action: "mkdir", hostAlias: "prod", path: "/app/logs" })
- ssh_fs({ action: "rm", hostAlias: "prod", path: "/tmp/build", force: true })`,
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["list", "stat", "mkdir", "rm", "mv"], description: "Filesystem operation" },
          hostAlias: { type: "string", description: "Target host" },
          path: { type: "string", description: "Remote path" },
          destPath: { type: "string", description: "Destination path (for mv action)" },
          parents: { type: "boolean", description: "Create parent dirs (mkdir, default: true)", default: true },
          recursive: { type: "boolean", description: "Recursive (rm, default: true)", default: true },
          force: { type: "boolean", description: "Override danger detection (rm, default: false)", default: false },
          detailed: { type: "boolean", description: "Include size/type/modifiedAt (list, default: true)", default: true },
        },
        required: ["action", "hostAlias", "path"],
      },
    },
    {
      name: "ssh_transfer",
      description: `Transfer files between local and remote via SCP. Supports single files and directories.

Actions:
- "upload": Upload local file/dir to remote host
- "download": Download remote file/dir to local

Set recursive=true for directory transfer (uses scp -r).
Returns {success, bytesTransferred, duration} or {success:false, error, errorType, stderr} on failure.

Examples:
- ssh_transfer({ action: "upload", hostAlias: "prod", localPath: "./dist", remotePath: "/app/dist", recursive: true })
- ssh_transfer({ action: "download", hostAlias: "prod", remotePath: "/var/log/app.log", localPath: "./app.log" })`,
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["upload", "download"], description: "Transfer direction" },
          hostAlias: { type: "string", description: "Target host" },
          localPath: { type: "string", description: "Local file/directory path" },
          remotePath: { type: "string", description: "Remote file/directory path" },
          recursive: { type: "boolean", description: "Transfer directory recursively (default: false)", default: false },
          preservePermissions: { type: "boolean", description: "Preserve file permissions (scp -p, default: false)", default: false },
          timeout: { type: "number", description: "Timeout ms (default: 60000 for files, 300000 for dirs)", default: 60000 },
        },
        required: ["action", "hostAlias", "localPath", "remotePath"],
      },
    },
    {
      name: "ssh_task",
      description: `Manage background tasks on remote hosts: start long-running commands, check status, stop, or list active tasks.

Actions:
- "start": Start a command in background (via nohup/setsid). Returns {taskId, remotePid, processGroupId, logFile}
- "status": Check task status. Returns {running, health, processTree, portsListening, resources, recentLog, remotePid, processGroupId, startedAt}
- "stop": Stop a running background task (kills remote process group, escalates, verifies)
- "list": List all active background tasks

Examples:
- ssh_task({ action: "start", hostAlias: "prod", command: "npm run build" })
- ssh_task({ action: "status", taskId: "task_12345" })
- ssh_task({ action: "list" })`,
      inputSchema: {
        type: "object",
        properties: {
          action: { type: "string", enum: ["start", "status", "stop", "list"], description: "Task operation" },
          hostAlias: { type: "string", description: "Target host (for start action)" },
          command: { type: "string", description: "Command to run in background (for start action)" },
          taskId: { type: "string", description: "Task ID (for status/stop actions)" },
          timeout: { type: "number", description: "Startup timeout ms for background command (default: 120000, max: 300000)", default: 120000 },
          logLines: { type: "number", description: "Lines of task log to include for status action (default: 50, max: 1000)", default: 50 },
          grep: { type: "string", description: "Include only status log lines matching this extended regex" },
          exclude: { type: "string", description: "Exclude status log lines matching this extended regex" },
          tailBytes: { type: "number", description: "Bytes of task log to scan before line filtering (default: 262144, max: 2097152)", default: DEFAULT_TASK_LOG_TAIL_BYTES },
          onlyNew: { type: "boolean", description: "Show only log bytes added since the previous onlyNew status call", default: false },
          maxLogLineLength: { type: "number", description: "Truncate individual log lines after this many characters (default: 1000)", default: DEFAULT_TASK_LOG_LINE_LENGTH },
          readyPattern: { type: "string", description: "Regex considered ready when it appears in the returned log window" },
          ports: { type: "array", items: { type: "number" }, description: "Ports expected to be listening for readiness checks" },
        },
        required: ["action"],
      },
    },
  ];
}

export { getToolDefinitions };
