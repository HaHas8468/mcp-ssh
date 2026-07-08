# MCP SSH Full Function Test Report

Date: 2026-07-07
Target host: `scnet-docker`
Host path: `scnet-docker -> scnet-computer -> scnet-login`

## Summary

The local Codex MCP configuration is loading the new 6-tool `mcp-ssh` server successfully.
The server can connect to `scnet-docker` and execute commands through the configured ProxyJump chain.

Test result: usable, with several performance and correctness issues to fix before a polished release.

## Passed Coverage

### `ssh_hosts`

- `list`: listed `scnet-login`, `scnet-computer`, and `scnet-docker`.
- `info`: returned sanitized host config for `scnet-docker`.
- `check`: returned `connected: true`.
- `sessions`: returned tracked session state after command execution.

### `ssh_exec`

- Single command: passed.
- Batch sequential: passed.
- Batch `stopOnError`: passed and stopped after first failing command.
- Batch `parallel`: passed.
- Multi-host style `hosts` array: passed using two requests against `scnet-docker`.
- Session cwd/env tracking: passed. `cd /tmp/mcp-ssh-full-smoke` and `export MCP_SMOKE_VAR=present` were preserved for later calls.
- Timeout: passed functionally, returned `code: 124` and `errorType: "timeout"`.
- Unknown host: failed gracefully.
- Dangerous filesystem command via `ssh_fs rm /`: blocked correctly.

### `ssh_file`

- `write`: passed.
- `read`: passed.
- `read` with `offset` and `limit`: passed.
- `append`: passed.
- `edit`: passed and returned a diff preview.

### `ssh_fs`

- `mkdir`: passed.
- `stat`: passed.
- `list`: passed, but includes the directory itself as the first entry.
- `mv`: passed.
- `rm`: passed.

### `ssh_transfer`

- Single-file `upload`: passed.
- Single-file `download`: passed.
- Recursive directory `upload`: passed.
- Recursive directory `download`: passed.

### `ssh_task`

- `start`: simple short background task returned success.
- `list`: returned active task records.
- `status`: works when using the task id from `list`.
- `stop`: works when using the task id from `list`.

### MCP Resources

- `resources/list`: exposes SSH hosts as `ssh://hosts/...`.
- `resources/read`: returns host JSON for `ssh://hosts/scnet-docker`.

## Issues Found

### P1: Windows + ProxyJump failed with ControlMaster enabled

Initial `ssh_exec` through the MCP server failed with:

```text
getsockname failed: Not a socket
Read from remote host 173.0.90.4: Unknown error
```

Raw `ssh scnet-docker` worked, so the failure was caused by MCP-injected ControlMaster arguments on Windows. A local fix was applied: Windows now defaults `controlMaster` to `false`, while non-Windows keeps the previous default.

### P1: `ssh_task start` returns the wrong `taskId`

Status: fixed locally after the initial smoke test. `startBackground()` now registers the same task id that it returns to the caller.

Observed:

- `ssh_task start` returned `task_1783440371337_iwqhqj`.
- `ssh_task list` showed the actual registered id as `task_1783440373452_0yc7yp`.
- `ssh_task status` with the id returned from `start` failed with `Task ... not found`.

Root cause: `startBackground()` generated a task id for the log path before calling `TaskManager.register()`, then `TaskManager.register()` generated a second id.

### P1: `ssh_task start` has a hard-coded timeout that is too short for ProxyJump

Status: fixed locally. `startBackground()` now uses the configured default timeout and accepts an explicit startup `timeout`; `ssh_task start` passes that option through.

Starting a longer background task failed with timeout:

```text
[Command timed out]
```

The remote command should return quickly because it uses `nohup ... & echo $!`, but on this ProxyJump path the connection setup alone can exceed a short internal timeout.

### P2: `errorType` is null for command failures after marker parsing

Status: fixed locally. Error classification now happens after marker-derived exit code extraction.

Running a missing command returned:

```json
{
  "code": 127,
  "errorType": null
}
```

Expected: `errorType: "command_not_found"`.

### P2: `ssh_fs list` includes the target directory itself

Status: fixed locally. Detailed directory listing now uses `find ... -mindepth 1 -maxdepth 1`.

Listing `/tmp/mcp-ssh-full-smoke` returned:

```text
mcp-ssh-full-smoke
file.txt
json.txt
sub
```

Expected: only child entries.

### P2: Timeout duration exceeds requested timeout

`ssh_exec` with `timeout: 1000` returned `errorType: "timeout"`, but wall time was about 11 seconds. The extra time appears to come from post-timeout remote cleanup. This is functionally correct but should be documented or bounded.

### P2: High latency on some commands through ProxyJump

Several successful operations took 20-40 seconds, especially session-related commands and file writes. Examples:

- `cd /tmp/mcp-ssh-full-smoke`: about 30 seconds.
- `export MCP_SMOKE_VAR=present`: about 27 seconds.
- `ssh_file edit`: about 76 seconds because it performs read plus write.
- `ssh_fs mv`: about 46 seconds.

This is probably caused by disabling ControlMaster on Windows to avoid the ProxyJump failure. A future Windows-safe multiplexing strategy would greatly improve usability.

### P3: Repeated known-host warnings clutter stderr

Most successful calls include repeated warnings like:

```text
Warning: Permanently added '[zzeshell.scnet.cn]:65032' ...
Warning: Permanently added 'e03r1n05' ...
Warning: Permanently added '173.0.90.4' ...
```

These warnings are harmless but noisy for agents. Consider adding an option to suppress or filter known-host warning lines from `stderr`, while preserving real errors.

### P3: Missing `known_hosts` file logs a local debug warning

Status: fixed locally. Missing `~/.ssh/known_hosts` is now treated as an empty known-hosts list without debug noise.

Local test output included:

```text
Error reading known_hosts file: ENOENT: no such file or directory
```

The server still works via SSH config.

## Suggested Fix Order

1. Add a Windows-safe strategy for optional connection reuse, or document the performance tradeoff.
2. Bound timeout cleanup duration so short requested timeouts do not wait too long for remote cleanup.
3. Filter repeated known-host warnings from successful command stderr.

## Cleanup

Remote test directory removed:

```text
/tmp/mcp-ssh-full-smoke
```

Local test directory removed:

```text
C:\Users\s8468\AppData\Local\Temp\mcp-ssh-full-smoke
```
