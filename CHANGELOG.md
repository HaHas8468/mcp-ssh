# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- SSH/SCP 调用现在使用独立本地进程组，并在 POSIX `/proc` 可用时递归终止脱离根进程组的 OpenSSH/ProxyJump 后代；取消、超时和服务关闭会清理活动进程登记与 TERM→KILL 升级定时器。
- `timeoutMs` 现在覆盖目标解析、连接准备、远程执行和清理，不再只限制最终 SSH 子进程。
- 冷启动会先校验并接管健康的既有 ControlMaster；跨 MCP 进程使用原子锁与 generation token 协调 check/remove/open，避免误删刚重建的 socket。
- 无论 SSH 退出码为何，均识别并剥离本地 mux 降级诊断；已完成操作保持成功并返回 `SSH_MASTER_DEGRADED` warning，确认未开始的操作仅安全重试一次，状态不明的写入与后台任务不重放。
- stdio 关闭及 `SIGTERM`/`SIGINT`/`SIGHUP` 现在统一取消活动操作并等待本地 SSH 子进程退出；`SIGCONT` 会恢复活动进程组并强制所有连接在下一次使用前执行健康检查。

## [3.0.0] - 2026-07-10

### Changed
- Replaced the v2 session-oriented API with five v3 tools: `ssh_targets`, `ssh_exec`, `ssh_file`, `ssh_transfer`, and `ssh_task`.
- SSH targets are now explicit aliases from SSH config; raw `known_hosts` addresses, warmup, sessions, batches, cross-host parallelism, and hidden shell state are no longer public API.
- All tool responses use stable operation results, structured MCP content, output schemas, request IDs, timings, and error codes.

### Added
- Added `ssh -G` effective-config resolution, recursive ProxyJump route resolution, route-cycle detection, and configuration fingerprints.
- Added final-target ControlMaster connection reuse with health checks, single-flight connection creation, stale socket cleanup, and a Windows no-pooling fallback.
- Added bounded output storage/resources, atomic task-state persistence, atomic remote file writes, optimistic SHA-256 writes, and local transfer-root enforcement.

## [2.0.0] - 2026-07-07

### Changed
- Consolidated the SSH MCP surface into 6 action-based tools: `ssh_hosts`, `ssh_exec`, `ssh_file`, `ssh_fs`, `ssh_transfer`, and `ssh_task`.
- Grouped related host, command, file, filesystem, transfer, and background-task operations behind clear `action` parameters so coding agents have fewer tools to choose from.
- Updated MCP tool descriptions with action docs, examples, and structured result expectations.
- Declared both `tools` and `resources` capabilities for the MCP server.

### Added
- Added remote file content operations (`read`, `write`, `edit`, `append`) and remote filesystem operations (`list`, `stat`, `mkdir`, `rm`, `mv`) under the merged tool model.
- Added background task management through `ssh_task`.

## [1.3.8] - 2026-04-14

### Fixed
- **Startup regression**: The `start.sh`, `start-silent.sh`, `npm start`, `npm run dev`, and DXT manifest all launched `node server.mjs` directly, but since 1.3.6 `server.mjs` no longer auto-runs `main()` — only `bin/mcp-ssh.js` does. The server therefore exited immediately on startup for anyone not invoking the bin wrapper (including the shipped start scripts and DXT package). All entry points now call `node bin/mcp-ssh.js`.

## [1.3.7] - 2026-04-11

### Security
- Resolved all open `npm audit` advisories (4 high, 3 moderate) by bumping transitive dependencies. Seven GHSAs no longer reachable from this package:
  - `path-to-regexp` (prod, via `@modelcontextprotocol/sdk → express → router`) — CVE-2024-45296 / CVE-2024-52798 DoS (not exploitable via our STDIO-only usage, fixed anyway).
  - `node-forge` — GHSA-2328-f5f3-gj25, GHSA-q67f-28xg-22rw, GHSA-5m6q-g25r-mvwx, GHSA-ppp5-5v6c-4jwp.
  - `hono`, `@hono/node-server`, `brace-expansion` (dev, via vitest chain).
  - `picomatch`, `vite` (dev, via vitest chain) — required a `vitest`/`@vitest/coverage-v8` minor bump from 4.0.18 to 4.1.4.
- `npm audit --audit-level=high` now reports zero vulnerabilities. CI workflow's security audit step is unchanged and continues to block on any future high-severity finding.

## [1.3.6] - 2026-04-11

### Fixed
- **Windows startup (fixes #8)**: The server silently exited when launched via `bin/mcp-ssh.js` on Windows MCP clients (e.g. Antigravity), causing a "failed to initialize: EOF" error. The cause was an `isMainModule` check in `server.mjs` that compared `process.argv[1]` against forward-slash path suffixes (`/mcp-ssh.js`), which never matched on Windows where `process.argv[1]` uses backslashes. The check has been removed entirely; `bin/mcp-ssh.js` now imports `main()` from `server.mjs` and calls it explicitly. Reported by @sdwru.

## [1.3.5] - 2026-04-11

### Security
- **SECURITY FIX (high)**: Fixed SSH `ProxyCommand` option-injection that allowed local RCE on the machine running the MCP server. A crafted `hostAlias` such as `-oProxyCommand=...` was passed to `ssh`/`scp` without an argument-terminator, so SSH interpreted it as an option and executed the attacker's command locally — bypassing the documented protection of `# @password:` annotations and exposing local SSH keys and credentials.
- **SECURITY FIX (high, Windows-only)**: Fixed a second local-RCE vector on Windows. `runRemoteCommand`, `uploadFile` and `downloadFile` previously used `spawn(..., { shell: true })` so that `ssh.exe`/`scp.exe` could be found via PATH. With `shell: true` every argument is re-parsed by `cmd.exe`, so shell metacharacters (`&`, `|`, `^`, `>`, `"`, `;`, etc.) in `hostAlias`, `command`, `localPath` or `remotePath` would have been interpreted by `cmd.exe` and could trigger arbitrary local command execution. The server now resolves `ssh.exe`/`scp.exe` to absolute paths once at startup (via PATH + PATHEXT walk) and uses `shell: false` everywhere.
- **Hardening**: Added a strict whitelist for `hostAlias` (`^[A-Za-z0-9_.@:][A-Za-z0-9._@:-]*$`). Rejects leading `-` (option injection) and all shell metacharacters (cmd.exe injection). Applied to `runRemoteCommand`, `uploadFile`, `downloadFile` (and transitively to `checkConnectivity` and `runCommandBatch`).
- **Hardening**: Added a known-host check (`_assertKnownHostAlias`) that requires every `hostAlias` to be defined in `~/.ssh/config` (including Include directives) or present in `~/.ssh/known_hosts`. The LLM can no longer reach arbitrary hostnames the user has not explicitly configured — Whitelist instead of Blacklist.
- **Hardening**: Added `--` argument terminator to all `ssh`/`scp` invocations as defense in depth.
- **Fix**: Removed the hard-coded `DISPLAY=:0` value from the SSH askpass environment. It was a POSIX/X11 assumption that could break behavior on Windows; `SSH_ASKPASS_REQUIRE=force` is sufficient on its own.
- **Fix**: `expandIncludePath()` now handles Windows drive-letter and UNC paths correctly (`path.isAbsolute` + `path.win32.isAbsolute`) and accepts `~\path` with a backslash separator.
- Added regression tests for the option-injection vector and shell-metacharacter vector across all five affected tools.
- Documented the tool's threat model and trust boundaries in `README.md` (`runRemoteCommand` is by-design remote RCE; `uploadFile`/`downloadFile` expose the local filesystem with the server process's privileges; recommend running under an unprivileged user or in a container).
- Reported by Pico (`piiiico` on GitHub) as part of an MCP server security audit. Thank you for the responsible disclosure.

## [1.1.0] - 2025-08-17

### Added
- **NEW FEATURE**: SSH config Include directive support
- Added recursive processing of Include directives in SSH configuration files
- Support for glob patterns in Include paths (e.g., `Include ~/.ssh/configs/*`)
- Enhanced SSH host discovery from included configuration files
- Added `glob` dependency for Include path pattern matching

### Enhanced
- Improved SSH configuration parsing to handle complex Include hierarchies
- Enhanced host discovery to recursively process all included config files
- Better error handling for malformed or inaccessible Include files

## [1.0.4] - 2025-08-17

### Security
- **SECURITY FIX**: Fixed command injection vulnerability in SSH operations (commit 5b9b9c5)
- **SECURITY FIX**: Upgraded `tmp` dependency to version 0.2.5 to address CVE vulnerability
- Fixed arbitrary temporary file/directory write via symbolic link in `tmp` package (GHSA-52f5-9888-hmc6)
- Added dependency overrides to ensure all transitive dependencies use secure `tmp` version
- Enhanced input validation and sanitization for SSH commands and file paths

### Technical
- Added `tmp: ">=0.2.4"` to devDependencies to force secure version
- Added npm overrides configuration to enforce secure tmp version across entire dependency tree
- Updated package-lock.json to reflect security fixes

## [1.0.3] - 2025-06-06

### Added
- Binary wrapper script (`bin/mcp-ssh.js`) for proper npx compatibility
- Fixed npx execution issues by implementing wrapper pattern

### Fixed
- NPX executable resolution using wrapper script approach
- Package binary configuration now points to proper wrapper

### Technical
- Added `bin/mcp-ssh.js` wrapper to handle npx execution
- Updated package.json bin configuration to use wrapper script

## [1.0.2] - 2025-06-06

### Fixed
- Build script temporary fix
- File permissions for executable

## [1.0.1] - 2025-06-06

### Fixed
- Initial package configuration
- File permissions

## [1.0.0] - 2025-06-06

### Added
- Initial release of MCP SSH Agent
- Support for all SSH operations via native ssh/scp commands
- Automatic SSH host discovery from ~/.ssh/config and ~/.ssh/known_hosts
- Functions: listKnownHosts, runRemoteCommand, getHostInfo, checkConnectivity, uploadFile, downloadFile, runCommandBatch
- Claude Desktop integration support
- NPM package distribution via @hahalololos/mcp-ssh
- npx compatibility for easy installation and usage

### Features
- Native SSH command execution for maximum compatibility
- Silent mode for MCP clients (MCP_SILENT=true)
- Comprehensive error handling with timeouts
- Batch command execution support
- File upload/download via scp
- SSH connectivity testing

### Documentation
- Complete README with Claude Desktop setup instructions
- Usage examples and troubleshooting guide
- Professional npm package configuration
