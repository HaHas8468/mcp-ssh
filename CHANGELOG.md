# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- NPM package distribution via @aiondadotcom/mcp-ssh
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
