# scnet-docker MCP Test Report

Test time: 2026-07-08T01:43:41Z

## Target

- Host alias: `scnet-docker`
- SSH config: `/home/haha/.ssh/config`
- MCP server: local `/home/haha/mcp-ssh/bin/mcp-ssh.js`

## SSH Config Fixes Applied

The first connection attempts failed before MCP functional testing could proceed. I fixed the local SSH config used by the MCP server:

1. Replaced relative `IdentityFile ../...` paths with absolute paths under `/home/haha/.ssh/`.
2. Changed Windows-only `NUL` known-hosts paths to Linux `/dev/null`.
3. Set private key permissions to `600`.
4. Added `GSSAPIAuthentication no` and `ConnectTimeout 30` for the three scnet hosts.

A backup of the original config was created as `/home/haha/.ssh/config.bak-mcp-ssh-test-*`.

## Results

| Area | Result | Notes |
| --- | --- | --- |
| `ssh_hosts list` | PASS | Found `scnet-login`, `scnet-computer`, and `scnet-docker`. |
| `ssh_hosts info` | PASS | Returned sanitized config for `scnet-docker`. |
| `ssh_hosts check` | PASS after config fixes | Initially timed out; later returned `connected: true`. |
| `ssh_exec` single command | PASS | Returned hostname `worker-0`, user `root`, cwd `/root`. |
| `ssh_exec` batch commands | PASS | `cd /tmp` and exported env persisted in session state. |
| `ssh_hosts sessions` | PASS | Session showed cwd `/tmp` and env count `1`. |
| `ssh_fs mkdir/stat/list/mv/rm` | PASS | Tested under `/tmp/mcp-ssh-codex-test`. |
| `ssh_file write/read/edit/append` | PASS | Wrote, edited, appended, and read test content successfully. |
| `ssh_transfer upload/download` | PASS | Uploaded and downloaded a small file; local `cmp` matched. |
| `ssh_task start/status/stop/list` | PASS with note | Start/status/stop worked; completed tasks remain listed. |

## Issues Found

1. SSH config portability issue - fixed locally

   The original WSL config used Windows-style or cwd-sensitive values:

   - `IdentityFile ../...`
   - `UserKnownHostsFile NUL`
   - `GlobalKnownHostsFile NUL`

   In WSL/Linux, `NUL` is treated as a normal file name, and relative identity paths can fail depending on the process cwd.

2. Slow multi-hop authentication without `GSSAPIAuthentication no` - fixed locally

   The first and second jump hosts spent time trying GSSAPI/Kerberos. With the MCP server's default timeouts, this caused `ssh_hosts check` and `ssh_exec` to time out. Adding `GSSAPIAuthentication no` made the path reliable.

3. `ssh_hosts check` timeout is not configurable through the tool schema - fixed in code

   The tool now exposes a `timeout` property, and `checkConnectivity()` passes it through to the underlying SSH command.

4. Remote login warning on `scnet-computer` - remote environment issue

   Native SSH to `scnet-computer` printed:

   ```text
   /etc/profile.d/ssh-auto-keygen.sh: line 33: /public/home/xdzs2026_c203/.ssh/config: Permission denied
   chmod: changing permissions of '/public/home/xdzs2026_c203/.ssh/config': Operation not permitted
   ```

   This warning appears to come from the remote environment. It did not block connecting to `scnet-docker`.

5. Completed background tasks remain in `ssh_task list` - fixed in code

   `ssh_task list` now checks each tracked remote pid, prunes exited tasks, and only returns tasks that are still running or whose status could not be verified.

## Fix Verification

- Unit tests: `105 passed / 105`
- SDK smoke test:
  - `ssh_hosts` tool schema includes `timeout`
  - `ssh_hosts check` with `{ timeout: 90000 }` returned `connected: true`
  - A short `ssh_task start` command was pruned from `ssh_task list` after it exited

## Cleanup

- Removed remote test directory: `/tmp/mcp-ssh-codex-test`
- Removed local temp files:
  - `/tmp/mcp-ssh-local-upload.txt`
  - `/tmp/mcp-ssh-downloaded.txt`
