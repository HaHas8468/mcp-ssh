# 迁移到 mcp-ssh 3.0

v3 是一次不兼容升级。它不再维护 SSH shell 会话，也不再公开预热、批处理、跨主机并行或独立文件系统工具。

| v2 | v3 |
| --- | --- |
| `ssh_hosts` | `ssh_targets` |
| `hostAlias` | `target` |
| `ssh_exec.commands` / `hosts` | 一个 `command`，多步骤使用多行 shell 脚本 |
| 保存的 cwd/env | 每次 `ssh_exec` 显式给 `cwd`、`env` |
| `ssh_file.edit`、`ssh_fs` | `ssh_file.read` 后以 `expectedSha256` 执行完整 `write`；目录操作使用 `ssh_exec` |
| `ssh_task.start` | `ssh_exec({ detach: true })` |
| `preservePermissions` / `timeout` | `preserve` / `timeoutMs` |
| `confirmed=true` | MCP elicitation 的真实用户批准 |

目标必须是 `~/.ssh/config` 或 Include 文件中的显式 `Host` 别名。`known_hosts` 中的裸地址不再是可调用目标。

每个工具现在返回 `ok`、`requestId`、`operation`、`timing`、`data`、`warnings` 和稳定的 `error`。超出输出预算的内容可从 `mcp-ssh://outputs/{requestId}/...` 读取，后台日志可从 `mcp-ssh://tasks/{taskId}/log` 读取。
