# mcp-ssh

`mcp-ssh` 是一个使用本机 OpenSSH 配置的 MCP stdio 服务。它不实现 SSH 协议；`ssh -G`、`ssh`、`scp`、ProxyJump、SSH Agent 与主机密钥验证均继续由 OpenSSH 负责。

## 安装

从 Release 下载与你的平台相符的 `mcp-ssh` 可执行文件，并加入 `PATH`。MCP 配置示例：

```json
{
  "mcpServers": {
    "ssh": {
      "command": "/absolute/path/to/mcp-ssh",
      "args": [],
      "env": { "MCP_SILENT": "true" }
    }
  }
}
```

服务公开 `ssh_targets`、`ssh_exec`、`ssh_file`、`ssh_transfer` 与 `ssh_task` 五个工具。目标必须是 `~/.ssh/config` 中的显式 `Host` 别名。

## 从 v3 迁移

在停用旧 Node 服务后执行：

```sh
mcp-ssh migrate-state
```

该命令将旧的任务记录和截断输出复制到 `~/.mcp-ssh/state/v4`、`~/.mcp-ssh/runtime/v4`，不会删除 v3 数据。运行时配置与策略文件仍使用 `~/.mcp-ssh/config.json`、`~/.mcp-ssh/permissions.json`。
