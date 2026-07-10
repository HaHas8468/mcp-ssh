# mcp-ssh v3 开发说明

## 常用命令

- `npm start`：通过 stdio 启动 MCP 服务。
- `npm test`：运行 v3 单元与契约测试。
- `npm run test:unit`、`npm run test:contract`、`npm run test:integration`：分别执行对应测试层。
- `npm run build:dxt`：生成 DXT 包。

## 架构

运行时从 `src/mcp/server.mjs` 进入，公开接口固定为五个工具：`ssh_targets`、`ssh_exec`、`ssh_file`、`ssh_transfer`、`ssh_task`。

- `TargetCatalog` 只发现 SSH 配置及 Include 中的显式别名；有效配置必须由 `ssh -G` 获取。
- `RouteResolver` 解析 ProxyJump，并检测环路与超深路由。
- `ConnectionManager` 按最终目标与配置指纹管理 POSIX ControlMaster；Windows 自动使用无复用实现。
- 仅 `OpenSshAdapter` 可启动本地 `ssh` 与 `scp` 进程。
- 执行、文件、传输和任务服务没有跨请求的 cwd 或环境变量状态。

## 安全不变量

- 本地进程始终使用 argv 与 `shell: false`；不得接受模型提供的 SSH 选项、ProxyCommand 或 ControlPath。
- `target` 必须是显式 SSH 配置别名，不能使用裸 `known_hosts` 地址。
- 密码仅通过 keychain 或 `@password` 注释进入 askpass 环境；不得写入 argv、日志、错误或 MCP 返回。
- `ssh_transfer` 的本地路径必须位于 `allowedLocalRoots`。
- 危险命令只接受 MCP elicitation 的真实用户批准；工具参数中不存在 `confirmed` 绕过项。

## 状态目录

默认目录为 `~/.mcp-ssh/`：ControlPath 在 `runtime/control`，大输出在 `runtime/outputs`，任务记录在 `state/tasks.json`。POSIX 目录与文件权限分别为 `0700` 和 `0600`。
