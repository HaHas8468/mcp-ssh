# mcp-ssh v3 整体架构设计

状态：Implemented（v3.0.0）  
目标版本：v3  
设计基准：`scnet-login -> scnet-computer -> scnet-docker` 三级 SSH 路由

## 1. 产品定义

mcp-ssh v3 是一个面向 Agent 的远程执行运行时。它通过用户现有的 OpenSSH 配置访问远程目标，并提供少量、稳定、可预测的 MCP 操作。

Agent 只需要表达两件事：

1. 最终目标是谁，例如 `scnet-docker`。
2. 想执行什么操作，例如运行命令、读写文件、传输数据或管理后台任务。

路由解析、ProxyJump、连接预热、ControlMaster、连接恢复、超时清理、输出限流和错误诊断均属于 MCP 内部机制，不要求 Agent 参与管理。

### 1.1 核心体验目标

- Agent 可以直接操作最终目标，不需要先执行 `list`、`check` 或 `warmup`。
- `scnet-docker` 与普通单跳主机使用完全相同的工具参数。
- 首次访问承担建链成本，后续命令、文件和传输操作自动复用连接。
- 任意失败都能区分目标解析、跳板连接、认证、远程执行和本地传输阶段。
- 默认没有跨调用的隐藏 shell 状态，不会发生不同 Agent 之间的工作目录或环境变量污染。
- 返回内容具有稳定结构、明确退出状态和严格输出预算。
- MCP 重启后仍能恢复其创建的后台任务记录。

### 1.2 核心能力

- 从 OpenSSH 配置发现和解析目标。
- 执行同步命令和启动后台任务。
- 读取及原子写入远程文件。
- 上传和下载文件或目录。
- 查询、读取日志和停止后台任务。
- 诊断 SSH 路由和连接问题。

### 1.3 非目标

v3 首版不承担以下职责：

- 通用终端模拟器或交互式 PTY 产品。
- 自动保存任意 shell 状态，例如 `source`、函数、alias、conda 激活状态。
- Kubernetes、Docker、数据库等专用管理协议。
- 任意网络扫描或访问未显式配置的主机。
- 工作流编排器；跨主机并行由 Agent/MCP 客户端编排。
- 自行重新实现 OpenSSH 的配置、认证和加密协议。

## 2. 设计原则

### 2.1 最终目标优先

所有公开工具统一接收 `target`。`target` 是用户 SSH 配置中的稳定别名，而不是主机名、跳板参数或临时连接字符串。

```json
{
  "target": "scnet-docker",
  "command": "pwd"
}
```

Agent 不传递 `ProxyJump`、`ProxyCommand`、IdentityFile 或 ControlPath。

### 2.2 OpenSSH 是配置真相来源

目标的有效配置通过 `ssh -G <target>` 获取。项目可以扫描配置文件发现显式 `Host` 别名，但不能依靠第三方解析器重新实现 OpenSSH 的匹配和覆盖语义。

### 2.3 连接状态与执行上下文分离

ControlMaster 只表示传输连接可复用，不表示 shell 持久存在。

执行上下文通过每次请求显式提供：

```json
{
  "target": "scnet-docker",
  "command": "npm test",
  "cwd": "/workspace/project",
  "env": {
    "NODE_ENV": "test"
  }
}
```

### 2.4 默认不重放远程命令

连接建立失败可以安全重试；远程命令开始执行后发生连接中断时，不能直接自动重放，因为命令可能已经产生副作用。

无法确定执行状态时返回：

```json
{
  "code": "EXECUTION_STATE_UNKNOWN",
  "mayHaveRun": true,
  "retryable": false
}
```

文件读取等明确幂等操作可以由相应服务声明允许重试。

### 2.5 小而稳定的公开表面

公开工具只描述用户意图。连接预热、批处理连接复用、重连次数、ControlMaster 和输出缓存均为内部策略。

### 2.6 安全边界不可下沉给 Agent

Agent 被视为不可信输入源。不能让 Agent 通过参数注入本地 SSH 选项，也不能让模型用 `confirmed=true` 自行声明获得了用户批准。

## 3. 总体架构

```text
┌──────────────────────────────────────────────────────────────┐
│                         MCP Adapter                          │
│ schema / validation / structuredContent / cancellation      │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│                       Application Services                   │
│ TargetService / ExecService / FileService / TransferService │
│ TaskService                                                  │
└───────────────┬──────────────────────────────┬───────────────┘
                │                              │
┌───────────────▼────────────────┐  ┌──────────▼───────────────┐
│      Target & Route Core       │  │     Operation State      │
│ TargetCatalog / RouteResolver  │  │ TaskStore / OutputStore  │
└───────────────┬────────────────┘  └──────────┬───────────────┘
                │                              │
┌───────────────▼──────────────────────────────▼───────────────┐
│                    Connection Manager                        │
│ final-target ControlMaster / single-flight / health / drain │
└──────────────────────────────┬───────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────┐
│                     OpenSSH Adapter                          │
│ ssh / scp / ssh -G / ssh -O / askpass / safe argv           │
└──────────────────────────────────────────────────────────────┘

横切能力：PolicyGuard / SecretProvider / Audit / Diagnostics
```

### 3.1 依赖方向

- MCP Adapter 依赖 Application Services。
- Application Services 依赖领域接口，不直接调用 `child_process`。
- Connection Manager 依赖 OpenSSH Adapter。
- OpenSSH Adapter 不依赖 MCP SDK。
- Policy、Secret、Audit 和 StateStore 通过接口注入。
- 任何核心模块都不能反向依赖工具定义或 MCP 请求对象。

## 4. 推荐目录结构

```text
src/
  domain/
    target.mjs
    route.mjs
    result.mjs
    errors.mjs

  core/
    target-catalog.mjs
    route-resolver.mjs
    connection-manager.mjs
    execution-registry.mjs

  services/
    target-service.mjs
    exec-service.mjs
    file-service.mjs
    transfer-service.mjs
    task-service.mjs

  adapters/
    openssh-adapter.mjs
    credential-provider.mjs
    local-state-store.mjs
    audit-logger.mjs

  mcp/
    server.mjs
    tools.mjs
    resources.mjs
    presenters.mjs

  compatibility/
    v2-tools.mjs
```

文件按职责拆分，不要求每个模块都成为类。纯解析和转换逻辑优先使用无状态函数。

## 5. 领域模型

### 5.1 TargetId

```ts
type TargetId = string;
```

默认只允许显式配置的非通配符 SSH Host 别名。来自 `known_hosts` 的裸主机名只有在用户配置明确开启后才能成为目标。

### 5.2 ResolvedTarget

```ts
interface ResolvedTarget {
  id: TargetId;
  destination: {
    hostname: string;
    user?: string;
    port: number;
  };
  route: RouteHop[];
  proxyMode: "none" | "jump" | "opaque-command";
  configFingerprint: string;
  auth: {
    method: "agent" | "identity-file" | "password" | "unknown";
    secretAvailable: boolean;
  };
  warnings: DiagnosticWarning[];
}
```

返回给 Agent 的视图需要删除 IdentityFile 路径、密码、代理命令正文和其他敏感字段。

### 5.3 RouteHop

```ts
interface RouteHop {
  alias: string;
  hostname: string;
  user?: string;
  port: number;
  depth: number;
}
```

对于当前基准场景：

```text
route[0] = scnet-login
route[1] = scnet-computer
route[2] = scnet-docker
```

### 5.4 ConnectionRecord

```ts
interface ConnectionRecord {
  key: string;
  targetId: TargetId;
  configFingerprint: string;
  controlPath: string;
  state: "cold" | "connecting" | "ready" | "stale" | "closing";
  createdAt?: number;
  lastUsedAt?: number;
  lastCheckedAt?: number;
  failure?: SshError;
}
```

连接键由目标 ID 与有效配置指纹组成。SSH 配置变化后产生新键，旧连接进入 drain/close 流程。

### 5.5 OperationResult

```ts
interface OperationResult<T> {
  ok: boolean;
  requestId: string;
  operation: string;
  target?: string;
  timing: {
    resolveMs: number;
    connectMs: number;
    executeMs: number;
    totalMs: number;
  };
  data?: T;
  error?: OperationError;
  warnings: DiagnosticWarning[];
}
```

## 6. TargetCatalog 与 RouteResolver

### 6.1 TargetCatalog 职责

- 扫描 `~/.ssh/config` 及 Include 文件中的显式 Host 别名。
- 排除 `Host *` 和包含 `*`、`?`、`!` 的模式目标。
- 维护别名索引和配置文件变更版本。
- 不负责决定 HostName、User、Port 等最终值。
- 单独读取兼容性的 `@password` 注释，但绝不把密码写入目标模型。

### 6.2 RouteResolver 职责

对目标执行 `ssh -G -- <target>`，提取：

- hostname
- user
- port
- proxyjump
- proxycommand 是否存在
- identityagent/identityfile 是否配置，仅生成非敏感认证摘要
- host key 相关策略警告

ProxyJump 的每个别名继续递归解析，直到没有下一跳。

必须具备：

- 循环检测。
- 最大路由深度，默认 8。
- 逗号分隔多跳 ProxyJump 支持。
- `user@host:port` 形式解析。
- 解析缓存和配置指纹。
- `ProxyCommand` 只标记为 opaque，不解释或执行其文本进行探测。

### 6.3 为什么不用自建配置解释器

OpenSSH 配置包含顺序优先、Host 模式、Match、Include、token 展开、CanonicalizeHostname 等语义。使用 `ssh -G` 可以保证执行配置与展示配置一致，避免 MCP 认为的目标和 OpenSSH 实际连接目标不同。

## 7. Connection Manager

### 7.1 连接粒度

v3 首版以最终目标为连接池粒度。为 `scnet-docker` 建立的最终 ControlMaster 已经封装完整 ProxyJump 链，后续访问无需重新经过三级认证建链。

共享跳板连接池不进入首版；只有性能基准证明多个最终目标共享跳板时存在明显收益，才单独设计。

### 7.2 生命周期

```text
cold ──ensureReady──> connecting ──success──> ready
                           │                    │
                           └──failure──> stale  │ health failure
                                                ▼
                                              stale

ready ──config changed/idle shutdown──> closing ──> cold
```

### 7.3 ensureReady

`ensureReady(target)` 是所有远程服务的统一前置步骤：

1. 解析目标并计算配置指纹。
2. 查找对应连接记录。
3. ready 且健康检查在 TTL 内时直接复用。
4. ready 但需要检查时执行 `ssh -O check`。
5. cold/stale 时建立最终目标 ControlMaster。
6. 多个并发调用共享同一个连接 Promise。
7. 返回 connection lease 和建链耗时。

### 7.4 ControlMaster 策略

- MCP 管理独立 ControlPath，不复用无法识别所有权的用户 socket。
- runtime/state 目录在首次使用前创建，POSIX 权限为 `0700`。
- ControlPath 使用短目录与哈希，避免 Unix socket 路径长度限制。
- exec、scp 和控制命令必须使用同一个 ControlPath。
- 默认 ControlPersist 建议 30 分钟，可配置但不暴露为工具参数。
- 服务器正常退出时不强制关闭持久 master；下次启动可以检查并接管同一命名规则下的有效连接。
- 配置指纹改变后不再复用旧 master。

### 7.5 恢复策略

允许自动恢复：

- master 建立前的 DNS、TCP 和临时连接失败。
- `ssh -O check` 确认 socket 已失效。
- 尚未提交远程操作时的 stale socket 重建。

禁止自动重放：

- 已收到远程 started 状态后连接中断的命令。
- 无法判断是否已经执行的写操作。
- 后台任务启动请求状态不明时重新启动同一命令。

## 8. OpenSSH Adapter

OpenSSH Adapter 是唯一允许调用本地 `ssh`、`scp` 和系统进程 API 的模块。

### 8.1 安全约束

- 始终使用 argv 数组和 `shell: false`。
- `target` 必须先经过 TargetCatalog 白名单解析。
- target 不能以 `-` 开头，不能包含本地 shell 元字符。
- 不接受 Agent 提供的 `-o`、`-F`、ProxyCommand 或 ControlPath。
- 使用参数终止符保护目标和路径位置。
- 本地路径在 TransferService 中完成允许目录检查。
- 调试日志不得打印密码、askpass 环境、完整代理命令或文件内容。

### 8.2 接口

```ts
interface OpenSshAdapter {
  resolve(target: TargetId): Promise<EffectiveSshConfig>;
  openMaster(target: ResolvedTarget, controlPath: string): Promise<void>;
  checkMaster(target: ResolvedTarget, controlPath: string): Promise<MasterStatus>;
  closeMaster(target: ResolvedTarget, controlPath: string): Promise<void>;
  exec(request: TransportExecRequest): Promise<TransportExecResult>;
  upload(request: TransferRequest): Promise<TransferResult>;
  download(request: TransferRequest): Promise<TransferResult>;
}
```

### 8.3 凭据

凭据通过 CredentialProvider 获取：

1. SSH agent/OpenSSH 自身认证。
2. 系统钥匙串。
3. 兼容现有 `@password` 注释。

密码只进入子进程环境和 askpass，不进入服务结果、异常、审计记录或 MCP 内容。

## 9. ExecService

### 9.1 执行模型

每个 `ssh_exec` 请求创建一个独立、非交互式远程 shell。`cwd` 和 `env` 显式注入到这次调用，不保存到后续调用。

多步操作使用一个多行 command：

```json
{
  "target": "scnet-docker",
  "cwd": "/workspace/app",
  "command": "set -e\nnpm ci\nnpm test"
}
```

不再提供：

- `useSession`
- `showSessionContext`
- `singleConnection`
- `commands` 批处理模式
- `hosts` 跨主机并行模式
- `combineOutput`

### 9.2 远程执行登记

每次请求生成不可预测的 requestId。远程 wrapper 在私有临时目录维护：

- started 标记
- PID/进程组
- completed 标记
- exit code

目标是支持：

- 超时和取消时清理远程进程组。
- 连接中断后查询命令是否开始或完成。
- 区分“确认未执行”和“可能执行过”。

临时元数据设置 TTL，并由后续操作或后台清理任务回收。

### 9.3 退出状态

必须区分：

- 远程命令退出码。
- SSH 传输失败。
- 本地 spawn 失败。
- 超时。
- 客户端取消。
- 执行状态未知。

远程命令非零退出属于正常工具结果，不属于 MCP 协议异常。

### 9.4 输出预算

- 默认 stdout 和 stderr 合计不超过 128 KiB。
- 工具参数只允许降低或在服务器上限内提高预算。
- 超出后返回 head/tail 摘要、原始字节数和 `outputRef`。
- 完整输出存入权限受限的 OutputStore，按 TTL 清理。
- 大量持续输出通过 MCP progress 通知发送有限行摘要，不能无限推送。

## 10. FileService

首版只提供 Agent 编辑代码和配置所需的确定性能力：

- read
- write
- append
- stat

目录创建、移动和删除可以通过 `ssh_exec` 完成，避免将文件工具扩展为远程文件管理器。

### 10.1 读取

返回：

```ts
{
  path: string;
  size: number;
  sha256: string;
  encoding: "utf-8" | "base64";
  content: string;
  truncated: boolean;
}
```

支持 offset/limit，默认受输出预算限制。

### 10.2 写入

默认使用同目录临时文件加原子 rename：

1. 写入临时文件。
2. 设置权限。
3. 可选校验 SHA-256。
4. rename 替换目标。

支持 `expectedSha256` 乐观并发控制。文件在 Agent 读取后被其他进程修改时，拒绝覆盖并返回 `FILE_CHANGED`。

不保留基于正则的隐式 edit 状态。Agent 可以 read 后生成完整内容，再以 `expectedSha256` 写入。

## 11. TransferService

TransferService 负责本地与远程之间的文件或目录传输。

- 复用 Connection Manager 提供的最终目标 master。
- 默认使用 scp；未来替换为 sftp/rsync 不改变 MCP 契约。
- 本地路径必须位于 `allowedLocalRoots`。
- 路径使用 argv 传递，不能经过本地 shell。
- 返回已传输字节、耗时和校验信息。
- 大文件传输支持取消和有限进度通知。
- 传输失败不返回包含密码、私钥路径或完整 SSH 命令行的 stderr。

## 12. TaskService

后台任务通过 `ssh_exec(detach=true)` 创建，`ssh_task` 负责后续管理，避免 exec 和 task 同时存在两套启动逻辑。

### 12.1 TaskRecord

```ts
interface TaskRecord {
  taskId: string;
  requestId: string;
  target: TargetId;
  commandSummary: string;
  remotePid?: number;
  processGroupId?: number;
  logPath: string;
  exitPath: string;
  createdAt: number;
  state: "starting" | "running" | "exited" | "stopped" | "unknown";
}
```

### 12.2 持久化

- TaskStore 使用原子 JSON 文件或其他可替换实现。
- 本地状态文件权限为 `0600`。
- MCP 启动时加载记录并向对应目标查询 PID、进程组和退出文件。
- 远程任务仍在运行时恢复为 running。
- 远程任务已退出时读取退出码和日志尾部。
- 不因为本地记录丢失而随意杀死远程进程。

### 12.3 停止语义

停止操作发送 TERM，等待宽限期，再按策略发送 KILL，并最终验证进程组是否消失。结果必须明确是 stopped、still_running 或 unknown。

## 13. Policy、批准与审计

### 13.1 PolicyGuard

策略在执行前检查：

- 目标是否允许。
- 操作类型是否允许。
- 本地传输路径是否允许。
- 命令是否匹配 deny 规则。
- 文件写入路径是否受保护。

### 13.2 危险操作批准

不能接受由模型自由填写的 `confirmed=true` 作为用户批准。

推荐顺序：

1. 客户端支持 MCP elicitation 时请求真实用户确认。
2. 客户端不支持时返回 `APPROVAL_REQUIRED`，由宿主完成批准流程。
3. 批准结果以短期、绑定 request hash 的 approval token 表示。

### 13.3 审计

默认记录：

- requestId
- target
- operation
- 命令摘要或 hash
- 路径摘要
- 时间和退出状态
- 是否复用连接
- 错误类别

默认不记录：

- 密码和环境变量值
- 私钥内容或完整身份路径
- 文件正文
- 完整 stdout/stderr
- 可能含 token 的完整命令

## 14. MCP 公开契约

v3 暴露五个工具。

### 14.1 ssh_targets

用途：发现、描述和显式诊断目标。

```ts
{
  action: "list" | "describe" | "diagnose";
  target?: string;
  networkProbe?: boolean;
}
```

- `list` 只读本地配置，不连接网络。
- `describe` 返回脱敏后的最终目标和路由摘要。
- `diagnose` 可以执行显式网络探测，并返回失败 hop。
- 普通操作不要求先调用本工具。

### 14.2 ssh_exec

```ts
{
  target: string;
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  detach?: boolean;
  outputLimitBytes?: number;
}
```

### 14.3 ssh_file

```ts
{
  action: "read" | "write" | "append" | "stat";
  target: string;
  path: string;
  content?: string;
  encoding?: "utf-8" | "base64";
  offset?: number;
  limit?: number;
  mode?: string;
  expectedSha256?: string;
}
```

### 14.4 ssh_transfer

```ts
{
  action: "upload" | "download";
  target: string;
  localPath: string;
  remotePath: string;
  recursive?: boolean;
  preserve?: boolean;
  timeoutMs?: number;
}
```

### 14.5 ssh_task

```ts
{
  action: "list" | "status" | "logs" | "stop";
  taskId?: string;
  offset?: number;
  limit?: number;
}
```

后台任务只通过 `ssh_exec(detach=true)` 创建。

### 14.6 MCP Resources

资源用于读取较大的或可分页的数据：

```text
mcp-ssh://targets/{target}
mcp-ssh://outputs/{requestId}/stdout
mcp-ssh://outputs/{requestId}/stderr
mcp-ssh://tasks/{taskId}/log
```

资源内容同样受权限、大小和 TTL 限制。

## 15. 错误模型

### 15.1 ErrorCode

```text
INVALID_ARGUMENT
TARGET_NOT_FOUND
TARGET_NOT_ALLOWED
ROUTE_CYCLE
ROUTE_TOO_DEEP
SSH_CONFIG_INVALID
SSH_DNS_FAILED
SSH_HOP_UNREACHABLE
SSH_AUTH_FAILED
SSH_HOST_KEY_FAILED
SSH_MASTER_FAILED
SSH_CONNECTION_LOST
REMOTE_COMMAND_FAILED
REMOTE_COMMAND_TIMEOUT
REMOTE_COMMAND_CANCELLED
EXECUTION_STATE_UNKNOWN
FILE_NOT_FOUND
FILE_CHANGED
FILE_PERMISSION_DENIED
TRANSFER_FAILED
TASK_NOT_FOUND
TASK_STATE_UNKNOWN
APPROVAL_REQUIRED
LOCAL_SPAWN_FAILED
```

### 15.2 OperationError

```ts
interface OperationError {
  code: ErrorCode;
  message: string;
  phase: "validate" | "resolve" | "connect" | "authenticate" |
         "execute" | "transfer" | "cleanup";
  retryable: boolean;
  mayHaveRun?: boolean;
  hop?: {
    alias: string;
    depth: number;
  };
  hint?: string;
}
```

### 15.3 MCP 错误语义

- 参数错误、权限拒绝和无法执行工具时返回 MCP `isError: true`，同时提供 structuredContent。
- 远程命令正常执行但退出码非零时，返回普通工具结果，`ok=false`，不视为 MCP 协议失败。
- 为旧客户端保留简短 text fallback，但结构化内容是主结果。

## 16. 配置与状态目录

MCP 配置只控制 MCP 行为，不重复保存 SSH 连接信息。

示例：

```json
{
  "connectionPersistMs": 1800000,
  "connectionHealthTtlMs": 10000,
  "defaultTimeoutMs": 120000,
  "maxTimeoutMs": 300000,
  "defaultOutputLimitBytes": 131072,
  "maxOutputLimitBytes": 2097152,
  "allowedLocalRoots": ["/home/haha/mcp-ssh"],
  "allowKnownHostsTargets": false,
  "maxRouteDepth": 8
}
```

目录通过平台适配器选择：

- config：用户配置目录
- state：任务和审计状态
- runtime/cache：ControlPath、临时输出和请求元数据

所有包含敏感元数据的目录在 POSIX 上必须为 `0700`，文件为 `0600`。

## 17. 可观测性

每个请求生成 requestId，并记录分段耗时：

```ts
{
  resolveMs,
  connectionWaitMs,
  connectMs,
  executeMs,
  cleanupMs,
  totalMs,
  connectionReused
}
```

诊断信息重点回答：

- 使用了哪个最终目标。
- 解析到多少跳。
- 是否复用最终 master。
- 失败发生在哪个阶段和 hop。
- 命令是否可能已经执行。

不向 Agent 默认返回详细 `ssh -vvv` 日志。详细日志只写入脱敏的本地诊断记录。

## 18. 三级跳转验收体系

### 18.1 集成拓扑

测试环境必须包含三个 SSH 服务：

```text
test client
    │ only reachable
    ▼
jump1
    │ private network
    ▼
jump2
    │ private network
    ▼
target
```

客户端不能直接访问 jump2 和 target，以确保测试真的经过完整路由。

### 18.2 必须通过的场景

目标解析：

- 正确得到 `[jump1, jump2, target]`。
- 配置 Include 和 ProxyJump 变化后缓存失效。
- 循环 ProxyJump 返回 ROUTE_CYCLE。

连接复用：

- 第一次 `ssh_exec(target, "true")` 自动建立最终 master。
- 后续 exec/file/transfer 均复用同一最终 master。
- 10 个并发冷启动请求只建立一个 master。
- stale socket 自动重建。

失败定位：

- jump1 不可达时 hop=jump1。
- jump2 认证失败时 hop=jump2、phase=authenticate。
- target 命令退出 1 时不能误报 SSH 连接失败。

执行一致性：

- 超时后远程进程组被清理或明确返回清理未知。
- 传输中断后不能自动重复非幂等写操作。
- 连接中断且无法确认执行状态时返回 mayHaveRun=true。

隔离性：

- 两个并发 Agent 在同一 target 使用不同 cwd/env，互不影响。
- MCP 重启后任务可以重新发现。
- 所有结果和日志均不包含测试密码及私钥内容。

### 18.3 性能基线

性能以本机原生 OpenSSH 为基线，不使用固定互联网延迟阈值：

- 冷启动耗时不得高于原生 `ssh target true` 基线的 1.2 倍。
- 热连接 p95 不得高于原生复用 ControlMaster 基线的 1.2 倍。
- 连续 20 次操作只能发生一次最终目标认证建链。
- MCP 额外协议和结构化处理开销目标低于 50 ms。

## 19. 测试分层

### 19.1 单元测试

- ProxyJump 解析。
- route cycle/depth。
- config fingerprint。
- single-flight。
- 状态机转换。
- 错误分类。
- 输出截断。
- 原子文件写入脚本生成。
- 路径、target 和环境变量校验。

### 19.2 Adapter 测试

使用伪 ssh/scp 可执行文件捕获 argv，验证：

- 永远不启用本地 shell。
- 参数终止符和 ControlPath 正确。
- 密码不进入 argv 和返回值。
- 取消和超时行为。

### 19.3 Docker 集成测试

真实运行 OpenSSH 的单跳、双跳、三级目标、认证失败、host key 失败、网络断开和 master 损坏场景。

### 19.4 MCP 契约测试

- 工具 schema。
- structuredContent。
- text fallback。
- isError 语义。
- cancellation/progress。
- resource 分页和 TTL。

## 20. 迁移方案

### 阶段 A：建立基线

- 固化现有 v2 行为测试。
- 新增三级跳转 Docker 集成环境。
- 记录冷、热连接性能和错误表现。

### 阶段 B：引入新内核

- 实现 TargetCatalog、RouteResolver、OpenSSH Adapter 和 Connection Manager。
- 当前 v2 工具改为调用新内核。
- 暂时不改变 MCP 工具名称和 schema。

### 阶段 C：替换执行和状态模型

- ExecService 使用显式 cwd/env。
- 删除内部伪 shell 状态更新。
- 引入 requestId、执行登记、OutputStore 和持久 TaskStore。
- File/Transfer/Task 服务统一通过 Connection Manager。

### 阶段 D：启用 v3 MCP 契约

- 暴露五个 v3 工具和资源。
- v2 工具放入 compatibility adapter。
- 对旧字段返回弃用提示。

### 阶段 E：清理旧实现

- 删除旧 SessionManager 中 cwd/env 状态。
- 删除公开 warmup/closeSession/sessions。
- 删除批处理、跨主机 parallel 和重复任务启动逻辑。
- 删除 MCP handler 中的大型 switch，改为工具注册表。

## 21. 架构决策摘要

### ADR-001：使用 OpenSSH 作为配置解析真相来源

决定：目标有效配置通过 `ssh -G` 获取。  
原因：保证解析行为与最终执行一致。

### ADR-002：执行默认无隐藏状态

决定：cwd/env 每次调用显式传入。  
原因：可预测、可并发、无跨 Agent 污染。

### ADR-003：首版只池化最终目标连接

决定：ControlMaster 按最终目标和配置指纹管理。  
原因：它已经消除重复三级建链成本，复杂度最低。

### ADR-004：远程操作开始后不盲目自动重试

决定：不确定状态返回 mayHaveRun。  
原因：避免重复部署、删除、重启或写入。

### ADR-005：后台任务由 ssh_exec 创建

决定：`detach=true` 是唯一任务启动入口。  
原因：消除两套远程启动和清理实现。

### ADR-006：结构化结果优先

决定：所有工具使用统一 OperationResult 和稳定错误码。  
原因：降低 Agent 对文本错误和工具特例的推理成本。

## 22. 首个实施里程碑

首个里程碑只实现连接核心，不扩充产品功能：

1. 三级跳转 Docker 集成拓扑。
2. `ssh -G` TargetCatalog/RouteResolver。
3. 最终目标 Connection Manager 与 single-flight。
4. exec、scp 共用 master。
5. 分阶段错误和耗时结果。
6. 用现有 v2 工具作为临时适配层验证兼容性。

达到以下条件后才进入文件和任务重构：

- 三级目标可以直接操作，无需显式预热。
- 热连接性能达到原生 OpenSSH 基线。
- 并发冷启动不会创建多个 master。
- 任一跳失败能够给出阶段化诊断。
- 不存在本地 shell 注入和凭据泄漏回归。
