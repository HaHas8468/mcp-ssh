const operationOutputSchema = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' }, requestId: { type: 'string' }, operation: { type: 'string' }, target: { type: 'string' },
    timing: { type: 'object', additionalProperties: true }, data: { type: 'object', additionalProperties: true },
    error: { type: 'object', additionalProperties: true }, warnings: { type: 'array', items: { type: 'object', additionalProperties: true } },
  },
  required: ['ok', 'requestId', 'operation', 'timing', 'data', 'warnings'], additionalProperties: false,
};

function getToolDefinitions() {
  return [
    {
      name: 'ssh_targets',
      description: '发现、描述或诊断 ~/.ssh/config 中显式定义的最终 SSH 目标。普通操作无需预热。',
      inputSchema: {
        type: 'object', properties: {
          action: { type: 'string', enum: ['list', 'describe', 'diagnose'], default: 'list' },
          target: { type: 'string' }, networkProbe: { type: 'boolean', default: false },
        }, required: ['action'], additionalProperties: false,
      }, outputSchema: operationOutputSchema,
    },
    {
      name: 'ssh_exec',
      description: '在最终 SSH 目标上运行一个独立的非交互式 shell。cwd 与 env 只对本次调用生效；detach=true 创建可由 ssh_task 管理的后台任务。',
      inputSchema: {
        type: 'object', properties: {
          target: { type: 'string' }, command: { type: 'string' }, cwd: { type: 'string' },
          env: { type: 'object', additionalProperties: { type: 'string' } }, timeoutMs: { type: 'integer', minimum: 1 },
          detach: { type: 'boolean', default: false }, outputLimitBytes: { type: 'integer', minimum: 1 },
        }, required: ['target', 'command'], additionalProperties: false,
      }, outputSchema: operationOutputSchema,
    },
    {
      name: 'ssh_file',
      description: '读取、原子写入、追加或查看远程文件。write 可用 expectedSha256 防止覆盖并发变更。',
      inputSchema: {
        type: 'object', properties: {
          action: { type: 'string', enum: ['read', 'write', 'append', 'stat'] }, target: { type: 'string' }, path: { type: 'string' },
          content: { type: 'string' }, encoding: { type: 'string', enum: ['utf-8', 'base64'] }, offset: { type: 'integer', minimum: 0 },
          limit: { type: 'integer', minimum: 0 }, mode: { type: 'string' }, expectedSha256: { type: 'string' },
        }, required: ['action', 'target', 'path'], additionalProperties: false,
      }, outputSchema: operationOutputSchema,
    },
    {
      name: 'ssh_transfer',
      description: '使用 SCP 在已配置的 SSH 目标与 allowedLocalRoots 内的本地路径之间传输文件或目录。',
      inputSchema: {
        type: 'object', properties: {
          action: { type: 'string', enum: ['upload', 'download'] }, target: { type: 'string' }, localPath: { type: 'string' }, remotePath: { type: 'string' },
          recursive: { type: 'boolean', default: false }, preserve: { type: 'boolean', default: false }, timeoutMs: { type: 'integer', minimum: 1 },
        }, required: ['action', 'target', 'localPath', 'remotePath'], additionalProperties: false,
      }, outputSchema: operationOutputSchema,
    },
    {
      name: 'ssh_task',
      description: '列出、查询、读取日志或停止由 ssh_exec(detach=true) 创建的后台任务。',
      inputSchema: {
        type: 'object', properties: {
          action: { type: 'string', enum: ['list', 'status', 'logs', 'stop'], default: 'list' }, taskId: { type: 'string' },
          offset: { type: 'integer', minimum: 0 }, limit: { type: 'integer', minimum: 1 },
        }, required: ['action'], additionalProperties: false,
      }, outputSchema: operationOutputSchema,
    },
  ];
}

export { getToolDefinitions, operationOutputSchema };
