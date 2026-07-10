const ORDINARY_TOOL_FAILURES = new Set(['REMOTE_COMMAND_FAILED']);

function presentResult(result) {
  const isError = !result.ok && !ORDINARY_TOOL_FAILURES.has(result.error?.code);
  const text = result.ok
    ? `${result.operation} 完成${result.target ? `：${result.target}` : ''}`
    : `${result.error?.code || 'OPERATION_FAILED'}：${result.error?.message || '操作失败'}`;
  return {
    content: [{ type: 'text', text }],
    structuredContent: result,
    ...(isError ? { isError: true } : {}),
  };
}

export { presentResult, ORDINARY_TOOL_FAILURES };
