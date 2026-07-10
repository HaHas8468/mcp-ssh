function targetUri(target) { return `mcp-ssh://targets/${encodeURIComponent(target)}`; }

function parseResourceUri(uri) {
  const target = String(uri).match(/^mcp-ssh:\/\/targets\/([^/]+)$/);
  if (target) return { kind: 'target', target: decodeURIComponent(target[1]) };
  const output = String(uri).match(/^mcp-ssh:\/\/outputs\/([^/]+)\/(stdout|stderr)$/);
  if (output) {
    const requestId = decodeURIComponent(output[1]);
    if (!/^[a-f0-9-]{36}$/i.test(requestId)) return null;
    return { kind: 'output', requestId, stream: output[2] };
  }
  const task = String(uri).match(/^mcp-ssh:\/\/tasks\/([^/]+)\/log$/);
  if (task) {
    const taskId = decodeURIComponent(task[1]);
    if (!/^task_[a-f0-9-]{36}$/i.test(taskId)) return null;
    return { kind: 'task-log', taskId };
  }
  return null;
}

export { targetUri, parseResourceUri };
