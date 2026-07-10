const SSH_MASTER_DEGRADED_WARNING = Object.freeze({
  code: 'SSH_MASTER_DEGRADED',
  message: 'SSH ControlMaster 已降级并从连接池淘汰，后续操作将自动重建连接。',
});

async function evictDegradedMaster(connections, lease, result, warnings) {
  if (!result?.masterDegraded) return false;
  if (!warnings.some(warning => warning.code === SSH_MASTER_DEGRADED_WARNING.code)) {
    warnings.push({ ...SSH_MASTER_DEGRADED_WARNING });
  }
  try { await connections.invalidate?.(lease); } catch {}
  return true;
}

export { SSH_MASTER_DEGRADED_WARNING, evictDegradedMaster };
