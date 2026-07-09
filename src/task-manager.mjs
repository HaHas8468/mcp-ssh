// =============================================================================
// TaskManager — background tasks and parallel execution
// =============================================================================
class TaskManager {
  constructor() {
    this.tasks = new Map();
  }

  generateTaskId() {
    return `task_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  }

  register(hostAlias, remotePid, command, options = {}) {
    const taskId = options.taskId || this.generateTaskId();
    const logFile = options.logFile || `/tmp/mcp-task-${taskId}.log`;
    this.tasks.set(taskId, {
      hostAlias,
      remotePid,
      processGroupId: options.processGroupId || remotePid,
      command,
      startedAt: Date.now(),
      logFile,
      exitFile: options.exitFile || `/tmp/mcp-task-${taskId}.exit`,
      lastLogOffset: 0,
      lastExitCode: null,
    });
    return taskId;
  }

  get(taskId) {
    return this.tasks.get(taskId) || null;
  }

  remove(taskId) {
    this.tasks.delete(taskId);
  }

  entries() {
    return Array.from(this.tasks.entries());
  }

  list() {
    return Array.from(this.tasks.entries()).map(([id, t]) => ({
      taskId: id,
      hostAlias: t.hostAlias,
      command: t.command,
      startedAt: new Date(t.startedAt).toISOString(),
      remotePid: t.remotePid,
      processGroupId: t.processGroupId || t.remotePid,
      exitFile: t.exitFile,
    }));
  }
}

export { TaskManager };
