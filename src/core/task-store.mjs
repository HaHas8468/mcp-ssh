class TaskStore {
  constructor({ store } = {}) {
    this.store = store;
  }

  async _all() {
    const state = await this.store.read();
    return state.tasks || {};
  }

  async create(task) {
    await this.store.update(state => {
      state.tasks ||= {};
      state.tasks[task.taskId] = task;
      return state;
    });
    return task;
  }

  async get(taskId) {
    return (await this._all())[taskId] || null;
  }

  async list() {
    return Object.values(await this._all()).sort((a, b) => b.createdAt - a.createdAt);
  }

  async update(taskId, patch) {
    let result = null;
    await this.store.update(state => {
      state.tasks ||= {};
      if (!state.tasks[taskId]) return state;
      result = { ...state.tasks[taskId], ...patch, taskId };
      state.tasks[taskId] = result;
      return state;
    });
    return result;
  }
}

export { TaskStore };
