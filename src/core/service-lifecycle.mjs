class ServiceLifecycle {
  constructor({ adapter, connections } = {}) {
    this.adapter = adapter;
    this.connections = connections;
    this.operations = new Set();
    this.shuttingDown = false;
    this.shutdownPromise = null;
  }

  track(parentSignal) {
    const controller = new AbortController();
    const abort = () => controller.abort(parentSignal?.reason || { code: 'REQUEST_CANCELLED' });
    parentSignal?.addEventListener('abort', abort, { once: true });
    if (parentSignal?.aborted) abort();
    if (this.shuttingDown) controller.abort({ code: 'SERVER_SHUTDOWN' });
    const operation = {
      signal: controller.signal,
      abort: reason => controller.abort(reason),
      done: () => {
        parentSignal?.removeEventListener('abort', abort);
        this.operations.delete(operation);
      },
    };
    this.operations.add(operation);
    return operation;
  }

  resume() {
    this.adapter?.resumeActiveProcesses?.();
    this.connections?.markForRecheck?.();
  }

  shutdown(reason = 'SERVER_SHUTDOWN') {
    if (this.shutdownPromise) return this.shutdownPromise;
    this.shuttingDown = true;
    for (const operation of this.operations) operation.abort({ code: reason });
    this.shutdownPromise = (async () => {
      await this.adapter?.shutdown?.();
      while (this.operations.size > 0) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    })();
    return this.shutdownPromise;
  }
}

export { ServiceLifecycle };
