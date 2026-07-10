import { ERROR_CODES, OperationFailure } from '../domain/errors.mjs';

function abortReason(signal) {
  return signal?.reason?.code === 'OPERATION_TIMEOUT' ? 'timeout' : 'cancelled';
}

function operationAbortError({ signal, deadline, phase = 'execute', message } = {}) {
  const timedOut = deadline !== undefined && Date.now() >= deadline && !signal?.aborted;
  const reason = timedOut ? 'timeout' : abortReason(signal);
  return new OperationFailure(
    reason === 'timeout' ? ERROR_CODES.REMOTE_COMMAND_TIMEOUT : ERROR_CODES.REMOTE_COMMAND_CANCELLED,
    message || (reason === 'timeout' ? '操作超时。' : '操作已取消。'),
    { phase, retryable: false },
  );
}

function throwIfAborted({ signal, deadline, phase = 'execute', message } = {}) {
  if (signal?.aborted || (deadline !== undefined && Date.now() >= deadline)) {
    throw operationAbortError({ signal, deadline, phase, message });
  }
}

function remainingMs(deadline, fallback = 30_000) {
  if (deadline === undefined || deadline === null) return Math.max(1, fallback);
  return Math.max(1, deadline - Date.now());
}

function waitForAbortable(promise, { signal, deadline, phase = 'connect' } = {}) {
  throwIfAborted({ signal, deadline, phase });
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      callback(value);
    };
    const onAbort = () => finish(reject, operationAbortError({ signal, deadline, phase }));
    signal?.addEventListener('abort', onAbort, { once: true });
    if (deadline !== undefined && deadline !== null) {
      timer = setTimeout(() => finish(reject, operationAbortError({ signal, deadline, phase })), remainingMs(deadline));
    }
    Promise.resolve(promise).then(value => finish(resolve, value), error => finish(reject, error));
    // Close the race between the initial check and listener registration.
    if (signal?.aborted) onAbort();
  });
}

function createDeadline(timeoutMs, startedAt = Date.now()) {
  return startedAt + Math.max(1, Number(timeoutMs) || 1);
}

export { abortReason, createDeadline, operationAbortError, remainingMs, throwIfAborted, waitForAbortable };
