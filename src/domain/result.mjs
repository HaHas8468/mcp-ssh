import { randomUUID } from 'crypto';
import { operationError } from './errors.mjs';

function createRequestId() {
  return randomUUID();
}

function emptyTiming(startedAt = Date.now()) {
  return {
    resolveMs: 0,
    connectionWaitMs: 0,
    connectMs: 0,
    executeMs: 0,
    cleanupMs: 0,
    totalMs: Math.max(0, Date.now() - startedAt),
    connectionReused: false,
  };
}

function successResult({ requestId = createRequestId(), operation, target, timing, data = {}, warnings = [] }) {
  return { ok: true, requestId, operation, ...(target ? { target } : {}), timing: timing || emptyTiming(), data, warnings };
}

function failureResult({ requestId = createRequestId(), operation, target, timing, data = {}, warnings = [], error }) {
  return {
    ok: false,
    requestId,
    operation,
    ...(target ? { target } : {}),
    timing: timing || emptyTiming(),
    data,
    error: operationError(error),
    warnings,
  };
}

export { createRequestId, emptyTiming, successResult, failureResult };
