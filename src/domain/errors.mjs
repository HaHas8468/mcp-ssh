// Stable, transport-independent errors returned by the v3 services.
const ERROR_CODES = Object.freeze({
  INVALID_ARGUMENT: 'INVALID_ARGUMENT',
  TARGET_NOT_FOUND: 'TARGET_NOT_FOUND',
  TARGET_NOT_ALLOWED: 'TARGET_NOT_ALLOWED',
  ROUTE_CYCLE: 'ROUTE_CYCLE',
  ROUTE_TOO_DEEP: 'ROUTE_TOO_DEEP',
  SSH_CONFIG_INVALID: 'SSH_CONFIG_INVALID',
  SSH_DNS_FAILED: 'SSH_DNS_FAILED',
  SSH_HOP_UNREACHABLE: 'SSH_HOP_UNREACHABLE',
  SSH_AUTH_FAILED: 'SSH_AUTH_FAILED',
  SSH_HOST_KEY_FAILED: 'SSH_HOST_KEY_FAILED',
  SSH_MASTER_FAILED: 'SSH_MASTER_FAILED',
  SSH_CONNECTION_LOST: 'SSH_CONNECTION_LOST',
  REMOTE_COMMAND_FAILED: 'REMOTE_COMMAND_FAILED',
  REMOTE_COMMAND_TIMEOUT: 'REMOTE_COMMAND_TIMEOUT',
  REMOTE_COMMAND_CANCELLED: 'REMOTE_COMMAND_CANCELLED',
  EXECUTION_STATE_UNKNOWN: 'EXECUTION_STATE_UNKNOWN',
  FILE_NOT_FOUND: 'FILE_NOT_FOUND',
  FILE_CHANGED: 'FILE_CHANGED',
  FILE_PERMISSION_DENIED: 'FILE_PERMISSION_DENIED',
  TRANSFER_FAILED: 'TRANSFER_FAILED',
  TASK_NOT_FOUND: 'TASK_NOT_FOUND',
  TASK_STATE_UNKNOWN: 'TASK_STATE_UNKNOWN',
  APPROVAL_REQUIRED: 'APPROVAL_REQUIRED',
  LOCAL_SPAWN_FAILED: 'LOCAL_SPAWN_FAILED',
});

class OperationFailure extends Error {
  constructor(code, message, options = {}) {
    super(message);
    this.name = 'OperationFailure';
    this.operationError = {
      code,
      message,
      phase: options.phase || 'execute',
      retryable: Boolean(options.retryable),
      ...(options.mayHaveRun === undefined ? {} : { mayHaveRun: Boolean(options.mayHaveRun) }),
      ...(options.hop ? { hop: options.hop } : {}),
      ...(options.hint ? { hint: options.hint } : {}),
    };
    this.isProtocolError = options.isProtocolError !== false;
    this.cause = options.cause;
  }
}

function operationError(error, fallback = {}) {
  if (error instanceof OperationFailure) return error.operationError;
  return {
    code: fallback.code || ERROR_CODES.LOCAL_SPAWN_FAILED,
    message: error instanceof Error ? error.message : String(error),
    phase: fallback.phase || 'execute',
    retryable: Boolean(fallback.retryable),
  };
}

function isProtocolError(error) {
  return !(error instanceof OperationFailure) || error.isProtocolError;
}

export { ERROR_CODES, OperationFailure, operationError, isProtocolError };
