#!/usr/bin/env node

/**
 * MCP SSH Agent v3.0 — a small, final-target-first SSH MCP runtime.
 */

export { RuntimeConfig, runtimePaths } from './src/adapters/runtime-config.mjs';
export { CredentialProvider } from './src/adapters/credential-provider.mjs';
export { AuditLogger } from './src/adapters/audit-logger.mjs';
export { OpenSshAdapter } from './src/adapters/openssh-adapter.mjs';
export { TargetCatalog } from './src/core/target-catalog.mjs';
export { RouteResolver } from './src/core/route-resolver.mjs';
export { ConnectionManager } from './src/core/connection-manager.mjs';
export { OutputStore } from './src/core/output-store.mjs';
export { TaskStore } from './src/core/task-store.mjs';
export { ExecService } from './src/services/exec-service.mjs';
export { FileService } from './src/services/file-service.mjs';
export { TransferService } from './src/services/transfer-service.mjs';
export { TaskService } from './src/services/task-service.mjs';
export { ERROR_CODES, OperationFailure } from './src/domain/errors.mjs';
export {
  debugLog,
  shQuote,
  validateFileMode,
} from './src/shared.mjs';
export { main, createServer, createV3Runtime } from './src/mcp-server.mjs';
