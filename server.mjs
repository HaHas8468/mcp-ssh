#!/usr/bin/env node

/**
 * MCP SSH Agent v2.0 — A Model Context Protocol server for SSH operations.
 *
 * Compatibility entrypoint. The implementation lives under src/.
 */

export {
  McpConfig,
  mcpConfig,
  AuditLogger,
  PermissionGuard,
  SSHConfigParser,
  RateLimiter,
} from './src/config.mjs';
export { SessionManager } from './src/session-manager.mjs';
export { TaskManager } from './src/task-manager.mjs';
export { SSHClient } from './src/ssh-client.mjs';
export {
  debugLog,
  detectDangerousCommand,
  shQuote,
  validateFileMode,
} from './src/shared.mjs';
export { main } from './src/mcp-server.mjs';
