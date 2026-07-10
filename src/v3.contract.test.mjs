import { describe, expect, it } from 'vitest';
import { getToolDefinitions } from './mcp/tools.mjs';
import { presentResult } from './mcp/presenters.mjs';
import { parseResourceUri } from './mcp/resources.mjs';

describe('v3 MCP contract', () => {
  it('publishes five closed input contracts with an output schema', () => {
    const tools = getToolDefinitions();
    expect(tools).toHaveLength(5);
    for (const tool of tools) {
      expect(tool.inputSchema.additionalProperties).toBe(false);
      expect(tool.outputSchema.required).toEqual(expect.arrayContaining(['ok', 'requestId', 'operation', 'timing', 'data', 'warnings']));
    }
  });

  it('returns structured content and only treats transport/validation failures as MCP errors', () => {
    const remoteExit = presentResult({
      ok: false, requestId: 'r', operation: 'exec', target: 'target', timing: {}, data: { exitCode: 1 }, warnings: [],
      error: { code: 'REMOTE_COMMAND_FAILED', message: 'exit 1', phase: 'execute', retryable: false },
    });
    expect(remoteExit.structuredContent.data.exitCode).toBe(1);
    expect(remoteExit.isError).toBeUndefined();
    const invalid = presentResult({
      ok: false, requestId: 'r', operation: 'exec', timing: {}, data: {}, warnings: [],
      error: { code: 'INVALID_ARGUMENT', message: 'bad', phase: 'validate', retryable: false },
    });
    expect(invalid.isError).toBe(true);
    expect(invalid.structuredContent.error.code).toBe('INVALID_ARGUMENT');
  });

  it('does not decode output resources into local path traversal', () => {
    expect(parseResourceUri('mcp-ssh://outputs/%2e%2e%2fsecret/stdout')).toBeNull();
    expect(parseResourceUri('mcp-ssh://outputs/123e4567-e89b-12d3-a456-426614174000/stdout')).toMatchObject({ kind: 'output', stream: 'stdout' });
  });
});
