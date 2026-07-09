import { homedir } from 'os';
import { join } from 'path';
import { watch } from 'fs';
import { createRequire } from 'module';
import { SSHClient } from './ssh-client.mjs';
import { getToolDefinitions } from './tools.mjs';
import { debugLog } from './shared.mjs';

const require = createRequire(import.meta.url);

// =============================================================================
// Main — MCP server setup with all tools
// =============================================================================
async function main() {
  try {
    debugLog("Initializing SSH client (v2.0)...\n");
    const sshClient = new SSHClient();

    debugLog("Creating MCP server...\n");
    const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
    const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
    const { CallToolRequestSchema, ListToolsRequestSchema, ListResourcesRequestSchema, ReadResourceRequestSchema } = require('@modelcontextprotocol/sdk/types.js');

    const server = new Server(
      { name: "mcp-ssh", version: "2.0.0" },
      { capabilities: { tools: {}, resources: {} } }
    );

    // listChanged: watch SSH config for changes (P1 #36)
    try {
      const configDir = join(homedir(), '.ssh');
      watch(configDir, (eventType, filename) => {
        if (filename && (filename === 'config' || filename === 'known_hosts')) {
          sshClient.configParser.invalidateCache();
          debugLog(`SSH config changed: ${filename}, notifying clients...\n`);
          try {
            server.notification({ method: "notifications/tools/list_changed" });
          } catch {}
        }
      });
    } catch (e) {
      debugLog(`Config watch failed (non-fatal): ${e.message}\n`);
    }

    // P2 #43: MCP Resources — expose host list as resources
    server.setRequestHandler(ListResourcesRequestSchema, async () => {
      const hosts = await sshClient.listKnownHosts();
      return {
        resources: hosts
          .filter(h => h.alias || h.hostname)
          .map(h => ({
            uri: `ssh://hosts/${encodeURIComponent(h.alias || h.hostname)}`,
            name: h.alias || h.hostname,
            description: `SSH host: ${h.hostname}${h.user ? ` (user: ${h.user})` : ''}${h.port ? ` port: ${h.port}` : ''}`,
            mimeType: "application/json",
          })),
      };
    });

    server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const uri = request.params.uri;
      const match = uri.match(/^ssh:\/\/hosts\/(.+)$/);
      if (!match) {
        throw new Error(`Unknown resource URI: ${uri}`);
      }
      const hostAlias = decodeURIComponent(match[1]);
      const info = await sshClient.getHostInfo(hostAlias);
      if (!info) {
        throw new Error(`Host not found: ${hostAlias}`);
      }
      return {
        contents: [{
          uri,
          mimeType: "application/json",
          text: JSON.stringify(info, null, 2),
        }],
      };
    });

    server.setRequestHandler(ListToolsRequestSchema, async () => {
      return { tools: getToolDefinitions() };
    });

    server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
      const { name, arguments: args } = request.params;
      debugLog(`Received callTool request for tool: ${name} (action: ${args?.action || 'n/a'})\n`);

      // MCP Cancellation: extract AbortSignal from extra
      const abortSignal = extra?.signal || null;

      // MCP Progress: extract progressToken and sendNotification
      const progressToken = request.params?._meta?.progressToken || null;
      const sendNotification = extra?.sendNotification || null;
      const onProgress = (progressToken && sendNotification)
        ? (progress, total, message) => {
            sendNotification({
              method: "notifications/progress",
              params: { progressToken, progress, total: total ?? null, message: message ?? undefined },
            }).catch(() => {});
          }
        : null;

      if (!args) {
        throw new Error(`No arguments provided for tool: ${name}`);
      }

      try {
        let result;
        const action = args.action;

        switch (name) {
          // ===================================================================
          // ssh_hosts — list | info | check | sessions | warmup | closeSession
          // ===================================================================
          case "ssh_hosts": {
            if (action === 'list' || !action) {
              const hosts = await sshClient.listKnownHosts();
              result = hosts.map(({ _password, ...host }) => {
                if (_password) host.passwordAuth = true;
                return host;
              });
            } else if (action === 'info') {
              result = await sshClient.getHostInfo(args.hostAlias);
            } else if (action === 'check') {
              result = await sshClient.checkConnectivity(args.hostAlias, { timeout: args.timeout });
            } else if (action === 'inspect') {
              result = await sshClient.inspectRemote(args.hostAlias, {
                processPattern: args.processPattern,
                ports: args.ports,
                maxProcesses: args.maxProcesses,
                timeout: args.timeout,
              });
            } else if (action === 'sessions') {
              result = sshClient.listSessions();
            } else if (action === 'warmup') {
              const startedAt = Date.now();
              const opened = await sshClient.openSession(args.hostAlias, { timeout: args.timeout });
              result = {
                hostAlias: args.hostAlias,
                warmed: Boolean(opened.opened),
                latency: Date.now() - startedAt,
                session: opened,
              };
            } else if (action === 'closeSession') {
              result = await sshClient.closeSession(args.hostAlias);
            } else {
              throw new Error(`Unknown action '${action}' for ssh_hosts. Use: list, info, check, inspect, sessions, warmup, closeSession`);
            }
            break;
          }

          // ===================================================================
          // ssh_exec — single | batch | parallel
          // ===================================================================
          case "ssh_exec": {
            if (args.hosts) {
              // Parallel: multiple hosts
              result = await sshClient.runParallel(args.hosts, { concurrency: args.concurrency || 5 });
            } else if (args.commands) {
              // Batch: multiple commands on one host
              result = await sshClient.runCommandBatch(args.hostAlias, args.commands, {
                mode: args.mode || 'sequential', timeout: args.timeout,
                concurrency: args.concurrency,
                singleConnection: args.singleConnection,
                confirmed: args.confirmed,
                useSession: args.useSession,
                showSessionContext: args.showSessionContext,
                signal: abortSignal,
                onProgress,
              });
            } else if (args.command) {
              // Single command
              result = await sshClient.runRemoteCommand(args.hostAlias, args.command, {
                timeout: args.timeout, useSession: args.useSession,
                combineOutput: args.combineOutput, confirmed: args.confirmed,
                showSessionContext: args.showSessionContext,
                signal: abortSignal, onProgress,
              });
            } else {
              throw new Error('ssh_exec requires one of: command, commands, or hosts');
            }
            break;
          }

          // ===================================================================
          // ssh_file — read | write | edit | append
          // ===================================================================
          case "ssh_file": {
            if (action === 'read') {
              result = await sshClient.readFile(args.hostAlias, args.path, { offset: args.offset, limit: args.limit });
            } else if (action === 'write') {
              result = await sshClient.writeFile(args.hostAlias, args.path, args.content, { mode: args.mode });
            } else if (action === 'edit') {
              result = await sshClient.editFile(args.hostAlias, args.path, args.edits, { createIfMissing: args.createIfMissing });
            } else if (action === 'append') {
              result = await sshClient.appendFile(args.hostAlias, args.path, args.content);
            } else {
              throw new Error(`Unknown action '${action}' for ssh_file. Use: read, write, edit, append`);
            }
            break;
          }

          // ===================================================================
          // ssh_fs — list | stat | mkdir | rm | mv
          // ===================================================================
          case "ssh_fs": {
            if (action === 'list') {
              result = await sshClient.listDir(args.hostAlias, args.path, { detailed: args.detailed });
            } else if (action === 'stat') {
              result = await sshClient.stat(args.hostAlias, args.path);
            } else if (action === 'mkdir') {
              result = await sshClient.mkdir(args.hostAlias, args.path, { parents: args.parents });
            } else if (action === 'rm') {
              result = await sshClient.remove(args.hostAlias, args.path, { recursive: args.recursive, force: args.force });
            } else if (action === 'mv') {
              result = await sshClient.move(args.hostAlias, args.path, args.destPath);
            } else {
              throw new Error(`Unknown action '${action}' for ssh_fs. Use: list, stat, mkdir, rm, mv`);
            }
            break;
          }

          // ===================================================================
          // ssh_transfer — upload | download
          // ===================================================================
          case "ssh_transfer": {
            const opts = { preservePermissions: args.preservePermissions, timeout: args.timeout, signal: abortSignal, onProgress };
            if (action === 'upload') {
              result = args.recursive
                ? await sshClient.uploadDir(args.hostAlias, args.localPath, args.remotePath, opts)
                : await sshClient.uploadFile(args.hostAlias, args.localPath, args.remotePath, opts);
            } else if (action === 'download') {
              result = args.recursive
                ? await sshClient.downloadDir(args.hostAlias, args.remotePath, args.localPath, opts)
                : await sshClient.downloadFile(args.hostAlias, args.remotePath, args.localPath, opts);
            } else {
              throw new Error(`Unknown action '${action}' for ssh_transfer. Use: upload, download`);
            }
            break;
          }

          // ===================================================================
          // ssh_task — start | status | stop | list
          // ===================================================================
          case "ssh_task": {
            if (action === 'start') {
              result = await sshClient.startBackground(args.hostAlias, args.command, { timeout: args.timeout });
            } else if (action === 'status') {
              result = await sshClient.getTaskStatus(args.taskId, {
                logLines: args.logLines,
                grep: args.grep,
                exclude: args.exclude,
                tailBytes: args.tailBytes,
                onlyNew: args.onlyNew,
                maxLogLineLength: args.maxLogLineLength,
                readyPattern: args.readyPattern,
                ports: args.ports,
              });
            } else if (action === 'stop') {
              result = await sshClient.stopTask(args.taskId);
            } else if (action === 'list' || !action) {
              result = await sshClient.listTasks();
            } else {
              throw new Error(`Unknown action '${action}' for ssh_task. Use: start, status, stop, list`);
            }
            break;
          }

          default:
            throw new Error(`Unknown tool: ${name}. Available: ssh_hosts, ssh_exec, ssh_file, ssh_fs, ssh_transfer, ssh_task`);
        }

        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        debugLog(`Error executing tool ${name}: ${error.message}\n`);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              success: false,
              error: error instanceof Error ? error.message : String(error),
              errorType: 'tool_error',
            }, null, 2),
          }],
        };
      }
    });

    // Transport selection: STDIO (default) or SSE (P1 #35)
    const transportType = process.env.MCP_TRANSPORT || 'stdio';
    let transport;

    if (transportType === 'sse') {
      try {
        const { SSEServerTransport } = require('@modelcontextprotocol/sdk/server/sse.js');
        const port = parseInt(process.env.MCP_PORT || '3000', 10);
        transport = new SSEServerTransport(port);
        debugLog(`Starting MCP SSH Agent on SSE port ${port}...\n`);
      } catch (e) {
        debugLog(`SSE transport not available, falling back to STDIO: ${e.message}\n`);
        transport = new StdioServerTransport();
      }
    } else {
      transport = new StdioServerTransport();
    }

    await server.connect(transport);
    debugLog("MCP SSH Agent v2.0 connected and ready!\n");

  } catch (error) {
    debugLog(`Error starting MCP SSH Agent: ${error.message}\n`);
    process.exit(1);
  }
}

export { main };
