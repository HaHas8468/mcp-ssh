import { describe, expect, it } from 'vitest';
import {
  buildTaskStatusCommand,
  normalizeTaskStatusOptions,
  parseListeningPorts,
  parseProcessTree,
  summarizeResources,
} from './task-status.mjs';

describe('task-status helpers', () => {
  it('normalizes log filtering options', () => {
    const options = normalizeTaskStatusOptions({
      logLines: 5000,
      tailBytes: 999999999,
      maxLogLineLength: 10,
      grep: 'ready',
      exclude: ['tqdm', 'Namespace'],
      onlyNew: true,
      ports: ['8000', 'bad', 9000],
    });

    expect(options.logLines).toBe(1000);
    expect(options.tailBytes).toBe(2 * 1024 * 1024);
    expect(options.maxLogLineLength).toBe(80);
    expect(options.grep).toEqual(['ready']);
    expect(options.exclude).toEqual(['tqdm', 'Namespace']);
    expect(options.onlyNew).toBe(true);
    expect(options.ports).toEqual([8000, 9000]);
  });

  it('builds status command with log filters and only-new offset', () => {
    const options = normalizeTaskStatusOptions({
      grep: 'ready',
      exclude: 'tqdm',
      onlyNew: true,
      logLines: 25,
    });
    const command = buildTaskStatusCommand(
      {
        taskId: 'task_1',
        remotePid: 123,
        processGroupId: 123,
        logFile: '/tmp/task.log',
        exitFile: '/tmp/task.exit',
        lastLogOffset: 456,
      },
      options,
      {
        processStart: 'PS',
        processEnd: 'PE',
        treeStart: 'TS',
        treeEnd: 'TE',
        portStart: 'PORTS',
        portEnd: 'PORTE',
        exitStart: 'ES',
        exitEnd: 'EE',
        logMetaStart: 'LMS',
        logMetaEnd: 'LME',
        logStart: 'LS',
        logEnd: 'LE',
      }
    );

    expect(command).toContain('__mcp_log_start=456');
    expect(command).toContain('grep -E --');
    expect(command).toContain("'ready'");
    expect(command).toContain('grep -Ev --');
    expect(command).toContain("'tqdm'");
    expect(command).toContain('tail -n 25');
  });

  it('parses process tree and listening ports', () => {
    const tree = parseProcessTree('123|1|123|S|00:01|12.5|3.5|204800|python|python -m vllm\n');
    expect(tree).toEqual([
      {
        pid: 123,
        ppid: 1,
        pgid: 123,
        stat: 'S',
        elapsed: '00:01',
        cpuPercent: 12.5,
        memPercent: 3.5,
        rssKb: 204800,
        command: 'python',
        args: 'python -m vllm',
      },
    ]);
    expect(summarizeResources(tree)).toEqual({ cpuPercent: 12.5, memPercent: 3.5, rssKb: 204800 });

    const ports = parseListeningPorts(
      'LISTEN 0 4096 0.0.0.0:8000 0.0.0.0:* users:(("python",pid=123,fd=42))\n',
      [123],
      [8000]
    );
    expect(ports).toHaveLength(1);
    expect(ports[0].port).toBe(8000);
    expect(ports[0].pids).toEqual([123]);
  });

  it('parses lsof listening ports and applies pid and port filters', () => {
    const ports = parseListeningPorts(
      [
        'sshd         1 root    3u  IPv4 743203833      0t0  TCP *:22 (LISTEN)',
        'code-fc3d 1897 root   10u  IPv4 746074351      0t0  TCP 127.0.0.1:34753 (LISTEN)',
      ].join('\n'),
      [1897],
      [34753]
    );

    expect(ports).toEqual([
      {
        protocol: 'tcp',
        localAddress: '127.0.0.1:34753',
        port: 34753,
        pids: [1897],
        raw: 'code-fc3d 1897 root   10u  IPv4 746074351      0t0  TCP 127.0.0.1:34753 (LISTEN)',
      },
    ]);
  });
});
