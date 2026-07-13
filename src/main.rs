use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use directories::BaseDirs;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::BTreeMap,
    env,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    time::timeout,
};
use uuid::Uuid;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Deserialize)]
#[serde(default)]
struct Config {
    connection_persist_ms: u64,
    default_timeout_ms: u64,
    max_timeout_ms: u64,
    default_output_limit_bytes: usize,
    max_output_limit_bytes: usize,
    allowed_local_roots: Vec<PathBuf>,
    output_ttl_ms: u64,
    strict_host_key_checking: String,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            connection_persist_ms: 1_800_000,
            default_timeout_ms: 120_000,
            max_timeout_ms: 300_000,
            default_output_limit_bytes: 131_072,
            max_output_limit_bytes: 2_097_152,
            allowed_local_roots: vec![env::current_dir().unwrap_or_else(|_| PathBuf::from("."))],
            output_ttl_ms: 86_400_000,
            strict_host_key_checking: "accept-new".into(),
        }
    }
}

#[allow(dead_code)]
#[derive(Clone)]
struct Paths {
    root: PathBuf,
    config: PathBuf,
    policy: PathBuf,
    old_tasks: PathBuf,
    old_outputs: PathBuf,
    tasks: PathBuf,
    outputs: PathBuf,
    audit: PathBuf,
}
impl Paths {
    fn from_home(home: Option<PathBuf>) -> Self {
        let home = home
            .or_else(|| BaseDirs::new().map(|d| d.home_dir().to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        let root = home.join(".mcp-ssh");
        Self {
            config: root.join("config.json"),
            policy: root.join("permissions.json"),
            old_tasks: root.join("state/tasks.json"),
            old_outputs: root.join("runtime/outputs"),
            tasks: root.join("state/v4/tasks.json"),
            outputs: root.join("runtime/v4/outputs"),
            audit: root.join("state/audit.log"),
            root,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Task {
    #[serde(rename = "taskId")]
    task_id: String,
    #[serde(rename = "requestId")]
    request_id: String,
    target: String,
    #[serde(rename = "commandSummary")]
    command_summary: String,
    #[serde(rename = "remotePid")]
    remote_pid: i64,
    #[serde(rename = "processGroupId")]
    process_group_id: i64,
    #[serde(rename = "logPath")]
    log_path: String,
    #[serde(rename = "exitPath")]
    exit_path: String,
    #[serde(rename = "createdAt")]
    created_at: i64,
    state: String,
    #[serde(rename = "exitCode", skip_serializing_if = "Option::is_none")]
    exit_code: Option<i64>,
}

struct App {
    paths: Paths,
    config: Config,
}
impl App {
    async fn new(home: Option<PathBuf>) -> Self {
        let paths = Paths::from_home(home);
        let config = fs::read_to_string(&paths.config)
            .await
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { paths, config }
    }
    async fn run(
        &self,
        bin: &str,
        args: &[String],
        input: Option<Vec<u8>>,
        timeout_ms: u64,
    ) -> Result<(i32, String, String)> {
        let mut c = Command::new(bin);
        c.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = c.spawn().with_context(|| format!("无法启动 {bin}"))?;
        if let Some(data) = input {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(&data).await?;
            }
        }
        let output = timeout(Duration::from_millis(timeout_ms), child.wait_with_output())
            .await
            .map_err(|_| anyhow!("REMOTE_COMMAND_TIMEOUT"))??;
        Ok((
            output.status.code().unwrap_or(255),
            String::from_utf8_lossy(&output.stdout).into(),
            String::from_utf8_lossy(&output.stderr).into(),
        ))
    }
    fn timeout(&self, args: &Map<String, Value>) -> u64 {
        args.get("timeoutMs")
            .and_then(Value::as_u64)
            .unwrap_or(self.config.default_timeout_ms)
            .clamp(1, self.config.max_timeout_ms)
    }
    async fn ssh_g(&self, target: &str) -> Result<BTreeMap<String, String>> {
        let (code, out, err) = self
            .run(
                "ssh",
                &["-G".into(), "--".into(), target.into()],
                None,
                15_000,
            )
            .await?;
        if code != 0 {
            return Err(anyhow!(sanitize(&err)));
        }
        let mut r = BTreeMap::new();
        for l in out.lines() {
            let mut p = l.splitn(2, ' ');
            if let (Some(k), Some(v)) = (p.next(), p.next()) {
                r.insert(k.into(), v.into());
            }
        }
        Ok(r)
    }
    async fn targets(&self, args: &Map<String, Value>) -> Result<Value> {
        let action = args.get("action").and_then(Value::as_str).unwrap_or("list");
        let target = args.get("target").and_then(Value::as_str);
        if action == "list" {
            let file = fs::read_to_string(BaseDirs::new().unwrap().home_dir().join(".ssh/config"))
                .await
                .unwrap_or_default();
            let re = Regex::new(r"(?i)^\s*Host\s+(.+)$").unwrap();
            let ids: Vec<Value> = file
                .lines()
                .filter_map(|x| re.captures(x))
                .flat_map(|c| {
                    c[1].split_whitespace()
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .filter(|x| !x.contains('*') && !x.contains('!'))
                .map(|id| json!({"id":id}))
                .collect();
            return Ok(json!({"targets":ids}));
        }
        let t = target.ok_or_else(|| anyhow!("target 为必填项"))?;
        let d = self.ssh_g(t).await?;
        if action == "diagnose" {
            return Ok(json!({"target":t,"resolved":d,"networkProbe":false}));
        }
        Ok(json!({"target":t,"resolved":d}))
    }
    #[allow(clippy::regex_creation_in_loops)]
    async fn exec(&self, args: &Map<String, Value>) -> Result<Value> {
        let target = req_str(args, "target")?;
        let command = req_str(args, "command")?;
        if command.trim().is_empty() {
            return Err(anyhow!("command 必须是非空字符串"));
        }
        let id = Uuid::new_v4().to_string();
        let cwd = args.get("cwd").and_then(Value::as_str);
        if cwd.is_some_and(|p| !p.starts_with('/')) {
            return Err(anyhow!("cwd 必须是绝对远程路径"));
        }
        let danger = Regex::new(r"(?i)(rm\s+-[rf].*[/~]|mkfs|shutdown|reboot)").unwrap();
        if danger.is_match(command) {
            return Err(anyhow!("APPROVAL_REQUIRED: 危险操作需要客户端确认"));
        }
        if args.get("detach").and_then(Value::as_bool).unwrap_or(false) {
            return self
                .detach(
                    target,
                    command,
                    cwd,
                    args.get("env").and_then(Value::as_object),
                )
                .await;
        }
        let mut script = format!(
            "set +e\nprintf '%s\\n' {}\n",
            shell(&format!("__MCP_SSH_STARTED_{id}"))
        );
        if let Some(p) = cwd {
            script.push_str(&format!("cd -- {} || exit 125\n", shell(p)));
        }
        if let Some(envs) = args.get("env").and_then(Value::as_object) {
            for (k, v) in envs {
                if !Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap().is_match(k) || !v.is_string() {
                    return Err(anyhow!("无效环境变量"));
                }
                script.push_str(&format!("export {}={}\n", k, shell(v.as_str().unwrap())));
            }
        }
        script.push_str(&format!(
            "(\n{}\n)\n__mcp_rc=$?\nprintf '%s%s\\n' {} \"$__mcp_rc\"\nexit \"$__mcp_rc\"",
            command,
            shell(&format!("__MCP_SSH_EXIT_{id}="))
        ));
        let (code, stdout, stderr) = self
            .run(
                "ssh",
                &[
                    "-o".into(),
                    format!(
                        "StrictHostKeyChecking={}",
                        self.config.strict_host_key_checking
                    ),
                    "--".into(),
                    target.into(),
                    script,
                ],
                None,
                self.timeout(args),
            )
            .await?;
        let (clean, started, exit) = markers(&stdout, &id);
        let output = self
            .output(
                &id,
                &clean,
                &stderr,
                args.get("outputLimitBytes")
                    .and_then(Value::as_u64)
                    .unwrap_or(self.config.default_output_limit_bytes as u64)
                    as usize,
            )
            .await?;
        let ec = exit.unwrap_or(code as i64);
        if code == 255 && started && exit.is_none() {
            return Err(anyhow!("EXECUTION_STATE_UNKNOWN"));
        }
        Ok(json!({"exitCode":ec,"output":output,"remoteFailed":ec!=0}))
    }
    async fn output(&self, id: &str, stdout: &str, stderr: &str, limit: usize) -> Result<Value> {
        let limit = limit.clamp(1, self.config.max_output_limit_bytes);
        let a = stdout.as_bytes();
        let b = stderr.as_bytes();
        let total = a.len() + b.len();
        let al = if total <= limit {
            a.len()
        } else {
            limit * a.len() / total.max(1)
        };
        let bl = limit - al;
        let ao = self.store_stream(id, "stdout", a, al).await?;
        let bo = self.store_stream(id, "stderr", b, bl).await?;
        Ok(json!({"stdout":ao,"stderr":bo,"totalSize":total,"truncated":a.len()>al||b.len()>bl}))
    }
    async fn store_stream(&self, id: &str, name: &str, data: &[u8], limit: usize) -> Result<Value> {
        if data.len() <= limit {
            return Ok(
                json!({"content":String::from_utf8_lossy(data),"size":data.len(),"truncated":false}),
            );
        }
        let d = self.paths.outputs.join(id);
        fs::create_dir_all(&d).await?;
        fs::write(d.join(name), data).await?;
        let h = limit.div_ceil(2);
        let t = limit / 2;
        Ok(
            json!({"head":String::from_utf8_lossy(&data[..h.min(data.len())]),"tail":String::from_utf8_lossy(&data[data.len()-t.min(data.len())..]),"size":data.len(),"truncated":true,"outputRef":format!("mcp-ssh://outputs/{id}/{name}")}),
        )
    }
    async fn resource(&self, uri: &str) -> Result<Value> {
        if let Some(t) = uri.strip_prefix("mcp-ssh://targets/") {
            return Ok(
                json!({"mimeType":"application/json","text":serde_json::to_string_pretty(&self.ssh_g(t).await?)?}),
            );
        }
        let re = Regex::new(r"^mcp-ssh://outputs/([a-fA-F0-9-]{36})/(stdout|stderr)$").unwrap();
        if let Some(c) = re.captures(uri) {
            let bytes = fs::read(self.paths.outputs.join(&c[1]).join(&c[2])).await?;
            return Ok(json!({"mimeType":"text/plain","text":String::from_utf8_lossy(&bytes)}));
        }
        if let Some(id) = uri
            .strip_prefix("mcp-ssh://tasks/")
            .and_then(|x| x.strip_suffix("/log"))
        {
            let mut a = Map::new();
            a.insert("action".into(), json!("logs"));
            a.insert("taskId".into(), json!(id));
            return Ok(json!({"mimeType":"text/plain","text":self.tasks(&a).await?["content"]}));
        }
        Err(anyhow!("未知资源"))
    }
    async fn ssh(&self, target: &str, script: String, limit: u64) -> Result<(i32, String, String)> {
        self.run(
            "ssh",
            &[
                "-o".into(),
                format!(
                    "StrictHostKeyChecking={}",
                    self.config.strict_host_key_checking
                ),
                "--".into(),
                target.into(),
                script,
            ],
            None,
            limit,
        )
        .await
    }
    async fn file(&self, args: &Map<String, Value>) -> Result<Value> {
        let action = req_str(args, "action")?;
        let target = req_str(args, "target")?;
        let path = req_str(args, "path")?;
        if !path.starts_with('/') {
            return Err(anyhow!("path 必须是绝对远程路径"));
        }
        let to = self.timeout(args);
        match action {
            "read" => {
                let off = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
                let lim = args
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(131072)
                    .min(2_097_152);
                let q = shell(path);
                let script=format!("set -e; n=$(wc -c < {q}); dd if={q} bs=1 skip={off} count={lim} 2>/dev/null | base64 | tr -d '\\n'; printf '\\n__MCP_SIZE=%s' \"$n\"");
                let (c, o, e) = self.ssh(target, script, to).await?;
                if c != 0 {
                    return Err(anyhow!(sanitize(&e)));
                }
                let (body, size) = o.rsplit_once("\n__MCP_SIZE=").unwrap_or(("", "0"));
                let bytes = BASE64.decode(body).unwrap_or_default();
                let total_size = size.parse::<u64>().unwrap_or(0);
                let truncated = off + (bytes.len() as u64) < total_size;
                Ok(
                    json!({"path":path,"encoding":"base64","content":BASE64.encode(&bytes),"offset":off,"size":total_size,"truncated":truncated}),
                )
            }
            "stat" => {
                let q = shell(path);
                let (c, o, e) = self
                    .ssh(
                        target,
                        format!("if [ -e {q} ]; then stat -c '%s|%a' {q}; else exit 44; fi"),
                        to,
                    )
                    .await?;
                if c == 44 {
                    return Err(anyhow!("FILE_NOT_FOUND"));
                }
                if c != 0 {
                    return Err(anyhow!(sanitize(&e)));
                }
                let (mut size, mut mode) = (0u64, String::new());
                if let Some((a, b)) = o.trim().split_once('|') {
                    size = a.parse().unwrap_or(0);
                    mode = b.into();
                }
                Ok(json!({"path":path,"size":size,"mode":mode}))
            }
            "write" | "append" => {
                let enc = args
                    .get("encoding")
                    .and_then(Value::as_str)
                    .unwrap_or("utf-8");
                let content = req_str(args, "content")?;
                let bytes = if enc == "base64" {
                    BASE64.decode(content).context("content 不是有效 base64")?
                } else if enc == "utf-8" {
                    content.as_bytes().to_vec()
                } else {
                    return Err(anyhow!("encoding 无效"));
                };
                let q = shell(path);
                let data = BASE64.encode(&bytes);
                let expected = args.get("expectedSha256").and_then(Value::as_str);
                let pre = if let Some(hash) = expected {
                    format!("[ -e {q} ] || exit 45; test \"$(sha256sum {q} | awk '{{print $1}}')\" = {} || exit 46;",shell(hash))
                } else {
                    String::new()
                };
                let script = if action == "append" {
                    format!(
                        "set -e; {pre} printf %s {} | base64 -d >> {q}",
                        shell(&data)
                    )
                } else {
                    format!("set -e; {pre} d=$(dirname {q}); b=$(basename {q}); t=$d/.$b.mcp-ssh-$$; (umask 077; printf %s {} | base64 -d > \"$t\"); mv -f \"$t\" {q}",shell(&data))
                };
                let (c, _o, e) = self.ssh(target, script, to).await?;
                if c == 45 {
                    return Err(anyhow!("FILE_NOT_FOUND"));
                }
                if c == 46 {
                    return Err(anyhow!("FILE_CHANGED"));
                }
                if c != 0 {
                    return Err(anyhow!(sanitize(&e)));
                }
                Ok(json!({"path":path,"written":bytes.len()}))
            }
            _ => Err(anyhow!("不支持的 file action")),
        }
    }
    async fn transfer(&self, args: &Map<String, Value>) -> Result<Value> {
        let action = req_str(args, "action")?;
        let target = req_str(args, "target")?;
        let local = PathBuf::from(req_str(args, "localPath")?);
        let remote = req_str(args, "remotePath")?;
        let allowed = self
            .config
            .allowed_local_roots
            .iter()
            .any(|r| local.starts_with(r));
        if !allowed {
            return Err(anyhow!(
                "TARGET_NOT_ALLOWED: localPath 不在 allowedLocalRoots"
            ));
        }
        let mut a = vec![
            "-o".into(),
            format!(
                "StrictHostKeyChecking={}",
                self.config.strict_host_key_checking
            ),
        ];
        if args
            .get("recursive")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            a.push("-r".into())
        }
        if args
            .get("preserve")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            a.push("-p".into())
        }
        a.push("--".into());
        let r = format!("{target}:{remote}");
        if action == "upload" {
            a.push(local.to_string_lossy().into());
            a.push(r)
        } else if action == "download" {
            a.push(r);
            a.push(local.to_string_lossy().into())
        } else {
            return Err(anyhow!("不支持的 transfer action"));
        }
        let (c, _o, e) = self.run("scp", &a, None, self.timeout(args)).await?;
        if c != 0 {
            return Err(anyhow!(sanitize(&e)));
        }
        Ok(json!({"action":action,"localPath":local,"remotePath":remote}))
    }
    async fn tasks(&self, args: &Map<String, Value>) -> Result<Value> {
        let action = args.get("action").and_then(Value::as_str).unwrap_or("list");
        let mut all = self.load_tasks().await?;
        if action == "list" {
            return Ok(json!({"tasks":all.values().collect::<Vec<_>>() }));
        }
        let id = req_str(args, "taskId")?;
        let task = all.get_mut(id).ok_or_else(|| anyhow!("TASK_NOT_FOUND"))?;
        let to = self.config.default_timeout_ms;
        match action {
            "status" => {
                let script=format!("if kill -0 -- -{} 2>/dev/null; then echo running; elif [ -r {} ]; then cat {}; else echo unknown; fi",task.process_group_id,shell(&task.exit_path),shell(&task.exit_path));
                let (c, o, _) = self.ssh(&task.target, script, to).await?;
                if c != 0 {
                    return Err(anyhow!("TASK_STATE_UNKNOWN"));
                }
                let v = o.trim();
                if v == "running" {
                    task.state = "running".into()
                } else if let Ok(n) = v.parse() {
                    task.state = "exited".into();
                    task.exit_code = Some(n)
                } else {
                    task.state = "unknown".into()
                }
                let updated = task.clone();
                self.save_tasks(&all).await?;
                Ok(json!({"task":updated}))
            }
            "logs" => {
                let off = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
                let lim = args
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(131072)
                    .min(2_097_152);
                let q = shell(&task.log_path);
                let script=format!("set +e; n=$(wc -c < {q} 2>/dev/null || echo 0); dd if={q} bs=1 skip={off} count={lim} 2>/dev/null | base64 | tr -d '\\n'; printf '\\n__MCP_SIZE=%s' \"$n\"");
                let (_, o, _) = self.ssh(&task.target, script, to).await?;
                let (body, n) = o.rsplit_once("\n__MCP_SIZE=").unwrap_or(("", "0"));
                let bytes = BASE64.decode(body).unwrap_or_default();
                let size = n.parse::<u64>().unwrap_or(0);
                let truncated = off + (bytes.len() as u64) < size;
                Ok(
                    json!({"taskId":id,"offset":off,"size":size,"content":String::from_utf8_lossy(&bytes),"truncated":truncated,"logRef":format!("mcp-ssh://tasks/{id}/log")}),
                )
            }
            "stop" => {
                let script=format!("kill -TERM -- -{} 2>/dev/null; sleep 1; kill -0 -- -{} 2>/dev/null && kill -KILL -- -{} 2>/dev/null; ! kill -0 -- -{} 2>/dev/null",task.process_group_id,task.process_group_id,task.process_group_id,task.process_group_id);
                let (c, _, _) = self.ssh(&task.target, script, to).await?;
                task.state = if c == 0 {
                    "stopped".into()
                } else {
                    "still_running".into()
                };
                let updated = task.clone();
                self.save_tasks(&all).await?;
                Ok(json!({"task":updated}))
            }
            _ => Err(anyhow!("不支持的 task action")),
        }
    }
    #[allow(clippy::regex_creation_in_loops)]
    async fn detach(
        &self,
        target: &str,
        command: &str,
        cwd: Option<&str>,
        envs: Option<&Map<String, Value>>,
    ) -> Result<Value> {
        let task_id = format!("task_{}", Uuid::new_v4());
        let root = "${HOME}/.mcp-ssh/tasks";
        let log = format!("{root}/{task_id}.log");
        let exit = format!("{root}/{task_id}.exit");
        let mut setup = format!("set -eu; umask 077; mkdir -p {root}; ");
        if let Some(c) = cwd {
            setup.push_str(&format!("cd -- {}; ", shell(c)));
        }
        if let Some(e) = envs {
            for (k, v) in e {
                if !Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap().is_match(k) || !v.is_string() {
                    return Err(anyhow!("无效环境变量"));
                }
                setup.push_str(&format!("export {k}={}; ", shell(v.as_str().unwrap())));
            }
        }
        let child = format!("({command}); rc=$?; printf '%s\\n' \"$rc\" > {exit}");
        let script=format!("{setup} (setsid \"${{SHELL:-/bin/sh}}\" -c {} > {log} 2>&1 < /dev/null & echo $! > {root}/{task_id}.pid) & sleep 0.05; p=$(cat {root}/{task_id}.pid); printf '%s|%s|%s\\n' \"$p\" \"$HOME/.mcp-ssh/tasks/{task_id}.log\" \"$HOME/.mcp-ssh/tasks/{task_id}.exit\"",shell(&child));
        let (c, o, e) = self
            .ssh(target, script, self.config.default_timeout_ms)
            .await?;
        if c != 0 {
            return Err(anyhow!(sanitize(&e)));
        }
        let parts: Vec<_> = o.trim().split('|').collect();
        let pid = parts
            .first()
            .ok_or_else(|| anyhow!("无法确认后台任务 pid"))?
            .parse::<i64>()
            .context("无法确认后台任务 pid")?;
        let task = Task {
            task_id: task_id.clone(),
            request_id: Uuid::new_v4().to_string(),
            target: target.into(),
            command_summary: command.chars().take(200).collect(),
            remote_pid: pid,
            process_group_id: pid,
            log_path: parts.get(1).unwrap_or(&"").to_string(),
            exit_path: parts.get(2).unwrap_or(&"").to_string(),
            created_at: chrono_like_now().parse().unwrap_or(0),
            state: "running".into(),
            exit_code: None,
        };
        let mut all = self.load_tasks().await?;
        all.insert(task_id.clone(), task);
        self.save_tasks(&all).await?;
        Ok(
            json!({"detached":true,"taskId":task_id,"remotePid":pid,"processGroupId":pid,"logRef":format!("mcp-ssh://tasks/{task_id}/log")}),
        )
    }
    async fn load_tasks(&self) -> Result<BTreeMap<String, Task>> {
        let raw = fs::read_to_string(&self.paths.tasks)
            .await
            .unwrap_or_else(|_| "{\"tasks\":{}}".into());
        Ok(serde_json::from_str::<Value>(&raw)?
            .get("tasks")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default())
    }
    async fn save_tasks(&self, t: &BTreeMap<String, Task>) -> Result<()> {
        fs::create_dir_all(self.paths.tasks.parent().unwrap()).await?;
        let tmp = self.paths.tasks.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&json!({"tasks":t}))?).await?;
        fs::rename(tmp, &self.paths.tasks).await?;
        Ok(())
    }
}

fn req_str<'a>(a: &'a Map<String, Value>, k: &str) -> Result<&'a str> {
    a.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("{k} 为必填项"))
}
fn shell(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
fn sanitize(s: &str) -> String {
    Regex::new(r"(?i)(password|passphrase)\s*[:=].*")
        .unwrap()
        .replace_all(s, "$1: [REDACTED]")
        .into()
}
fn markers(s: &str, id: &str) -> (String, bool, Option<i64>) {
    let start_marker = format!("__MCP_SSH_STARTED_{id}");
    let exit_re = Regex::new(&format!(r"__MCP_SSH_EXIT_{}=(-?\d+)", regex::escape(id))).unwrap();
    let started = s.contains(&start_marker);
    let exit = exit_re
        .captures(s)
        .and_then(|captures| captures.get(1))
        .and_then(|value| value.as_str().parse().ok());
    let without_start = s.replace(&start_marker, "");
    let cleaned = exit_re.replace_all(&without_start, "");
    (cleaned.trim_matches('\n').to_string(), started, exit)
}

fn schemas() -> Value {
    let output = json!({"type":"object","properties":{"ok":{"type":"boolean"},"requestId":{"type":"string"},"operation":{"type":"string"},"target":{"type":"string"},"timing":{"type":"object","additionalProperties":true},"data":{"type":"object","additionalProperties":true},"error":{"type":"object","additionalProperties":true},"warnings":{"type":"array","items":{"type":"object","additionalProperties":true}}},"required":["ok","requestId","operation","timing","data","warnings"],"additionalProperties":false});
    let tool = |name, desc, input| json!({"name":name,"description":desc,"inputSchema":input,"outputSchema":output});
    json!([
        tool(
            "ssh_targets",
            "发现、描述或诊断 ~/.ssh/config 中显式定义的最终 SSH 目标。",
            json!({"type":"object","properties":{"action":{"type":"string","enum":["list","describe","diagnose"]},"target":{"type":"string"},"networkProbe":{"type":"boolean"}},"required":["action"],"additionalProperties":false})
        ),
        tool(
            "ssh_exec",
            "在最终 SSH 目标上运行独立非交互式 shell。",
            json!({"type":"object","properties":{"target":{"type":"string"},"command":{"type":"string"},"cwd":{"type":"string"},"env":{"type":"object","additionalProperties":{"type":"string"}},"timeoutMs":{"type":"integer","minimum":1},"detach":{"type":"boolean"},"outputLimitBytes":{"type":"integer","minimum":1}},"required":["target","command"],"additionalProperties":false})
        ),
        tool(
            "ssh_file",
            "读取、原子写入、追加或查看远程文件。",
            json!({"type":"object","properties":{"action":{"type":"string","enum":["read","write","append","stat"]},"target":{"type":"string"},"path":{"type":"string"}},"required":["action","target","path"],"additionalProperties":false})
        ),
        tool(
            "ssh_transfer",
            "使用 SCP 传输文件或目录。",
            json!({"type":"object","properties":{"action":{"type":"string","enum":["upload","download"]},"target":{"type":"string"},"localPath":{"type":"string"},"remotePath":{"type":"string"}},"required":["action","target","localPath","remotePath"],"additionalProperties":false})
        ),
        tool(
            "ssh_task",
            "管理由 ssh_exec 创建的后台任务。",
            json!({"type":"object","properties":{"action":{"type":"string","enum":["list","status","logs","stop"]},"taskId":{"type":"string"}},"required":["action"],"additionalProperties":false})
        )
    ])
}

async fn migrate(paths: &Paths) -> Result<()> {
    let marker = paths.root.join("state/v4/migration.json");
    if marker.exists() {
        return Ok(());
    }
    let raw = fs::read_to_string(&paths.old_tasks)
        .await
        .unwrap_or_else(|_| "{\"tasks\":{}}".into());
    let _: Value = serde_json::from_str(&raw).context("旧 tasks.json 无效")?;
    fs::create_dir_all(paths.tasks.parent().unwrap()).await?;
    fs::write(&paths.tasks, raw).await?;
    if paths.old_outputs.exists() {
        copy_dir(&paths.old_outputs, &paths.outputs).await?;
    }
    fs::write(
        marker,
        json!({"sourceVersion":"3","migratedAt":chrono_like_now()}).to_string(),
    )
    .await?;
    Ok(())
}
async fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).await?;
    let mut rd = fs::read_dir(src).await?;
    while let Some(e) = rd.next_entry().await? {
        let to = dst.join(e.file_name());
        if e.file_type().await?.is_dir() {
            Box::pin(copy_dir(&e.path(), &to)).await?
        } else {
            fs::copy(e.path(), to).await?;
        }
    }
    Ok(())
}
fn chrono_like_now() -> String {
    format!(
        "{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    )
}

fn result(id: Value, value: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":value})
}
fn error(id: Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":msg}})
}
async fn serve(app: App) -> Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    while let Some(line) = lines.next_line().await? {
        let r: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(id) = r.get("id").cloned() else {
            continue;
        };
        let method = r.get("method").and_then(Value::as_str).unwrap_or("");
        let p = r.get("params").cloned().unwrap_or_else(|| json!({}));
        let answer = match method {
            "initialize" => result(
                id,
                json!({"protocolVersion":"2025-03-26","capabilities":{"tools":{},"resources":{}},"serverInfo":{"name":"mcp-ssh","version":VERSION}}),
            ),
            "tools/list" => result(id, json!({"tools":schemas()})),
            "resources/list" => result(id, json!({"resources":[]})),
            "resources/read" => match app
                .resource(p.get("uri").and_then(Value::as_str).unwrap_or(""))
                .await
            {
                Ok(v) => result(
                    id,
                    json!({"contents":[{"uri":p["uri"],"mimeType":v["mimeType"],"text":v["text"]}]}),
                ),
                Err(e) => error(id, -32000, &e.to_string()),
            },
            "tools/call" => {
                let name = p.get("name").and_then(Value::as_str).unwrap_or("");
                let a = p
                    .get("arguments")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                let op = match name {
                    "ssh_targets" => app.targets(&a).await,
                    "ssh_exec" => app.exec(&a).await,
                    "ssh_file" => app.file(&a).await,
                    "ssh_transfer" => app.transfer(&a).await,
                    "ssh_task" => app.tasks(&a).await,
                    _ => Err(anyhow!("未知工具 {name}")),
                };
                match op {
                    Ok(data) => {
                        let failed = data
                            .get("remoteFailed")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let content = json!({"ok":!failed,"requestId":Uuid::new_v4().to_string(),"operation":name.trim_start_matches("ssh_"),"timing":{"resolveMs":0,"connectionWaitMs":0,"connectMs":0,"executeMs":0,"cleanupMs":0,"totalMs":0,"connectionReused":false},"data":data,"warnings":[]});
                        result(
                            id,
                            json!({"content":[{"type":"text","text":content.to_string()}],"structuredContent":content}),
                        )
                    }
                    Err(e) => {
                        let message = e.to_string();
                        let code = if message.contains("APPROVAL_REQUIRED") {
                            "APPROVAL_REQUIRED"
                        } else if message.contains("TASK_NOT_FOUND") {
                            "TASK_NOT_FOUND"
                        } else if message.contains("FILE_NOT_FOUND") {
                            "FILE_NOT_FOUND"
                        } else if message.contains("FILE_CHANGED") {
                            "FILE_CHANGED"
                        } else if message.contains("TARGET_NOT_ALLOWED") {
                            "TARGET_NOT_ALLOWED"
                        } else {
                            "INVALID_ARGUMENT"
                        };
                        let content = json!({"ok":false,"requestId":Uuid::new_v4().to_string(),"operation":name,"timing":{},"data":{},"error":{"code":code,"message":message,"phase":"validate","retryable":false},"warnings":[]});
                        result(
                            id,
                            json!({"content":[{"type":"text","text":content.to_string()}],"structuredContent":content,"isError":true}),
                        )
                    }
                }
            }
            _ => error(id, -32601, "Method not found"),
        };
        out.write_all(answer.to_string().as_bytes()).await?;
        out.write_all(b"\n").await?;
        out.flush().await?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|x| x == "--version") {
        println!("mcp-ssh {VERSION}");
        return Ok(());
    }
    let home = args
        .windows(2)
        .find(|pair| pair[0] == "--home")
        .map(|pair| PathBuf::from(&pair[1]));
    let app = App::new(home).await;
    if args.get(1).is_some_and(|x| x == "migrate-state") {
        migrate(&app.paths).await?;
        println!("状态迁移完成");
        return Ok(());
    }
    serve(app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v3_contract_has_five_closed_tools() {
        let tools = schemas();
        let a = tools.as_array().unwrap();
        assert_eq!(a.len(), 5);
        assert!(a
            .iter()
            .all(|t| t["inputSchema"]["additionalProperties"] == false));
    }
    #[test]
    fn markers_do_not_leak() {
        let id = "abc";
        let (s, started, exit) =
            markers("__MCP_SSH_STARTED_abc\nhello\n__MCP_SSH_EXIT_abc=0\n", id);
        assert_eq!(s, "hello");
        assert!(started);
        assert_eq!(exit, Some(0));
    }
    #[test]
    fn markers_are_removed_without_a_trailing_newline() {
        let (output, started, exit) =
            markers("__MCP_SSH_STARTED_abc\nhello__MCP_SSH_EXIT_abc=0\n", "abc");
        assert_eq!(output, "hello");
        assert!(started);
        assert_eq!(exit, Some(0));
    }
    #[test]
    fn shell_quote_is_single_argument() {
        assert_eq!(shell("a'b"), "'a'\\''b'");
    }
}
