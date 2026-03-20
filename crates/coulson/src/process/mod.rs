pub mod provider;

mod asgi;
mod docker;
mod node;
mod procfile;
mod rack;

pub use provider::{ListenTarget, ProviderRegistry};

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::process::{Child, Command};
use tracing::{debug, info, warn};

use std::process::Stdio;

use crate::config::ProcessBackend;
use crate::hooks::{HookContext, HookEvent, HookManager};
use provider::{ManagedApp, ProcessSpec};

/// Dedicated tmux socket name — isolates coulson sessions from user's own tmux.
const TMUX_SOCKET: &str = "coulson";

pub type ProcessManagerHandle = Arc<tokio::sync::Mutex<ProcessManager>>;

pub fn new_process_manager(
    idle_timeout: Duration,
    registry: Arc<ProviderRegistry>,
    runtime_dir: PathBuf,
    backend: ProcessBackend,
    hook_manager: Arc<HookManager>,
) -> ProcessManagerHandle {
    Arc::new(tokio::sync::Mutex::new(ProcessManager::new(
        idle_timeout,
        registry,
        runtime_dir,
        backend,
        hook_manager,
    )))
}

/// Create the default provider registry with all built-in providers.
///
/// Registration order determines auto-detection priority.
pub fn default_registry() -> ProviderRegistry {
    let mut reg = ProviderRegistry::new();
    reg.register(asgi::AsgiProvider);
    reg.register(node::NodeProvider);
    reg.register(procfile::ProcfileProvider);
    reg
}

enum ProcessHandle {
    Direct { child: Child },
    Tmux { session_name: String },
}

struct ManagedProcess {
    handle: ProcessHandle,
    listen_target: ListenTarget,
    started_at: Instant,
    last_active: Instant,
    kind: String,
    ready: bool,
}

#[allow(dead_code)]
struct CompanionProcess {
    process_type: String,
    handle: ProcessHandle,
}

struct ProcessGroup {
    primary: ManagedProcess,
    companions: Vec<CompanionProcess>,
    /// App name, preserved for hook context on stop/idle events.
    name: String,
    /// App root directory, preserved for hook context on stop/idle events.
    root: PathBuf,
}

pub struct ProcessManager {
    processes: HashMap<i64, ProcessGroup>,
    idle_timeout: Duration,
    registry: Arc<ProviderRegistry>,
    runtime_dir: PathBuf,
    use_tmux: bool,
    hook_manager: Arc<HookManager>,
}

pub enum StartStatus {
    /// Process is running and ready to accept connections.
    Ready(ListenTarget),
    /// Process has been spawned but is not yet ready.
    Starting,
}

#[derive(serde::Serialize)]
pub struct ProcessInfo {
    pub app_id: i64,
    pub pid: u32,
    pub kind: String,
    pub process_type: String,
    pub listen_address: String,
    pub uptime_secs: u64,
    pub idle_secs: u64,
    pub alive: bool,
    pub backend: String,
}

impl ProcessManager {
    pub fn new(
        idle_timeout: Duration,
        registry: Arc<ProviderRegistry>,
        runtime_dir: PathBuf,
        backend: ProcessBackend,
        hook_manager: Arc<HookManager>,
    ) -> Self {
        let use_tmux = match backend {
            ProcessBackend::Tmux => {
                if !tmux_available() {
                    warn!("COULSON_PROCESS_BACKEND=tmux but tmux not found in PATH");
                }
                true
            }
            ProcessBackend::Direct => false,
            ProcessBackend::Auto => {
                let available = tmux_available();
                if available {
                    info!("tmux found, using tmux process backend");
                } else {
                    info!("tmux not found, using direct process backend");
                }
                available
            }
        };

        Self {
            processes: HashMap::new(),
            idle_timeout,
            registry,
            runtime_dir,
            use_tmux,
            hook_manager,
        }
    }

    fn fire_hook(&self, event: HookEvent, app_id: i64, name: &str, root: &Path, kind: &str) {
        let ctx = HookContext {
            event,
            app_id: Some(app_id),
            app_name: Some(name.to_string()),
            app_domain: None,
            app_root: Some(root.to_path_buf()),
            app_urls: Vec::new(),
            app_kind: Some(kind.to_string()),
            tunnel_url: None,
        };
        let hm = self.hook_manager.clone();
        tokio::spawn(async move { hm.fire(&ctx).await });
    }

    /// Whether the tmux backend is active.
    pub fn uses_tmux(&self) -> bool {
        self.use_tmux
    }

    pub fn list_status(&mut self) -> Vec<ProcessInfo> {
        let now = Instant::now();
        let mut result = Vec::new();
        for (app_id, group) in &mut self.processes {
            let proc = &mut group.primary;
            let (pid, alive, backend) = handle_status(&mut proc.handle);
            result.push(ProcessInfo {
                app_id: *app_id,
                pid,
                kind: proc.kind.clone(),
                process_type: "web".to_string(),
                listen_address: listen_target_display(&proc.listen_target),
                uptime_secs: now.duration_since(proc.started_at).as_secs(),
                idle_secs: now.duration_since(proc.last_active).as_secs(),
                alive,
                backend: backend.to_string(),
            });
            for companion in &mut group.companions {
                let (c_pid, c_alive, c_backend) = handle_status(&mut companion.handle);
                result.push(ProcessInfo {
                    app_id: *app_id,
                    pid: c_pid,
                    kind: proc.kind.clone(),
                    process_type: companion.process_type.clone(),
                    listen_address: String::new(),
                    uptime_secs: now.duration_since(proc.started_at).as_secs(),
                    idle_secs: now.duration_since(proc.last_active).as_secs(),
                    alive: c_alive,
                    backend: c_backend.to_string(),
                });
            }
        }
        result
    }

    /// Returns the listen target for the managed app, starting the process if needed.
    pub async fn ensure_running(
        &mut self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
    ) -> anyhow::Result<ListenTarget> {
        // Check if already running and alive
        if let Some(group) = self.processes.get_mut(&app_id) {
            if is_alive(&mut group.primary.handle) {
                group.primary.last_active = Instant::now();
                return Ok(group.primary.listen_target.clone());
            }
            info!(app_id, "managed process exited, will restart");
            let removed = self.processes.remove(&app_id).unwrap();
            for companion in removed.companions {
                kill_handle(companion.handle).await;
            }
            kill_handle(removed.primary.handle).await;
            cleanup_listen_target(&removed.primary.listen_target);
        }

        let (spec, sockets_dir, prov_name, companion_types) =
            self.resolve_spec(app_id, name, root, kind)?;

        info!(
            app_id,
            kind,
            listen = %listen_target_display(&spec.listen_target),
            root = %root.display(),
            "starting managed process via {prov_name} provider",
        );

        self.fire_hook(HookEvent::AppStart, app_id, name, root, kind);

        cleanup_listen_target(&spec.listen_target);

        let log_path = sockets_dir.join(format!("{name}.log"));
        let handle = self.spawn_process(name, &spec, &log_path, &sockets_dir)?;

        const READY_TIMEOUT_SECS: u64 = 30;
        if let Err(e) =
            wait_for_ready(&spec.listen_target, Duration::from_secs(READY_TIMEOUT_SECS)).await
        {
            log_tail(&log_path, name);
            return Err(e);
        }

        self.fire_hook(HookEvent::AppReady, app_id, name, root, kind);

        let companions =
            self.spawn_companions(app_id, name, root, kind, &companion_types, &sockets_dir);

        let now = Instant::now();
        self.processes.insert(
            app_id,
            ProcessGroup {
                primary: ManagedProcess {
                    handle,
                    listen_target: spec.listen_target.clone(),
                    started_at: now,
                    last_active: now,
                    kind: kind.to_string(),
                    ready: true,
                },
                companions,
                name: name.to_string(),
                root: root.to_path_buf(),
            },
        );

        Ok(spec.listen_target)
    }

    /// Non-blocking variant: spawns the process if needed but does NOT wait for readiness.
    pub async fn ensure_started(
        &mut self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
    ) -> anyhow::Result<StartStatus> {
        // Check existing process state in a limited scope to avoid borrow conflicts
        enum ExistingState {
            AlreadyReady(ListenTarget),
            JustBecameReady(ListenTarget),
            StillStarting,
            TimedOut,
            Exited,
        }
        let existing = if let Some(group) = self.processes.get_mut(&app_id) {
            if is_alive(&mut group.primary.handle) {
                if group.primary.ready {
                    group.primary.last_active = Instant::now();
                    Some(ExistingState::AlreadyReady(
                        group.primary.listen_target.clone(),
                    ))
                } else if quick_ready_check(&group.primary.listen_target).await {
                    group.primary.ready = true;
                    group.primary.last_active = Instant::now();
                    Some(ExistingState::JustBecameReady(
                        group.primary.listen_target.clone(),
                    ))
                } else {
                    const STARTUP_TIMEOUT_SECS: u64 = 30;
                    if group.primary.started_at.elapsed()
                        > Duration::from_secs(STARTUP_TIMEOUT_SECS)
                    {
                        Some(ExistingState::TimedOut)
                    } else {
                        Some(ExistingState::StillStarting)
                    }
                }
            } else {
                Some(ExistingState::Exited)
            }
        } else {
            None
        };

        match existing {
            Some(ExistingState::AlreadyReady(target)) => {
                return Ok(StartStatus::Ready(target));
            }
            Some(ExistingState::JustBecameReady(target)) => {
                self.fire_hook(HookEvent::AppReady, app_id, name, root, kind);
                return Ok(StartStatus::Ready(target));
            }
            Some(ExistingState::StillStarting) => {
                return Ok(StartStatus::Starting);
            }
            Some(ExistingState::TimedOut) => {
                let removed = self.processes.remove(&app_id).unwrap();
                for companion in removed.companions {
                    kill_handle(companion.handle).await;
                }
                kill_handle(removed.primary.handle).await;
                cleanup_listen_target(&removed.primary.listen_target);
                let log_path = self.runtime_dir.join(format!("managed/{name}.log"));
                log_tail(&log_path, name);
                const STARTUP_TIMEOUT_SECS: u64 = 30;
                anyhow::bail!(
                    "managed process for {name} (app_id={app_id}) failed to become ready within {STARTUP_TIMEOUT_SECS}s"
                );
            }
            Some(ExistingState::Exited) => {
                info!(app_id, "managed process exited, will restart");
                let removed = self.processes.remove(&app_id).unwrap();
                for companion in removed.companions {
                    kill_handle(companion.handle).await;
                }
                kill_handle(removed.primary.handle).await;
                cleanup_listen_target(&removed.primary.listen_target);
            }
            None => {} // No existing process, proceed to spawn
        }

        let (spec, sockets_dir, prov_name, companion_types) =
            self.resolve_spec(app_id, name, root, kind)?;

        info!(
            app_id,
            kind,
            listen = %listen_target_display(&spec.listen_target),
            root = %root.display(),
            "starting managed process via {prov_name} provider (non-blocking)",
        );

        self.fire_hook(HookEvent::AppStart, app_id, name, root, kind);

        cleanup_listen_target(&spec.listen_target);

        let log_path = sockets_dir.join(format!("{name}.log"));
        let handle = self.spawn_process(name, &spec, &log_path, &sockets_dir)?;

        let companions =
            self.spawn_companions(app_id, name, root, kind, &companion_types, &sockets_dir);

        let now = Instant::now();
        self.processes.insert(
            app_id,
            ProcessGroup {
                primary: ManagedProcess {
                    handle,
                    listen_target: spec.listen_target,
                    started_at: now,
                    last_active: now,
                    kind: kind.to_string(),
                    ready: false,
                },
                companions,
                name: name.to_string(),
                root: root.to_path_buf(),
            },
        );

        Ok(StartStatus::Starting)
    }

    /// Kill a specific managed process. Returns true if it was found and killed.
    pub async fn kill_process(&mut self, app_id: i64) -> bool {
        if let Some(group) = self.processes.remove(&app_id) {
            info!(app_id, "killing managed process");
            for companion in group.companions {
                kill_handle(companion.handle).await;
            }
            kill_handle(group.primary.handle).await;
            cleanup_listen_target(&group.primary.listen_target);
            let ctx = HookContext {
                event: HookEvent::AppStop,
                app_id: Some(app_id),
                app_name: Some(group.name),
                app_domain: None,
                app_root: Some(group.root),
                app_urls: Vec::new(),
                app_kind: Some(group.primary.kind),
                tunnel_url: None,
            };
            let hm = self.hook_manager.clone();
            tokio::spawn(async move { hm.fire(&ctx).await });
            true
        } else {
            false
        }
    }

    pub fn mark_active(&mut self, app_id: i64) {
        if let Some(group) = self.processes.get_mut(&app_id) {
            group.primary.last_active = Instant::now();
        }
    }

    /// Kill processes idle longer than the configured timeout. Returns count reaped.
    pub async fn reap_idle(&mut self) -> usize {
        let now = Instant::now();
        let timeout = self.idle_timeout;
        let mut to_remove = Vec::new();

        for (app_id, group) in &self.processes {
            if now.duration_since(group.primary.last_active) > timeout {
                to_remove.push(*app_id);
            }
        }

        for app_id in &to_remove {
            if let Some(group) = self.processes.remove(app_id) {
                info!(
                    app_id,
                    listen = %listen_target_display(&group.primary.listen_target),
                    "reaping idle managed process"
                );
                // Fire AppIdle before reaping
                let idle_ctx = HookContext {
                    event: HookEvent::AppIdle,
                    app_id: Some(*app_id),
                    app_name: Some(group.name.clone()),
                    app_domain: None,
                    app_root: Some(group.root.clone()),
                    app_urls: Vec::new(),
                    app_kind: Some(group.primary.kind.clone()),
                    tunnel_url: None,
                };
                self.hook_manager.fire(&idle_ctx).await;
                for companion in group.companions {
                    kill_handle(companion.handle).await;
                }
                kill_handle(group.primary.handle).await;
                cleanup_listen_target(&group.primary.listen_target);
                // Fire AppStop after kill
                let stop_ctx = HookContext {
                    event: HookEvent::AppStop,
                    app_id: Some(*app_id),
                    app_name: Some(group.name),
                    app_domain: None,
                    app_root: Some(group.root),
                    app_urls: Vec::new(),
                    app_kind: Some(group.primary.kind),
                    tunnel_url: None,
                };
                let hm = self.hook_manager.clone();
                tokio::spawn(async move { hm.fire(&stop_ctx).await });
            }
        }

        to_remove.len()
    }

    /// Kill all managed processes (called on daemon shutdown).
    pub async fn shutdown_all(&mut self) {
        for (app_id, group) in self.processes.drain() {
            info!(
                app_id,
                listen = %listen_target_display(&group.primary.listen_target),
                "shutting down managed process"
            );
            for companion in group.companions {
                kill_handle(companion.handle).await;
            }
            kill_handle(group.primary.handle).await;
            cleanup_listen_target(&group.primary.listen_target);
        }
        // If using tmux, kill the dedicated server to clean up.
        if self.use_tmux {
            let _ = tmux_cmd().args(["kill-server"]).output();
        }
    }

    /// Resolve a ProcessSpec from the provider registry.
    fn resolve_spec(
        &self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
    ) -> anyhow::Result<(ProcessSpec, PathBuf, String, Vec<String>)> {
        let prov = self
            .registry
            .get(kind)
            .ok_or_else(|| anyhow::anyhow!("no process provider for kind: {kind}"))?;

        let managed_dir = self.runtime_dir.join("managed");
        std::fs::create_dir_all(&managed_dir)
            .with_context(|| format!("failed to create {}", managed_dir.display()))?;
        let sockets_dir = std::fs::canonicalize(&managed_dir).unwrap_or(managed_dir);

        let env_overrides = crate::process::provider::load_coulsonrc(root);

        let companion_types = parse_managed_services(
            env_overrides
                .get("COULSON_MANAGED_SERVICES")
                .map(|s| s.as_str()),
        );

        if !companion_types.is_empty() && kind != "procfile" {
            warn!(
                app_id,
                kind, "COULSON_MANAGED_SERVICES is only supported for procfile apps, ignoring"
            );
        }

        // Load .coulson.toml manifest if present
        let manifest = load_coulson_toml_manifest(root);

        let managed_app = ManagedApp {
            name: name.to_string(),
            root: root.to_path_buf(),
            kind: kind.to_string(),
            manifest,
            env_overrides,
            socket_dir: sockets_dir.clone(),
        };

        let mut spec = prov.resolve(&managed_app)?;
        // Do not pass COULSON_MANAGED_SERVICES to child processes
        spec.env.remove("COULSON_MANAGED_SERVICES");

        let _ = app_id; // used in caller for logging
        Ok((
            spec,
            sockets_dir,
            prov.display_name().to_string(),
            companion_types,
        ))
    }

    /// Spawn a process using the current backend (direct or tmux).
    fn spawn_process(
        &self,
        name: &str,
        spec: &ProcessSpec,
        log_path: &Path,
        managed_dir: &Path,
    ) -> anyhow::Result<ProcessHandle> {
        if self.use_tmux {
            self.spawn_tmux(name, spec, log_path, managed_dir)
        } else {
            Self::spawn_direct(name, spec, log_path)
        }
    }

    /// Spawn companion processes for a Procfile app.
    fn spawn_companions(
        &self,
        app_id: i64,
        name: &str,
        root: &Path,
        kind: &str,
        companion_types: &[String],
        sockets_dir: &Path,
    ) -> Vec<CompanionProcess> {
        if companion_types.is_empty() || kind != "procfile" {
            return vec![];
        }

        let env_overrides = crate::process::provider::load_coulsonrc(root);
        let managed_app = ManagedApp {
            name: name.to_string(),
            root: root.to_path_buf(),
            kind: kind.to_string(),
            manifest: None,
            env_overrides,
            socket_dir: sockets_dir.to_path_buf(),
        };

        let provider = procfile::ProcfileProvider;
        let mut companions = Vec::new();

        for ptype in companion_types {
            match provider.resolve_companion(&managed_app, ptype) {
                Ok(cspec) => {
                    let spec = ProcessSpec {
                        command: cspec.command,
                        args: cspec.args,
                        env: cspec.env,
                        working_dir: cspec.working_dir,
                        listen_target: ListenTarget::Tcp {
                            host: String::new(),
                            port: 0,
                        },
                    };
                    let log_path = sockets_dir.join(format!("{name}-{ptype}.log"));
                    match self.spawn_process(
                        &format!("{name}-{ptype}"),
                        &spec,
                        &log_path,
                        sockets_dir,
                    ) {
                        Ok(handle) => {
                            info!(
                                app_id,
                                process_type = %ptype,
                                "spawned companion process"
                            );
                            companions.push(CompanionProcess {
                                process_type: ptype.clone(),
                                handle,
                            });
                        }
                        Err(e) => {
                            warn!(
                                app_id,
                                process_type = %ptype,
                                error = %e,
                                "failed to spawn companion process"
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        app_id,
                        process_type = %ptype,
                        error = %e,
                        "failed to resolve companion process"
                    );
                }
            }
        }

        companions
    }

    /// Spawn via direct child process (original behavior).
    fn spawn_direct(
        name: &str,
        spec: &ProcessSpec,
        log_path: &Path,
    ) -> anyhow::Result<ProcessHandle> {
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .with_context(|| format!("failed to open log file {}", log_path.display()))?;
        let stderr_file = log_file
            .try_clone()
            .with_context(|| "failed to clone log file handle")?;

        // All specs go through login shell for user env loading
        let full_cmd = build_full_command(spec);
        let (command, args) = login_shell_args(&full_cmd);

        let mut cmd = Command::new(&command);
        cmd.args(&args);
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        cmd.process_group(0);

        let child = cmd
            .current_dir(&spec.working_dir)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(stderr_file)
            .stderr(log_file)
            .spawn()
            .with_context(|| format!("failed to spawn {} for {name}", command.display()))?;

        Ok(ProcessHandle::Direct { child })
    }

    /// Spawn via tmux session.
    fn spawn_tmux(
        &self,
        name: &str,
        spec: &ProcessSpec,
        log_path: &Path,
        managed_dir: &Path,
    ) -> anyhow::Result<ProcessHandle> {
        let session_name = name.to_string();

        // Kill any existing session with this name
        if tmux_has_session(&session_name) {
            tmux_kill_session(&session_name);
        }

        // Generate wrapper script
        let script_path = managed_dir.join(format!("{name}.sh"));
        let script_content = generate_wrapper_script(spec);
        std::fs::write(&script_path, &script_content)
            .with_context(|| format!("failed to write wrapper script {}", script_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))?;
        }

        // Create tmux session
        let output = tmux_cmd()
            .args([
                "new-session",
                "-d",
                "-s",
                &session_name,
                "-c",
                &spec.working_dir.to_string_lossy(),
                &script_path.to_string_lossy(),
            ])
            .output()
            .with_context(|| format!("failed to spawn tmux session for {name}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("tmux new-session failed: {stderr}");
        }

        // Set remain-on-exit so session stays for inspection after crash
        let _ = tmux_cmd()
            .args(["set-option", "-t", &session_name, "remain-on-exit", "on"])
            .output();

        // Pipe pane output to log file
        let _ = tmux_cmd()
            .args([
                "pipe-pane",
                "-t",
                &session_name,
                "-o",
                &format!("cat >> {}", log_path.display()),
            ])
            .output();

        debug!(session = %session_name, "spawned tmux session");

        Ok(ProcessHandle::Tmux { session_name })
    }
}

/// Load `.coulson.toml` from app root and convert to serde_json::Value for providers.
/// Logs errors instead of silently ignoring them.
fn load_coulson_toml_manifest(root: &Path) -> Option<serde_json::Value> {
    let toml_path = root.join(".coulson.toml");
    let raw = match std::fs::read_to_string(&toml_path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::error!(path = %toml_path.display(), %e, "failed to read .coulson.toml");
            return None;
        }
    };
    let table: toml::Value = match toml::from_str(&raw) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(path = %toml_path.display(), %e, "failed to parse .coulson.toml");
            return None;
        }
    };
    match serde_json::to_value(table) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::error!(path = %toml_path.display(), %e, "failed to convert .coulson.toml to JSON");
            None
        }
    }
}

/// Build the full shell command string from a ProcessSpec.
/// Procfile specs have an empty command and a single args element (the raw shell command).
/// ASGI/Node specs have a binary command and separate args.
fn build_full_command(spec: &ProcessSpec) -> String {
    if spec.command.as_os_str().is_empty() {
        // Procfile-style: args[0] is the complete shell command string
        spec.args[0].clone()
    } else {
        // Binary + args: join into a single command line
        let mut parts = vec![shell_escape_path(&spec.command)];
        parts.extend(spec.args.iter().map(|a| shell_escape(a)));
        parts.join(" ")
    }
}

/// Generate a wrapper script for the process.
fn generate_wrapper_script(spec: &ProcessSpec) -> String {
    let mut lines = vec!["#!/usr/bin/env sh".to_string()];

    // Export env vars
    for (k, v) in &spec.env {
        let escaped = v.replace('\'', "'\\''");
        lines.push(format!("export {k}='{escaped}'"));
    }

    let shell = user_shell();
    let cmd = build_full_command(spec);
    let escaped_cmd = cmd.replace('\'', "'\\''");
    lines.push(format!("exec {} -li -c '{}'", shell.display(), escaped_cmd));

    lines.push(String::new()); // trailing newline
    lines.join("\n")
}

/// Shell-escape a string with single quotes.
fn shell_escape(s: &str) -> String {
    if s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/' || c == ':'
    }) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn shell_escape_path(p: &Path) -> String {
    shell_escape(&p.to_string_lossy())
}

/// Get the user's login shell from `$SHELL`, falling back to `/bin/sh`.
fn user_shell() -> PathBuf {
    std::env::var("SHELL")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/bin/sh"))
}

/// Build login-shell arguments that source the interactive RC file before
/// executing `cmd`. Used by Direct mode to load user env.
fn login_shell_args(cmd: &str) -> (PathBuf, Vec<String>) {
    let shell = user_shell();
    let name = shell.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let full_cmd = match name {
        "zsh" => format!(". ~/.zshrc 2>/dev/null; {cmd}"),
        "bash" => format!(". ~/.bashrc 2>/dev/null; {cmd}"),
        _ => cmd.to_string(),
    };
    (shell, vec!["-l".to_string(), "-c".to_string(), full_cmd])
}

/// Extract pid, alive status, and backend name from a process handle.
fn handle_status(handle: &mut ProcessHandle) -> (u32, bool, &'static str) {
    match handle {
        ProcessHandle::Direct { child } => {
            let pid = child.id().unwrap_or(0);
            let alive = matches!(child.try_wait(), Ok(None));
            (pid, alive, "direct")
        }
        ProcessHandle::Tmux { session_name } => {
            let pid = tmux_pane_pid(session_name).unwrap_or(0);
            let alive = if pid != 0 {
                tmux_pane_alive(session_name)
            } else {
                false
            };
            (pid, alive, "tmux")
        }
    }
}

/// Check whether the process handle is still alive.
fn is_alive(handle: &mut ProcessHandle) -> bool {
    match handle {
        ProcessHandle::Direct { child } => matches!(child.try_wait(), Ok(None)),
        ProcessHandle::Tmux { session_name } => {
            tmux_has_session(session_name) && tmux_pane_alive(session_name)
        }
    }
}

/// Kill a process handle.
async fn kill_handle(handle: ProcessHandle) {
    match handle {
        ProcessHandle::Direct { mut child } => {
            kill_process_group(&mut child).await;
        }
        ProcessHandle::Tmux { session_name } => {
            // SIGTERM the pane process first, then kill the session
            if let Some(pid) = tmux_pane_pid(&session_name) {
                let pgid = pid as i32;
                unsafe { libc::kill(-pgid, libc::SIGTERM) };
                const GRACE_MS: u64 = 500;
                tokio::time::sleep(Duration::from_millis(GRACE_MS)).await;
                // Force kill if still alive
                unsafe { libc::kill(-pgid, libc::SIGKILL) };
            }
            tmux_kill_session(&session_name);
        }
    }
}

// tmux helper functions

/// Check if tmux is available in PATH.
pub fn tmux_available() -> bool {
    std::process::Command::new("tmux")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Build a tmux command with the dedicated socket.
fn tmux_cmd() -> std::process::Command {
    let mut cmd = std::process::Command::new("tmux");
    cmd.args(["-L", TMUX_SOCKET]);
    cmd
}

/// Check if a tmux session exists.
fn tmux_has_session(name: &str) -> bool {
    tmux_cmd()
        .args(["has-session", "-t", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Check if the pane process in a tmux session is still alive.
/// With `remain-on-exit on`, the session persists after the pane process exits.
fn tmux_pane_alive(name: &str) -> bool {
    let output = tmux_cmd()
        .args(["list-panes", "-t", name, "-F", "#{pane_dead}"])
        .output();
    match output {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            // pane_dead is "0" if alive, "1" if dead
            text.trim() == "0"
        }
        Err(_) => false,
    }
}

/// Get the PID of the process running in a tmux session's pane.
fn tmux_pane_pid(name: &str) -> Option<u32> {
    let output = tmux_cmd()
        .args(["list-panes", "-t", name, "-F", "#{pane_pid}"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.trim().parse().ok()
}

/// Kill a tmux session.
fn tmux_kill_session(name: &str) {
    let _ = tmux_cmd()
        .args(["kill-session", "-t", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Log the last few lines of a managed process log file on startup failure.
fn log_tail(log_path: &Path, name: &str) {
    const TAIL_LINES: usize = 10;
    if let Ok(content) = std::fs::read_to_string(log_path) {
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(TAIL_LINES);
        let tail = lines[start..].join("\n");
        if !tail.trim().is_empty() {
            warn!(
                app = name,
                log = %log_path.display(),
                "\n--- process log tail ---\n{tail}\n---"
            );
        }
    }
}

/// Clean up resources associated with a listen target.
fn cleanup_listen_target(target: &ListenTarget) {
    if let ListenTarget::Uds(path) = target {
        let _ = std::fs::remove_file(path);
    }
}

/// Wait for a listen target to become ready (UDS or TCP).
async fn wait_for_ready(target: &ListenTarget, timeout: Duration) -> anyhow::Result<()> {
    match target {
        ListenTarget::Uds(path) => provider::wait_for_uds_ready(path, timeout).await,
        ListenTarget::Tcp { host, port } => {
            provider::wait_for_tcp_ready(host, *port, timeout).await
        }
    }
}

/// Single-shot readiness probe with a short timeout.
async fn quick_ready_check(target: &ListenTarget) -> bool {
    const PROBE_TIMEOUT_MS: u64 = 200;
    let timeout = Duration::from_millis(PROBE_TIMEOUT_MS);
    match target {
        ListenTarget::Uds(path) => {
            tokio::time::timeout(timeout, tokio::net::UnixStream::connect(path))
                .await
                .is_ok_and(|r| r.is_ok())
        }
        ListenTarget::Tcp { host, port } => {
            let addr = format!("{host}:{port}");
            tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr))
                .await
                .is_ok_and(|r| r.is_ok())
        }
    }
}

/// Human-readable display of a listen target.
/// Parse `COULSON_MANAGED_SERVICES` value into companion process types (excluding "web").
fn parse_managed_services(value: Option<&str>) -> Vec<String> {
    value
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty() && t != "web")
                .collect()
        })
        .unwrap_or_default()
}

fn listen_target_display(target: &ListenTarget) -> String {
    match target {
        ListenTarget::Uds(path) => path.to_string_lossy().to_string(),
        ListenTarget::Tcp { host, port } => format!("{host}:{port}"),
    }
}

/// Kill an entire process group: SIGTERM first, then SIGKILL after a grace period.
async fn kill_process_group(child: &mut Child) {
    let Some(pid) = child.id() else {
        return;
    };
    let pgid = pid as i32;

    let ret = unsafe { libc::kill(-pgid, libc::SIGTERM) };
    if ret != 0 {
        let _ = child.start_kill();
        return;
    }

    const GRACE_MS: u64 = 500;
    tokio::time::sleep(Duration::from_millis(GRACE_MS)).await;

    match child.try_wait() {
        Ok(None) => {
            let ret = unsafe { libc::kill(-pgid, libc::SIGKILL) };
            if ret != 0 {
                warn!(pid, "SIGKILL to process group failed, trying direct kill");
                let _ = child.start_kill();
            }
        }
        Ok(Some(_)) => {
            unsafe { libc::kill(-pgid, libc::SIGKILL) };
        }
        Err(e) => {
            warn!(pid, error = %e, "failed to check process status, skipping group kill");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_managed_services_with_companions() {
        let result = parse_managed_services(Some("web,worker, release "));
        assert_eq!(result, vec!["worker", "release"]);
    }

    #[test]
    fn parse_managed_services_web_only() {
        let result = parse_managed_services(Some("web"));
        assert!(result.is_empty());
    }

    #[test]
    fn parse_managed_services_empty_string() {
        let result = parse_managed_services(Some(""));
        assert!(result.is_empty());
    }

    #[test]
    fn parse_managed_services_none() {
        let result = parse_managed_services(None);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_managed_services_no_web() {
        let result = parse_managed_services(Some("worker,scheduler"));
        assert_eq!(result, vec!["worker", "scheduler"]);
    }
}
