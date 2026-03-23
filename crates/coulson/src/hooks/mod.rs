use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use parking_lot::RwLock;
use serde::Deserialize;
use tokio::process::Command;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvent {
    AppAdd,
    AppRemove,
    AppStart,
    AppReady,
    AppStop,
    AppIdle,
    TunnelStart,
    TunnelStop,
    ScanComplete,
}

impl HookEvent {
    /// Canonical event name used for file names, env vars, and webhook payloads.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AppAdd => "app_add",
            Self::AppRemove => "app_remove",
            Self::AppStart => "app_start",
            Self::AppReady => "app_ready",
            Self::AppStop => "app_stop",
            Self::AppIdle => "app_idle",
            Self::TunnelStart => "tunnel_start",
            Self::TunnelStop => "tunnel_stop",
            Self::ScanComplete => "scan_complete",
        }
    }
}

pub struct HookContext {
    pub event: HookEvent,
    pub app_id: Option<i64>,
    pub app_name: Option<String>,
    pub app_domain: Option<String>,
    pub app_root: Option<PathBuf>,
    /// All reachable URLs (.localhost, primary, HTTPS, tunnel).
    pub app_urls: Vec<String>,
    pub app_kind: Option<String>,
    pub tunnel_url: Option<String>,
}

/// Per-app hook configuration parsed from `.coulson.toml` `[hooks]` section.
#[derive(Debug, Clone, Deserialize)]
pub struct AppHooksConfig {
    #[serde(default)]
    pub skip_global: bool,
    #[serde(default)]
    pub app_add: Option<HookActionConfig>,
    #[serde(default)]
    pub app_remove: Option<HookActionConfig>,
    #[serde(default)]
    pub app_start: Option<HookActionConfig>,
    #[serde(default)]
    pub app_ready: Option<HookActionConfig>,
    #[serde(default)]
    pub app_stop: Option<HookActionConfig>,
    #[serde(default)]
    pub app_idle: Option<HookActionConfig>,
    #[serde(default)]
    pub tunnel_start: Option<HookActionConfig>,
    #[serde(default)]
    pub tunnel_stop: Option<HookActionConfig>,
    // Note: scan_complete is global-only (no app_id context), not configurable per-app.
}

impl AppHooksConfig {
    fn get_action(&self, event: &HookEvent) -> Option<&HookActionConfig> {
        match event {
            HookEvent::AppAdd => self.app_add.as_ref(),
            HookEvent::AppRemove => self.app_remove.as_ref(),
            HookEvent::AppStart => self.app_start.as_ref(),
            HookEvent::AppReady => self.app_ready.as_ref(),
            HookEvent::AppStop => self.app_stop.as_ref(),
            HookEvent::AppIdle => self.app_idle.as_ref(),
            HookEvent::TunnelStart => self.tunnel_start.as_ref(),
            HookEvent::TunnelStop => self.tunnel_stop.as_ref(),
            HookEvent::ScanComplete => None, // global-only event
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HookActionConfig {
    pub run: Option<String>,
    pub webhook: Option<String>,
}

pub struct HookManager {
    hooks_dir: PathBuf,
    timeout: Duration,
    http_client: reqwest::Client,
    app_hooks: RwLock<HashMap<i64, AppHooksConfig>>,
}

impl HookManager {
    pub fn new(hooks_dir: PathBuf, timeout_secs: u64) -> Self {
        Self {
            hooks_dir,
            timeout: Duration::from_secs(timeout_secs),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            app_hooks: RwLock::new(HashMap::new()),
        }
    }

    /// Register per-app hooks from `.coulson.toml` (called during scan).
    pub fn register_app_hooks(&self, app_id: i64, config: AppHooksConfig) {
        self.app_hooks.write().insert(app_id, config);
    }

    /// Remove per-app hooks (called when app is deleted).
    pub fn unregister_app_hooks(&self, app_id: i64) {
        self.app_hooks.write().remove(&app_id);
    }

    /// Clear all per-app hooks (called before re-scanning to avoid stale entries).
    pub fn clear_all_app_hooks(&self) {
        self.app_hooks.write().clear();
    }

    /// Snapshot and remove per-app hooks for the given app (for use before deletion).
    pub fn take_app_hooks(&self, app_id: i64) -> Option<AppHooksConfig> {
        self.app_hooks.write().remove(&app_id)
    }

    /// Main entry point: fire global + per-app hooks for the given event.
    pub async fn fire(&self, ctx: &HookContext) {
        let app_hooks = ctx.app_id.and_then(|id| {
            let map = self.app_hooks.read();
            map.get(&id).cloned()
        });
        self.fire_with_hooks(ctx, app_hooks.as_ref()).await;
    }

    /// Fire with an explicit per-app hooks snapshot (avoids shared table lookup).
    pub async fn fire_with_hooks(&self, ctx: &HookContext, app_hooks: Option<&AppHooksConfig>) {
        let event_name = ctx.event.as_str();

        let skip_global = app_hooks.map(|h| h.skip_global).unwrap_or(false);

        // Global hooks first
        if !skip_global {
            self.fire_global(event_name, ctx).await;
        }

        // Per-app hooks
        if let Some(hooks) = app_hooks {
            if let Some(action) = hooks.get_action(&ctx.event) {
                if let Some(ref cmd) = action.run {
                    self.fire_shell(cmd, ctx).await;
                }
                if let Some(ref url) = action.webhook {
                    let payload = build_webhook_payload(ctx);
                    let url = url.clone();
                    let client = self.http_client.clone();
                    tokio::spawn(async move {
                        fire_webhook(&client, &url, &payload).await;
                    });
                }
            }
        }
    }

    /// Execute a global hook script from `{hooks_dir}/{event_name}`.
    async fn fire_global(&self, event_name: &str, ctx: &HookContext) {
        let script = self.hooks_dir.join(event_name);
        if !script.exists() {
            return;
        }

        // Check executable permission
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&script) {
                if meta.permissions().mode() & 0o111 == 0 {
                    warn!(
                        hook = event_name,
                        path = %script.display(),
                        "global hook script is not executable, skipping"
                    );
                    return;
                }
            }
        }

        info!(hook = event_name, "executing global hook");
        let script_str = script.to_string_lossy().to_string();
        self.fire_shell(&script_str, ctx).await;
    }

    /// Execute a shell command with hook environment variables.
    async fn fire_shell(&self, cmd: &str, ctx: &HookContext) {
        let event_name = ctx.event.as_str();
        let cwd = ctx.app_root.clone().unwrap_or_else(|| PathBuf::from("."));

        let mut command = Command::new("sh");
        command.arg("-c").arg(cmd);
        command.current_dir(&cwd);

        // Set environment variables
        command.env("COULSON_EVENT", event_name);
        if let Some(ref id) = ctx.app_id {
            command.env("COULSON_APP_ID", id.to_string());
        }
        if let Some(ref name) = ctx.app_name {
            command.env("COULSON_APP_NAME", name);
        }
        if let Some(ref domain) = ctx.app_domain {
            command.env("COULSON_APP_DOMAIN", domain);
        }
        if let Some(ref root) = ctx.app_root {
            command.env("COULSON_APP_ROOT", root.as_os_str());
        }
        if let Some(url) = ctx.app_urls.first() {
            command.env("COULSON_APP_URL", url);
        }
        if !ctx.app_urls.is_empty() {
            command.env("COULSON_APP_URLS", ctx.app_urls.join(","));
        }
        if let Some(ref tunnel_url) = ctx.tunnel_url {
            command.env("COULSON_TUNNEL_URL", tunnel_url);
        }

        match tokio::time::timeout(self.timeout, command.output()).await {
            Ok(Ok(output)) => {
                if output.status.success() {
                    debug!(hook = event_name, cmd, "hook completed successfully");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!(
                        hook = event_name,
                        cmd,
                        status = %output.status,
                        stderr = %stderr.trim(),
                        "hook failed"
                    );
                }
            }
            Ok(Err(e)) => {
                error!(hook = event_name, cmd, error = %e, "failed to execute hook");
            }
            Err(_) => {
                warn!(
                    hook = event_name,
                    cmd,
                    timeout_secs = self.timeout.as_secs(),
                    "hook timed out"
                );
            }
        }
    }
}

fn build_webhook_payload(ctx: &HookContext) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "event": ctx.event.as_str(),
        "timestamp": time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
    });

    if ctx.app_id.is_some() {
        payload["app"] = serde_json::json!({
            "id": ctx.app_id,
            "name": ctx.app_name,
            "domain": ctx.app_domain,
            "urls": ctx.app_urls,
            "root": ctx.app_root.as_ref().map(|p| p.to_string_lossy().to_string()),
            "kind": ctx.app_kind,
            "tunnel_url": ctx.tunnel_url,
        });
    }

    payload
}

async fn fire_webhook(client: &reqwest::Client, url: &str, payload: &serde_json::Value) {
    match client.post(url).json(payload).send().await {
        Ok(resp) => {
            debug!(url, status = resp.status().as_u16(), "webhook delivered");
        }
        Err(e) => {
            warn!(url, error = %e, "webhook delivery failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_event_as_str() {
        assert_eq!(HookEvent::AppAdd.as_str(), "app_add");
        assert_eq!(HookEvent::AppReady.as_str(), "app_ready");
        assert_eq!(HookEvent::TunnelStart.as_str(), "tunnel_start");
        assert_eq!(HookEvent::TunnelStop.as_str(), "tunnel_stop");
        assert_eq!(HookEvent::ScanComplete.as_str(), "scan_complete");
    }

    #[test]
    fn webhook_payload_includes_app_info() {
        let ctx = HookContext {
            event: HookEvent::TunnelStart,
            app_id: Some(42),
            app_name: Some("myapp".to_string()),
            app_domain: Some("myapp.coulson.local".to_string()),
            app_root: Some(std::path::PathBuf::from("/tmp/myapp")),
            app_urls: vec![
                "http://myapp.localhost:8080/".to_string(),
                "https://myapp.example.com".to_string(),
            ],
            app_kind: Some("asgi".to_string()),
            tunnel_url: Some("https://myapp.example.com".to_string()),
        };
        let payload = build_webhook_payload(&ctx);
        assert_eq!(payload["event"], "tunnel_start");
        assert_eq!(payload["app"]["id"], 42);
        assert_eq!(payload["app"]["name"], "myapp");
        assert_eq!(payload["app"]["domain"], "myapp.coulson.local");
        assert_eq!(payload["app"]["tunnel_url"], "https://myapp.example.com");
        let urls = payload["app"]["urls"].as_array().unwrap();
        assert_eq!(urls.len(), 2);
    }

    #[test]
    fn webhook_payload_without_app() {
        let ctx = HookContext {
            event: HookEvent::ScanComplete,
            app_id: None,
            app_name: None,
            app_domain: None,
            app_root: None,
            app_urls: Vec::new(),
            app_kind: None,
            tunnel_url: None,
        };
        let payload = build_webhook_payload(&ctx);
        assert_eq!(payload["event"], "scan_complete");
        assert!(payload.get("app").is_none());
    }

    #[test]
    fn app_hooks_config_get_action() {
        let config = AppHooksConfig {
            skip_global: false,
            app_add: None,
            app_remove: None,
            app_start: None,
            app_ready: Some(HookActionConfig {
                run: Some("echo ready".to_string()),
                webhook: None,
            }),
            app_stop: None,
            app_idle: None,
            tunnel_start: Some(HookActionConfig {
                run: None,
                webhook: Some("https://hooks.example.com".to_string()),
            }),
            tunnel_stop: None,
        };
        assert!(config.get_action(&HookEvent::AppReady).is_some());
        assert!(config.get_action(&HookEvent::TunnelStart).is_some());
        assert!(config.get_action(&HookEvent::AppStart).is_none());
        assert!(config.get_action(&HookEvent::ScanComplete).is_none());
    }

    #[test]
    fn app_hooks_config_deserialize_from_toml() {
        let toml_str = r#"
skip_global = true

[tunnel_start]
webhook = "https://hooks.example.com/tunnel"

[app_ready]
run = "mise run db:migrate"
webhook = "https://hooks.example.com/ready"
"#;
        let config: AppHooksConfig = toml::from_str(toml_str).unwrap();
        assert!(config.skip_global);
        let ts = config.tunnel_start.as_ref().unwrap();
        assert!(ts.run.is_none());
        assert_eq!(
            ts.webhook.as_deref(),
            Some("https://hooks.example.com/tunnel")
        );
        let ar = config.app_ready.as_ref().unwrap();
        assert_eq!(ar.run.as_deref(), Some("mise run db:migrate"));
    }
}
