use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;
use tracing::debug;

use super::provider::{
    resolve_port, DetectedApp, ListenTarget, ManagedApp, ProcessProvider, ProcessSpec,
};

/// Spec for a companion process (no listen_target, no PORT).
#[allow(dead_code)]
pub struct CompanionSpec {
    pub process_type: String,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub working_dir: PathBuf,
}

/// Procfile provider — manages applications defined by a standard Procfile.
///
/// Detection: directory contains `Procfile.dev` or `Procfile` with a `web:` process.
/// Resolves to `$SHELL -l -c "<rc source>; <web command>"` with TCP port via `$PORT`.
/// The RC file (.zshrc/.bashrc) is sourced explicitly because login shells don't
/// load interactive config where tools like mise/direnv are typically activated.
///
/// This provider is registered at the lowest priority so that ASGI and Node
/// providers get first chance at detecting their respective app types.
pub struct ProcfileProvider;

const PROCFILE_DEV: &str = "Procfile.dev";
const PROCFILE: &str = "Procfile";

/// Read the Procfile content, preferring `Procfile.dev` over `Procfile`.
fn read_procfile(dir: &Path) -> Option<String> {
    let dev = dir.join(PROCFILE_DEV);
    if dev.exists() {
        if let Ok(content) = std::fs::read_to_string(&dev) {
            return Some(content);
        }
    }
    let standard = dir.join(PROCFILE);
    if standard.exists() {
        if let Ok(content) = std::fs::read_to_string(&standard) {
            return Some(content);
        }
    }
    None
}

/// Check if parsed procfile content contains a `web` process type.
fn has_web_process(content: &str) -> bool {
    procfile::parse(content)
        .ok()
        .and_then(|procs| procs.get("web").map(|_| ()))
        .is_some()
}

impl ProcfileProvider {
    /// Resolve a non-web companion process from the Procfile.
    #[allow(dead_code)]
    pub fn resolve_companion(
        &self,
        app: &ManagedApp,
        process_type: &str,
    ) -> anyhow::Result<CompanionSpec> {
        let root = &app.root;
        let content = read_procfile(root)
            .ok_or_else(|| anyhow::anyhow!("no Procfile found in {}", root.display()))?;
        let procs = procfile::parse(&content)
            .map_err(|e| anyhow::anyhow!("failed to parse Procfile: {e}"))?;
        let entry = procs
            .get(process_type)
            .ok_or_else(|| anyhow::anyhow!("Procfile has no '{process_type}' process type"))?;

        let full_command = if entry.options.is_empty() {
            entry.command.to_string()
        } else {
            format!("{} {}", entry.command, entry.options.join(" "))
        };

        // Companion gets env_overrides but no PORT, no COULSON_MANAGED_SERVICES
        let mut env = app.env_overrides.clone();
        env.remove("COULSON_MANAGED_SERVICES");

        Ok(CompanionSpec {
            process_type: process_type.to_string(),
            command: PathBuf::new(),
            args: vec![full_command],
            env,
            working_dir: root.clone(),
        })
    }
}

impl ProcessProvider for ProcfileProvider {
    fn kind(&self) -> &str {
        "procfile"
    }

    fn display_name(&self) -> &str {
        "Procfile"
    }

    fn detect(&self, dir: &Path, manifest: Option<&Value>) -> Option<DetectedApp> {
        // 1. manifest kind: "procfile" → direct match
        if let Some(m) = manifest {
            if m.get("kind").and_then(|v| v.as_str()) == Some("procfile") {
                return Some(DetectedApp {
                    kind: "procfile".into(),
                    meta: Value::Null,
                });
            }
        }

        // 2. Read Procfile.dev (preferred) or Procfile
        let content = read_procfile(dir)?;

        // 3. Must have a "web" process type
        if has_web_process(&content) {
            debug!(dir = %dir.display(), "detected Procfile with web process");
            Some(DetectedApp {
                kind: "procfile".into(),
                meta: Value::Null,
            })
        } else {
            None
        }
    }

    fn resolve(&self, app: &ManagedApp) -> anyhow::Result<ProcessSpec> {
        let root = &app.root;

        // 1. manifest command override
        if let Some(manifest) = &app.manifest {
            if let Some(cmd) = manifest.get("command").and_then(|v| v.as_str()) {
                let port = resolve_port(&app.env_overrides)?;
                let mut env = HashMap::new();
                env.insert("PORT".to_string(), port.to_string());
                env.extend(app.env_overrides.clone());
                return Ok(ProcessSpec {
                    command: PathBuf::new(),
                    args: vec![cmd.to_string()],
                    env,
                    working_dir: root.clone(),
                    listen_target: ListenTarget::Tcp {
                        host: "127.0.0.1".to_string(),
                        port,
                    },
                });
            }
        }

        // 2. Read Procfile.dev / Procfile
        let content = read_procfile(root)
            .ok_or_else(|| anyhow::anyhow!("no Procfile found in {}", root.display()))?;

        // 3. Parse and extract web process
        let procs = procfile::parse(&content)
            .map_err(|e| anyhow::anyhow!("failed to parse Procfile: {e}"))?;
        let web = procs
            .get("web")
            .ok_or_else(|| anyhow::anyhow!("Procfile has no web process type"))?;

        // 4. Build the full command string: command + options
        let full_command = if web.options.is_empty() {
            web.command.to_string()
        } else {
            format!("{} {}", web.command, web.options.join(" "))
        };

        // 5. Allocate port + PORT env
        let port = resolve_port(&app.env_overrides)?;
        let mut env = HashMap::new();
        env.insert("PORT".to_string(), port.to_string());
        env.extend(app.env_overrides.clone());

        debug!(
            root = %root.display(),
            command = %full_command,
            port,
            "resolved Procfile web process"
        );

        Ok(ProcessSpec {
            command: PathBuf::new(),
            args: vec![full_command],
            env,
            working_dir: root.clone(),
            listen_target: ListenTarget::Tcp {
                host: "127.0.0.1".to_string(),
                port,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "coulson-test-procfile-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detect_procfile_with_web() {
        let dir = temp_dir("detect-web");
        fs::write(
            dir.join("Procfile"),
            "web: bundle exec rails server -p $PORT\nworker: bundle exec sidekiq",
        )
        .unwrap();
        let p = ProcfileProvider;
        assert!(p.detect(&dir, None).is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_procfile_dev_preferred() {
        let dir = temp_dir("detect-dev");
        fs::write(dir.join("Procfile"), "web: rails s").unwrap();
        fs::write(dir.join("Procfile.dev"), "web: bin/dev").unwrap();
        let p = ProcfileProvider;
        assert!(p.detect(&dir, None).is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_procfile_no_web() {
        let dir = temp_dir("detect-no-web");
        fs::write(dir.join("Procfile"), "worker: bundle exec sidekiq").unwrap();
        let p = ProcfileProvider;
        assert!(p.detect(&dir, None).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_no_procfile() {
        let dir = temp_dir("detect-none");
        let p = ProcfileProvider;
        assert!(p.detect(&dir, None).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_by_manifest_kind() {
        let dir = temp_dir("detect-manifest");
        let manifest = serde_json::json!({ "kind": "procfile" });
        let p = ProcfileProvider;
        assert!(p.detect(&dir, Some(&manifest)).is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_procfile_web() {
        let dir = temp_dir("resolve-web");
        fs::write(
            dir.join("Procfile"),
            "web: bundle exec rails server -p $PORT",
        )
        .unwrap();
        let p = ProcfileProvider;
        let app = ManagedApp {
            name: "myapp".into(),
            root: dir.clone(),
            kind: "procfile".into(),
            manifest: None,
            env_overrides: Default::default(),
            socket_dir: dir.clone(),
        };
        let spec = p.resolve(&app).unwrap();

        assert_eq!(spec.args.len(), 1);
        assert!(spec.args[0].contains("bundle exec rails server -p $PORT"));
        assert!(spec.env.contains_key("PORT"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_procfile_dev_preferred() {
        let dir = temp_dir("resolve-dev");
        fs::write(dir.join("Procfile"), "web: rails s").unwrap();
        fs::write(dir.join("Procfile.dev"), "web: bin/dev").unwrap();
        let p = ProcfileProvider;
        let app = ManagedApp {
            name: "myapp".into(),
            root: dir.clone(),
            kind: "procfile".into(),
            manifest: None,
            env_overrides: Default::default(),
            socket_dir: dir.clone(),
        };
        let spec = p.resolve(&app).unwrap();

        assert!(spec.args[0].contains("bin/dev"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_command_override() {
        let dir = temp_dir("resolve-cmd");
        let manifest = serde_json::json!({ "kind": "procfile", "command": "my-custom-server" });
        let p = ProcfileProvider;
        let app = ManagedApp {
            name: "myapp".into(),
            root: dir.clone(),
            kind: "procfile".into(),
            manifest: Some(serde_json::to_value(&manifest).unwrap()),
            env_overrides: Default::default(),
            socket_dir: dir.clone(),
        };
        let spec = p.resolve(&app).unwrap();

        assert!(spec.args[0].contains("my-custom-server"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_companion_worker() {
        let dir = temp_dir("resolve-companion");
        fs::write(
            dir.join("Procfile"),
            "web: rails s -p $PORT\nworker: bundle exec sidekiq",
        )
        .unwrap();
        let p = ProcfileProvider;
        let app = ManagedApp {
            name: "myapp".into(),
            root: dir.clone(),
            kind: "procfile".into(),
            manifest: None,
            env_overrides: Default::default(),
            socket_dir: dir.clone(),
        };
        let spec = p.resolve_companion(&app, "worker").unwrap();

        assert_eq!(spec.args.len(), 1);
        assert!(spec.args[0].contains("bundle exec sidekiq"));
        assert!(!spec.env.contains_key("PORT"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_companion_missing_type() {
        let dir = temp_dir("resolve-companion-missing");
        fs::write(dir.join("Procfile"), "web: rails s").unwrap();
        let p = ProcfileProvider;
        let app = ManagedApp {
            name: "myapp".into(),
            root: dir.clone(),
            kind: "procfile".into(),
            manifest: None,
            env_overrides: Default::default(),
            socket_dir: dir.clone(),
        };
        assert!(p.resolve_companion(&app, "worker").is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
