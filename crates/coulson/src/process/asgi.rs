use std::path::{Path, PathBuf};

use anyhow::bail;
use serde_json::Value;
use tracing::warn;

use super::provider::{DetectedApp, ListenTarget, ManagedApp, ProcessProvider, ProcessSpec};

pub struct AsgiProvider;

impl ProcessProvider for AsgiProvider {
    fn kind(&self) -> &str {
        "asgi"
    }

    fn display_name(&self) -> &str {
        "Python ASGI"
    }

    fn detect(&self, dir: &Path, manifest: Option<&Value>) -> Option<DetectedApp> {
        // If manifest explicitly says kind=asgi, trust it.
        if let Some(m) = manifest {
            if m.get("kind").and_then(|v| v.as_str()) == Some("asgi") {
                return Some(DetectedApp {
                    kind: "asgi".into(),
                    meta: Value::Null,
                });
            }
        }

        // Convention-based detection:
        // has (app.py || main.py) AND (pyproject.toml || requirements.txt)
        let has_entry = dir.join("app.py").exists() || dir.join("main.py").exists();
        let has_deps = dir.join("pyproject.toml").exists() || dir.join("requirements.txt").exists();
        if has_entry && has_deps {
            Some(DetectedApp {
                kind: "asgi".into(),
                meta: Value::Null,
            })
        } else {
            None
        }
    }

    fn resolve(&self, app: &ManagedApp) -> anyhow::Result<ProcessSpec> {
        let module = detect_module(&app.root, app.manifest.as_ref())?;
        let binary = find_uvicorn(&app.root, app.manifest.as_ref())?;
        let socket_path = app.socket_path();

        let args = vec![
            module,
            "--uds".into(),
            socket_path.to_string_lossy().to_string(),
        ];

        let mut env = std::collections::HashMap::new();
        // Force unbuffered stdio so uvicorn startup messages and per-request
        // access logs hit the log file immediately instead of sitting in
        // Python's block buffer (which kicks in when stdout is a file).
        env.insert("PYTHONUNBUFFERED".into(), "1".into());
        // uvicorn's Click CLI enables `auto_envvar_prefix="UVICORN"`, so any
        // flag can be toggled via `UVICORN_<FLAG>` env vars the user sets in
        // `.coulson.toml` / env_overrides (e.g. `UVICORN_RELOAD=true`,
        // `UVICORN_LOG_LEVEL=debug`). No need to special-case individual
        // flags here.
        env.extend(app.env_overrides.clone());

        Ok(ProcessSpec {
            command: binary,
            args,
            env,
            working_dir: app.root.clone(),
            listen_target: ListenTarget::Uds(socket_path),
        })
    }
}

/// Detect the ASGI module to pass to uvicorn.
/// Priority: manifest `module` field > app.py > main.py
fn detect_module(root: &Path, manifest: Option<&Value>) -> anyhow::Result<String> {
    if let Some(m) = manifest {
        if let Some(module) = m.get("module").and_then(|v| v.as_str()) {
            return Ok(module.to_string());
        }
    }

    if root.join("app.py").exists() {
        return Ok("app:app".to_string());
    }
    if root.join("main.py").exists() {
        return Ok("main:app".to_string());
    }

    bail!(
        "cannot detect ASGI module in {}: no app.py or main.py found",
        root.display()
    )
}

/// Find uvicorn binary for the given app directory.
///
/// Resolution order:
///   1. manifest `command` field → use as binary path
///   2. Search .venv/bin/ → venv/bin/ → PATH
///
/// If manifest `server` is set to something other than "uvicorn", warn and
/// search for uvicorn anyway (granian support was removed).
fn find_uvicorn(root: &Path, manifest: Option<&Value>) -> anyhow::Result<PathBuf> {
    if let Some(m) = manifest {
        if let Some(server) = m.get("server").and_then(|v| v.as_str()) {
            if server != "uvicorn" {
                warn!(
                    server,
                    "only uvicorn is supported as ASGI server, ignoring server={server}"
                );
            }
        }

        if let Some(cmd) = m.get("command").and_then(|v| v.as_str()) {
            let path = PathBuf::from(cmd);
            if path.exists() {
                return Ok(path);
            }
            warn!(
                command = cmd,
                ".coulson.toml command not found, searching defaults"
            );
        }
    }

    find_server_binary(root, "uvicorn")
}

/// Look for a server binary in the app's virtualenv, then in PATH.
fn find_server_binary(root: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let candidates = [
        root.join(format!(".venv/bin/{name}")),
        root.join(format!("venv/bin/{name}")),
    ];
    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }
    if let Some(path) = super::provider::which_binary(name) {
        return Ok(path);
    }
    bail!("{name} not found in .venv/bin/, venv/bin/, or PATH")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a unique temp directory for a test case.
    fn temp_app_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("coulson-test-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Place a dummy binary in `.venv/bin/<name>`.
    fn place_venv_binary(root: &Path, name: &str) {
        let bin_dir = root.join(".venv/bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join(name), "#!/bin/sh\n").unwrap();
    }

    /// Place a dummy binary in `venv/bin/<name>` (non-dot variant).
    fn place_venv_nondot_binary(root: &Path, name: &str) {
        let bin_dir = root.join("venv/bin");
        fs::create_dir_all(&bin_dir).unwrap();
        fs::write(bin_dir.join(name), "#!/bin/sh\n").unwrap();
    }

    #[test]
    fn detect_asgi_by_convention() {
        let root = temp_app_dir("detect-asgi-conv");
        fs::write(root.join("app.py"), "").unwrap();
        fs::write(root.join("requirements.txt"), "").unwrap();
        let provider = AsgiProvider;
        let detected = provider.detect(&root, None);
        assert!(detected.is_some());
        assert_eq!(detected.unwrap().kind, "asgi");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_asgi_by_manifest() {
        let root = temp_app_dir("detect-asgi-manifest");
        let provider = AsgiProvider;
        let manifest = serde_json::json!({ "kind": "asgi" });
        let detected = provider.detect(&root, Some(&manifest));
        assert!(detected.is_some());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_asgi_no_match() {
        let root = temp_app_dir("detect-asgi-nomatch");
        fs::write(root.join("index.html"), "").unwrap();
        let provider = AsgiProvider;
        assert!(provider.detect(&root, None).is_none());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn finds_uvicorn_in_dot_venv() {
        let root = temp_app_dir("find-uvicorn-dotvenv");
        place_venv_binary(&root, "uvicorn");
        let result = find_server_binary(&root, "uvicorn").unwrap();
        assert_eq!(result, root.join(".venv/bin/uvicorn"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn prefers_dot_venv_over_venv() {
        let root = temp_app_dir("prefer-dotvenv");
        place_venv_binary(&root, "uvicorn");
        place_venv_nondot_binary(&root, "uvicorn");
        let result = find_server_binary(&root, "uvicorn").unwrap();
        assert_eq!(result, root.join(".venv/bin/uvicorn"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn falls_back_to_venv_nondot() {
        let root = temp_app_dir("fallback-venv");
        place_venv_nondot_binary(&root, "uvicorn");
        let result = find_server_binary(&root, "uvicorn").unwrap();
        assert_eq!(result, root.join("venv/bin/uvicorn"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn find_uvicorn_from_manifest_command() {
        let root = temp_app_dir("manifest-cmd-uvicorn");
        place_venv_binary(&root, "uvicorn");
        let custom = root.join(".venv/bin/uvicorn");
        let manifest = serde_json::json!({"command": custom.to_string_lossy().as_ref()});
        let result = find_uvicorn(&root, Some(&manifest)).unwrap();
        assert_eq!(result, custom);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn find_uvicorn_ignores_granian_server_field() {
        let root = temp_app_dir("manifest-granian-ignored");
        place_venv_binary(&root, "uvicorn");
        let manifest = serde_json::json!({"server": "granian"});
        let result = find_uvicorn(&root, Some(&manifest)).unwrap();
        assert_eq!(result, root.join(".venv/bin/uvicorn"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn find_uvicorn_no_manifest() {
        let root = temp_app_dir("no-manifest-uvicorn");
        place_venv_binary(&root, "uvicorn");
        let result = find_uvicorn(&root, None).unwrap();
        assert_eq!(result, root.join(".venv/bin/uvicorn"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_module_from_app_py() {
        let root = temp_app_dir("module-app-py");
        fs::write(root.join("app.py"), "").unwrap();
        assert_eq!(detect_module(&root, None).unwrap(), "app:app");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_module_from_main_py() {
        let root = temp_app_dir("module-main-py");
        fs::write(root.join("main.py"), "").unwrap();
        assert_eq!(detect_module(&root, None).unwrap(), "main:app");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_module_prefers_app_over_main() {
        let root = temp_app_dir("module-both");
        fs::write(root.join("app.py"), "").unwrap();
        fs::write(root.join("main.py"), "").unwrap();
        assert_eq!(detect_module(&root, None).unwrap(), "app:app");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_module_from_manifest() {
        let root = temp_app_dir("module-manifest");
        let manifest = serde_json::json!({"module": "mymod:create_app"});
        assert_eq!(
            detect_module(&root, Some(&manifest)).unwrap(),
            "mymod:create_app"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_module_manifest_overrides_files() {
        let root = temp_app_dir("module-manifest-override");
        fs::write(root.join("app.py"), "").unwrap();
        let manifest = serde_json::json!({"module": "custom:factory"});
        assert_eq!(
            detect_module(&root, Some(&manifest)).unwrap(),
            "custom:factory"
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn detect_module_fails_with_no_entry_point() {
        let root = temp_app_dir("module-none");
        assert!(detect_module(&root, None).is_err());
        fs::remove_dir_all(&root).ok();
    }

    fn make_managed_app(root: &Path, env: Vec<(&str, &str)>) -> ManagedApp {
        let socket_dir = root.join("sockets");
        fs::create_dir_all(&socket_dir).unwrap();
        ManagedApp {
            name: "testapp".into(),
            root: root.to_path_buf(),
            kind: "asgi".into(),
            manifest: None,
            env_overrides: env.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
            socket_dir,
        }
    }

    #[test]
    fn uvicorn_env_overrides_are_preserved() {
        // uvicorn supports `UVICORN_*` env vars natively via Click's
        // `auto_envvar_prefix`. Make sure the provider just passes them
        // through without stripping or translating.
        let root = temp_app_dir("uvicorn-env-passthrough");
        fs::write(root.join("app.py"), "").unwrap();
        place_venv_binary(&root, "uvicorn");
        let app = make_managed_app(
            &root,
            vec![("UVICORN_RELOAD", "true"), ("UVICORN_LOG_LEVEL", "debug")],
        );
        let spec = AsgiProvider.resolve(&app).unwrap();
        assert_eq!(
            spec.env.get("UVICORN_RELOAD").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            spec.env.get("UVICORN_LOG_LEVEL").map(String::as_str),
            Some("debug")
        );
        assert!(!spec.args.contains(&"--reload".to_string()));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn allocate_port_returns_nonzero() {
        let port = super::super::provider::allocate_port().unwrap();
        assert!(port > 0);
    }
}
