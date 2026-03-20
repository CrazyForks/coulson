use std::path::{Path, PathBuf};

use serde_json::Value;
use tracing::debug;

use super::provider::{
    resolve_port, DetectedApp, ListenTarget, ManagedApp, ProcessProvider, ProcessSpec,
};

/// Compose files in priority order.
const COMPOSE_FILES: &[&str] = &[
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
];

/// Docker Compose provider — manages containerized applications.
///
/// Detection: directory contains a Compose file (`compose.yml`, `docker-compose.yml`, etc.).
/// Only Docker Compose is supported (not bare `docker run`).
pub struct DockerProvider;

/// Find the first matching compose file in the directory.
fn find_compose_file(dir: &Path) -> Option<&'static str> {
    COMPOSE_FILES.iter().find(|f| dir.join(f).exists()).copied()
}

/// Find the `docker` binary in PATH.
fn find_docker_binary() -> anyhow::Result<PathBuf> {
    super::provider::which_binary("docker")
        .ok_or_else(|| anyhow::anyhow!("docker not found in PATH"))
}

/// Determine which compose service to proxy from the manifest `service` field.
fn determine_service(manifest: Option<&Value>) -> Option<String> {
    manifest
        .and_then(|m| m.get("service"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Determine the compose file from the manifest `compose_file` field,
/// falling back to auto-detection.
fn determine_compose_file(dir: &Path, manifest: Option<&Value>) -> anyhow::Result<String> {
    if let Some(cf) = manifest
        .and_then(|m| m.get("compose_file"))
        .and_then(|v| v.as_str())
    {
        let path = dir.join(cf);
        if path.exists() {
            return Ok(cf.to_string());
        }
        anyhow::bail!(
            "compose_file '{}' specified in .coulson.toml not found in {}",
            cf,
            dir.display()
        );
    }
    find_compose_file(dir)
        .map(|s| s.to_string())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no compose file found in {} (tried: {})",
                dir.display(),
                COMPOSE_FILES.join(", ")
            )
        })
}

/// Try to discover the host port from compose config using `docker compose config --format json`.
/// Returns the first host port mapping found for the target service (or any service if none specified).
fn discover_port_from_compose(
    docker: &Path,
    dir: &Path,
    compose_file: &str,
    service: Option<&str>,
) -> Option<u16> {
    let output = std::process::Command::new(docker)
        .args(["compose", "-f", compose_file, "config", "--format", "json"])
        .current_dir(dir)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let config: Value = serde_json::from_slice(&output.stdout).ok()?;
    let services = config.get("services")?.as_object()?;

    // If service is specified, look only at that service; otherwise check all services.
    let service_configs: Vec<&Value> = if let Some(svc) = service {
        services.get(svc).into_iter().collect()
    } else {
        services.values().collect()
    };

    for svc_config in service_configs {
        if let Some(ports) = svc_config.get("ports").and_then(|p| p.as_array()) {
            for port_entry in ports {
                // `docker compose config --format json` returns ports as objects:
                // {"published": 8080, "target": 80, "protocol": "tcp", ...}
                // or with ${PORT} as {"published": "$PORT", ...}
                if let Some(published) = port_entry.get("published") {
                    if let Some(p) = published.as_u64().and_then(|v| u16::try_from(v).ok()) {
                        if p > 0 {
                            return Some(p);
                        }
                    }
                }
            }
        }
    }
    None
}

impl ProcessProvider for DockerProvider {
    fn kind(&self) -> &str {
        "docker"
    }

    fn display_name(&self) -> &str {
        "Docker Compose"
    }

    fn detect(&self, dir: &Path, manifest: Option<&Value>) -> Option<DetectedApp> {
        if let Some(m) = manifest {
            if m.get("kind").and_then(|v| v.as_str()) == Some("docker") {
                let compose_file = determine_compose_file(dir, manifest)
                    .ok()
                    .unwrap_or_default();
                return Some(DetectedApp {
                    kind: "docker".into(),
                    meta: serde_json::json!({ "compose_file": compose_file }),
                });
            }
        }

        if let Some(f) = find_compose_file(dir) {
            return Some(DetectedApp {
                kind: "docker".into(),
                meta: serde_json::json!({ "compose_file": f }),
            });
        }

        None
    }

    fn resolve(&self, app: &ManagedApp) -> anyhow::Result<ProcessSpec> {
        let root = &app.root;
        let docker = find_docker_binary()?;
        let compose_file = determine_compose_file(root, app.manifest.as_ref())?;
        let service = determine_service(app.manifest.as_ref());

        // Port discovery priority:
        // 1. Manifest `port` field (explicit override)
        // 2. env_overrides PORT
        // 3. Parse compose file port mappings
        // 4. Allocate port + inject PORT env var
        let manifest_port = app
            .manifest
            .as_ref()
            .and_then(|m| m.get("port"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u16::try_from(v).ok());

        let port = if let Some(p) = manifest_port {
            p
        } else if let Some(p) = app
            .env_overrides
            .get("PORT")
            .and_then(|v| v.parse::<u16>().ok())
            .filter(|p| *p > 0)
        {
            p
        } else if let Some(p) =
            discover_port_from_compose(&docker, root, &compose_file, service.as_deref())
        {
            p
        } else {
            resolve_port(&app.env_overrides)?
        };

        let mut args = vec![
            "compose".to_string(),
            "-f".to_string(),
            compose_file.clone(),
            "-p".to_string(),
            app.name.clone(),
            "up".to_string(),
            "-d".to_string(),
            "--build".to_string(),
        ];

        // If a specific service is specified, pass it to `docker compose up`
        if let Some(ref svc) = service {
            args.push(svc.clone());
        }

        let mut env = std::collections::HashMap::new();
        env.insert("PORT".to_string(), port.to_string());
        env.extend(app.env_overrides.clone());

        debug!(
            root = %root.display(),
            compose_file,
            port,
            service = service.as_deref().unwrap_or("(all)"),
            "resolved Docker Compose app"
        );

        Ok(ProcessSpec {
            command: docker,
            args,
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
            "coulson-test-docker-{label}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn detect_docker_compose_yml() {
        let dir = temp_dir("detect-compose-yml");
        fs::write(dir.join("docker-compose.yml"), "version: '3'").unwrap();
        let p = DockerProvider;
        let result = p.detect(&dir, None);
        assert!(result.is_some());
        let meta = result.unwrap().meta;
        assert_eq!(
            meta.get("compose_file").and_then(|v| v.as_str()),
            Some("docker-compose.yml")
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_compose_yaml() {
        let dir = temp_dir("detect-compose-yaml");
        fs::write(dir.join("compose.yaml"), "services:").unwrap();
        let p = DockerProvider;
        let result = p.detect(&dir, None);
        assert!(result.is_some());
        let meta = result.unwrap().meta;
        assert_eq!(
            meta.get("compose_file").and_then(|v| v.as_str()),
            Some("compose.yaml")
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_compose_yml() {
        let dir = temp_dir("detect-compose-yml-short");
        fs::write(dir.join("compose.yml"), "services:").unwrap();
        let p = DockerProvider;
        assert!(p.detect(&dir, None).is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_dockerfile_only_not_matched() {
        let dir = temp_dir("detect-dockerfile-only");
        fs::write(dir.join("Dockerfile"), "FROM node:20").unwrap();
        let p = DockerProvider;
        assert!(
            p.detect(&dir, None).is_none(),
            "bare Dockerfile without compose should not be detected"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_docker_no_match() {
        let dir = temp_dir("detect-nomatch");
        fs::write(dir.join("app.py"), "").unwrap();
        let p = DockerProvider;
        assert!(p.detect(&dir, None).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn detect_by_manifest_kind() {
        let dir = temp_dir("detect-manifest-kind");
        fs::write(dir.join("compose.yml"), "services:").unwrap();
        let manifest = serde_json::json!({ "kind": "docker" });
        let p = DockerProvider;
        assert!(p.detect(&dir, Some(&manifest)).is_some());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_compose_file_priority() {
        let dir = temp_dir("compose-priority");
        fs::write(dir.join("compose.yml"), "").unwrap();
        fs::write(dir.join("docker-compose.yml"), "").unwrap();
        // docker-compose.yml has higher priority
        assert_eq!(find_compose_file(&dir), Some("docker-compose.yml"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn find_compose_file_none() {
        let dir = temp_dir("compose-none");
        assert_eq!(find_compose_file(&dir), None);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn determine_service_from_manifest() {
        let manifest = serde_json::json!({ "service": "web" });
        assert_eq!(determine_service(Some(&manifest)), Some("web".to_string()));
    }

    #[test]
    fn determine_service_none() {
        let manifest = serde_json::json!({});
        assert_eq!(determine_service(Some(&manifest)), None);
        assert_eq!(determine_service(None), None);
    }

    #[test]
    fn determine_compose_file_from_manifest() {
        let dir = temp_dir("compose-file-manifest");
        fs::write(dir.join("docker-compose.dev.yml"), "").unwrap();
        let manifest = serde_json::json!({ "compose_file": "docker-compose.dev.yml" });
        let result = determine_compose_file(&dir, Some(&manifest));
        assert_eq!(result.unwrap(), "docker-compose.dev.yml");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn determine_compose_file_manifest_missing() {
        let dir = temp_dir("compose-file-manifest-missing");
        let manifest = serde_json::json!({ "compose_file": "nonexistent.yml" });
        let result = determine_compose_file(&dir, Some(&manifest));
        assert!(result.is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn determine_compose_file_auto_detect() {
        let dir = temp_dir("compose-file-auto");
        fs::write(dir.join("compose.yml"), "").unwrap();
        let result = determine_compose_file(&dir, None);
        assert_eq!(result.unwrap(), "compose.yml");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_with_port_override() {
        let dir = temp_dir("resolve-port-override");
        fs::write(dir.join("compose.yml"), "services:\n  web:\n    build: .").unwrap();
        let manifest = serde_json::json!({ "kind": "docker", "port": 3000 });
        let p = DockerProvider;
        let app = ManagedApp {
            name: "myapp".into(),
            root: dir.clone(),
            kind: "docker".into(),
            manifest: Some(manifest),
            env_overrides: Default::default(),
            socket_dir: dir.clone(),
        };
        // resolve will fail if docker is not in PATH, which is fine for CI
        match p.resolve(&app) {
            Ok(spec) => {
                assert!(spec.args.contains(&"compose".to_string()));
                assert!(spec.args.contains(&"up".to_string()));
                assert!(spec.args.contains(&"-d".to_string()));
                if let ListenTarget::Tcp { port, .. } = &spec.listen_target {
                    assert_eq!(*port, 3000);
                } else {
                    panic!("expected TCP listen target");
                }
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("docker not found"), "unexpected error: {msg}");
            }
        }
        fs::remove_dir_all(&dir).ok();
    }
}
