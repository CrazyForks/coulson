use std::fmt;
use std::str::FromStr;

use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppId(pub i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppKind {
    Static,
    Rack,
    Asgi,
    Node,
    Procfile,
    Container,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DomainName(pub String);

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("domain must end with .{0}")]
    InvalidSuffix(String),
    #[error("invalid domain label")]
    InvalidLabel,
}

impl DomainName {
    pub fn parse(input: &str, suffix: &str) -> Result<Self, DomainError> {
        let input = input.trim().to_ascii_lowercase();
        if !input.ends_with(&format!(".{suffix}")) {
            return Err(DomainError::InvalidSuffix(suffix.to_string()));
        }

        let labels = input.trim_end_matches(&format!(".{suffix}"));
        if labels.is_empty() {
            return Err(DomainError::InvalidLabel);
        }
        let re = Regex::new(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$").expect("regex compile");
        if let Some(rest) = labels.strip_prefix("*.") {
            if rest.is_empty() {
                return Err(DomainError::InvalidLabel);
            }
            for label in rest.split('.') {
                if label.is_empty() || !re.is_match(label) {
                    return Err(DomainError::InvalidLabel);
                }
            }
            return Ok(Self(input));
        }

        for label in labels.split('.') {
            if label.is_empty() || !re.is_match(label) {
                return Err(DomainError::InvalidLabel);
            }
        }

        Ok(Self(input))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    #[default]
    None,
    Quick,
    Named,
    Global,
}

impl TunnelMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Quick => "quick",
            Self::Named => "named",
            Self::Global => "global",
        }
    }

    pub fn is_exposed(&self) -> bool {
        !matches!(self, Self::None)
    }
}

impl fmt::Display for TunnelMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TunnelMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "quick" => Ok(Self::Quick),
            "named" => Ok(Self::Named),
            "global" => Ok(Self::Global),
            other => Err(format!(
                "invalid tunnel_mode: {other}, must be none/global/quick/named"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackendTarget {
    Tcp {
        host: String,
        port: u16,
    },
    UnixSocket {
        path: String,
    },
    StaticDir {
        root: String,
    },
    Managed {
        app_id: i64,
        root: String,
        kind: String,
        name: String,
    },
}

impl BackendTarget {
    pub fn to_url_base(&self) -> String {
        match self {
            Self::Tcp { host, port } => format!("http://{host}:{port}"),
            Self::UnixSocket { path } => format!("unix://{path}"),
            Self::StaticDir { root } => format!("file://{root}"),
            Self::Managed { root, kind, .. } => format!("managed+{kind}://{root}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSpec {
    pub id: AppId,
    pub name: String,
    pub kind: AppKind,
    pub domain: DomainName,
    pub path_prefix: Option<String>,
    pub target: BackendTarget,
    pub timeout_ms: Option<u64>,
    pub cors_enabled: bool,
    pub force_https: bool,
    pub basic_auth_user: Option<String>,
    pub basic_auth_pass: Option<String>,
    pub spa_rewrite: bool,
    pub listen_port: Option<u16>,
    pub tunnel_url: Option<String>,
    pub tunnel_exposed: bool,
    pub tunnel_mode: TunnelMode,
    pub app_tunnel_id: Option<String>,
    pub app_tunnel_domain: Option<String>,
    pub app_tunnel_dns_id: Option<String>,
    pub app_tunnel_creds: Option<String>,
    pub inspect_enabled: bool,
    pub lan_access: bool,
    pub cname: Option<String>,
    pub fs_entry: Option<String>,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Runtime context needed to build URLs for an app.
pub struct UrlContext<'a> {
    pub http_port: u16,
    pub https_port: Option<u16>,
    pub use_default_http_port: bool,
    pub use_default_https_port: bool,
    pub domain_suffix: &'a str,
    pub global_tunnel_domain: Option<&'a str>,
}

/// Build HTTP/HTTPS URLs for a domain (localhost alias + primary + HTTPS).
/// This is the shared core used by both `AppSpec::urls()` and CLI output.
pub fn domain_urls(domain: &str, path: &str, ctx: &UrlContext<'_>) -> Vec<String> {
    let mut urls = Vec::new();

    // .localhost alias first (RFC 6761 — resolves to 127.0.0.1 without DNS)
    if ctx.domain_suffix != crate::config::LOCALHOST_SUFFIX {
        if let Some(prefix) = domain.strip_suffix(&format!(".{}", ctx.domain_suffix)) {
            let lh = format!("{prefix}.{}", crate::config::LOCALHOST_SUFFIX);
            urls.push(format_url(
                "http",
                &lh,
                ctx.http_port,
                path,
                ctx.use_default_http_port,
            ));
        }
    }

    // Primary HTTP URL
    urls.push(format_url(
        "http",
        domain,
        ctx.http_port,
        path,
        ctx.use_default_http_port,
    ));

    // HTTPS URL
    if let Some(hp) = ctx.https_port {
        urls.push(format_url(
            "https",
            domain,
            hp,
            path,
            ctx.use_default_https_port,
        ));
    }

    urls
}

impl AppSpec {
    /// Build all reachable URLs for this app.
    pub fn urls(&self, ctx: &UrlContext<'_>) -> Vec<String> {
        let path = self.path_prefix.as_deref().unwrap_or("/");
        let mut urls = domain_urls(&self.domain.0, path, ctx);

        // Tunnel URLs
        if self.tunnel_mode.is_exposed() {
            if let Some(ref td) = self.app_tunnel_domain {
                let href = format!("https://{td}");
                if !urls.contains(&href) {
                    urls.push(href);
                }
            }
        }
        if matches!(self.tunnel_mode, TunnelMode::Global) {
            if let Some(td) = ctx.global_tunnel_domain {
                let href = format!("https://{}.{td}", self.name);
                if !urls.contains(&href) {
                    urls.push(href);
                }
            }
        }
        if let Some(ref url) = self.tunnel_url {
            if !urls.contains(url) {
                urls.push(url.clone());
            }
        }

        urls
    }
}

pub fn format_url(scheme: &str, host: &str, port: u16, path: &str, use_default: bool) -> String {
    let default_port = if scheme == "https" { 443 } else { 80 };
    if use_default || port == default_port {
        format!("{scheme}://{host}{path}")
    } else {
        format!("{scheme}://{host}:{port}{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_test_domain() {
        let domain =
            DomainName::parse("myapp.coulson.local", "coulson.local").expect("valid domain");
        assert_eq!(domain.0, "myapp.coulson.local");
    }

    #[test]
    fn rejects_invalid_suffix() {
        let err = DomainName::parse("myapp.test", "coulson.local").expect_err("must fail");
        assert!(matches!(err, DomainError::InvalidSuffix(_)));
    }

    #[test]
    fn accepts_subdomain_labels() {
        let domain = DomainName::parse("www.myapp.coulson.local", "coulson.local").expect("valid");
        assert_eq!(domain.0, "www.myapp.coulson.local");
    }

    #[test]
    fn accepts_wildcard_subdomain() {
        let domain = DomainName::parse("*.myapp.coulson.local", "coulson.local").expect("valid");
        assert_eq!(domain.0, "*.myapp.coulson.local");
    }

    #[test]
    fn wildcard_must_have_suffix_labels() {
        let err = DomainName::parse("*.coulson.local", "coulson.local").expect_err("must fail");
        assert!(matches!(err, DomainError::InvalidLabel));
    }
}
