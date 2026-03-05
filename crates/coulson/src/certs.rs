use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use parking_lot::RwLock;
use pingora::listeners::TlsAccept;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::NameType;
use pingora::tls::x509::X509;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use tracing::{debug, info, warn};

use crate::config::LOCALHOST_SUFFIX;

#[cfg(unix)]
fn write_private_key(path: &Path, data: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to create key file: {}", path.display()))?;
    f.write_all(data.as_bytes())
        .with_context(|| format!("failed to write key file: {}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to set key file permissions: {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_key(path: &Path, data: &str) -> anyhow::Result<()> {
    fs::write(path, data).with_context(|| format!("failed to write key file: {}", path.display()))
}

pub struct CertManager {
    ca_cert_path: PathBuf,
    ca_key_pem: String,
    ca_cert_pem: String,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
}

impl CertManager {
    pub fn ensure(certs_dir: &Path, domain_suffix: &str) -> anyhow::Result<Self> {
        fs::create_dir_all(certs_dir)
            .with_context(|| format!("failed to create certs dir: {}", certs_dir.display()))?;

        let ca_cert_path = certs_dir.join("ca.crt");
        let ca_key_path = certs_dir.join("ca.key");
        let server_cert_path = certs_dir.join("server.crt");
        let server_key_path = certs_dir.join("server.key");
        let suffix_meta_path = certs_dir.join("server.suffix");

        // Generate CA if not present
        let (ca_key_pem, ca_cert_pem, ca_regenerated) = if ca_cert_path.exists()
            && ca_key_path.exists()
        {
            let cert_pem = fs::read_to_string(&ca_cert_path).context("failed to read CA cert")?;
            let key_pem = fs::read_to_string(&ca_key_path).context("failed to read CA key")?;
            (key_pem, cert_pem, false)
        } else {
            info!("generating self-signed CA certificate");
            let ca_params = build_ca_params()?;
            let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let cert = ca_params.self_signed(&ca_key)?;
            let cert_pem = cert.pem();
            let key_pem = ca_key.serialize_pem();
            fs::write(&ca_cert_path, &cert_pem).context("failed to write CA cert")?;
            write_private_key(&ca_key_path, &key_pem)?;
            (key_pem, cert_pem, true)
        };

        // Re-sign wildcard server cert for *.{domain_suffix} if needed
        let need_server_cert = ca_regenerated
            || !server_cert_path.exists()
            || !server_key_path.exists()
            || !suffix_matches(&suffix_meta_path, domain_suffix);

        if need_server_cert {
            info!(
                suffix = domain_suffix,
                "generating wildcard server certificate"
            );
            let (cert_pem, key_pem) =
                generate_wildcard_cert(&ca_key_pem, &ca_cert_pem, domain_suffix)?;
            fs::write(&server_cert_path, &cert_pem).context("failed to write server cert")?;
            write_private_key(&server_key_path, &key_pem)?;
            fs::write(&suffix_meta_path, domain_suffix)
                .context("failed to write suffix metadata")?;
        }

        Ok(Self {
            ca_cert_path,
            ca_key_pem,
            ca_cert_pem,
            server_cert_path,
            server_key_path,
        })
    }

    pub fn ca_path(&self) -> &str {
        self.ca_cert_path.to_str().unwrap_or("")
    }

    pub fn cert_path(&self) -> &str {
        self.server_cert_path.to_str().unwrap_or("")
    }

    pub fn key_path(&self) -> &str {
        self.server_key_path.to_str().unwrap_or("")
    }

    /// Build an `SniCertProvider` that uses the wildcard cert for the
    /// primary suffix and generates per-hostname certs on demand for
    /// `.localhost` domains (since `*.localhost` wildcards are rejected
    /// by browsers per RFC 6761 / PSL).
    pub fn build_sni_provider(&self, domain_suffix: &str) -> anyhow::Result<Arc<SniCertProvider>> {
        let cert_pem = fs::read(self.cert_path()).context("failed to read server cert")?;
        let key_pem = fs::read(self.key_path()).context("failed to read server key")?;
        let ca_pem = fs::read(self.ca_path()).context("failed to read CA cert")?;

        let wildcard_cert =
            X509::from_pem(&cert_pem).context("failed to parse wildcard cert PEM")?;
        let wildcard_key =
            PKey::private_key_from_pem(&key_pem).context("failed to parse wildcard key PEM")?;
        let ca_cert = X509::from_pem(&ca_pem).context("failed to parse CA cert PEM")?;

        Ok(Arc::new(SniCertProvider {
            domain_suffix: domain_suffix.to_string(),
            wildcard_cert,
            wildcard_key,
            ca_cert,
            ca_key_pem: self.ca_key_pem.clone(),
            ca_cert_pem: self.ca_cert_pem.clone(),
            cert_cache: RwLock::new(HashMap::new()),
        }))
    }
}

/// Provides TLS certificates per SNI hostname via pingora's `TlsAccept` callback.
///
/// - `*.{domain_suffix}` requests → served by the pre-generated wildcard cert
/// - `foo.localhost` requests → cert generated on demand and cached
pub struct SniCertProvider {
    domain_suffix: String,
    wildcard_cert: X509,
    wildcard_key: PKey<Private>,
    ca_cert: X509,
    ca_key_pem: String,
    ca_cert_pem: String,
    cert_cache: RwLock<HashMap<String, (X509, PKey<Private>)>>,
}

#[async_trait]
impl TlsAccept for SniCertProvider {
    async fn certificate_callback(&self, ssl: &mut pingora::protocols::tls::TlsRef) {
        let sni = match ssl.servername(NameType::HOST_NAME) {
            Some(name) => name.to_string(),
            None => return self.set_wildcard(ssl),
        };
        let suffix_dot = format!(".{}", self.domain_suffix);

        // Single-level subdomain under primary suffix → wildcard cert
        if sni.ends_with(&suffix_dot) || sni == self.domain_suffix {
            let prefix = sni.strip_suffix(&suffix_dot).unwrap_or("");
            if !prefix.contains('.') {
                return self.set_wildcard(ssl);
            }
            // Multi-level subdomain — generate per-hostname cert
            return self.set_on_demand(ssl, &sni);
        }

        // .localhost → per-hostname cert (on demand)
        if sni.ends_with(&format!(".{LOCALHOST_SUFFIX}")) || sni == LOCALHOST_SUFFIX {
            return self.set_on_demand(ssl, &sni);
        }

        // Unknown domain — use wildcard as best effort
        self.set_wildcard(ssl);
    }
}

/// Cloneable wrapper so we can create multiple `TlsAcceptCallbacks` from one
/// shared `SniCertProvider` (needed for v4 + v6 listeners).
pub struct SniCallback(pub Arc<SniCertProvider>);

impl Clone for SniCallback {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[async_trait]
impl TlsAccept for SniCallback {
    async fn certificate_callback(&self, ssl: &mut pingora::protocols::tls::TlsRef) {
        self.0.certificate_callback(ssl).await;
    }
}

impl SniCertProvider {
    /// Set the pre-loaded wildcard cert + CA chain on the SSL connection.
    fn set_wildcard(&self, ssl: &mut pingora::protocols::tls::TlsRef) {
        if let Err(e) = ext::ssl_use_certificate(ssl, &self.wildcard_cert) {
            warn!(error = %e, "failed to set wildcard cert");
            return;
        }
        if let Err(e) = ext::ssl_add_chain_cert(ssl, &self.ca_cert) {
            warn!(error = %e, "failed to add CA chain cert");
            return;
        }
        if let Err(e) = ext::ssl_use_private_key(ssl, &self.wildcard_key) {
            warn!(error = %e, "failed to set wildcard key");
        }
    }

    /// Generate (or fetch from cache) a per-hostname cert and set it on the SSL connection.
    fn set_on_demand(&self, ssl: &mut pingora::protocols::tls::TlsRef, sni: &str) {
        // Fast path: cache hit
        if let Some((cert, key)) = self.cert_cache.read().get(sni) {
            if let Err(e) = ext::ssl_use_certificate(ssl, cert) {
                warn!(sni, error = %e, "failed to set cached cert");
                return;
            }
            if let Err(e) = ext::ssl_add_chain_cert(ssl, &self.ca_cert) {
                warn!(sni, error = %e, "failed to add CA chain cert");
                return;
            }
            if let Err(e) = ext::ssl_use_private_key(ssl, key) {
                warn!(sni, error = %e, "failed to set cached key");
            }
            return;
        }

        // Slow path: generate and cache
        match generate_single_host_cert(&self.ca_key_pem, &self.ca_cert_pem, sni) {
            Ok((cert_pem, key_pem)) => {
                let cert = match X509::from_pem(cert_pem.as_bytes()) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(sni, error = %e, "failed to parse generated cert");
                        return self.set_wildcard(ssl);
                    }
                };
                let key = match PKey::private_key_from_pem(key_pem.as_bytes()) {
                    Ok(k) => k,
                    Err(e) => {
                        warn!(sni, error = %e, "failed to parse generated key");
                        return self.set_wildcard(ssl);
                    }
                };

                if let Err(e) = ext::ssl_use_certificate(ssl, &cert) {
                    warn!(sni, error = %e, "failed to set on-demand cert");
                    return;
                }
                if let Err(e) = ext::ssl_add_chain_cert(ssl, &self.ca_cert) {
                    warn!(sni, error = %e, "failed to add CA chain cert");
                    return;
                }
                if let Err(e) = ext::ssl_use_private_key(ssl, &key) {
                    warn!(sni, error = %e, "failed to set on-demand key");
                    return;
                }

                self.cert_cache
                    .write()
                    .insert(sni.to_string(), (cert, key));
                debug!(sni, "generated on-demand cert");
            }
            Err(err) => {
                warn!(sni, error = %err, "failed to generate on-demand cert");
                self.set_wildcard(ssl);
            }
        }
    }
}

// -- internal helpers --------------------------------------------------------

fn build_ca_params() -> anyhow::Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params
        .distinguished_name
        .push(DnType::CommonName, "Coulson Dev CA");
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    const CA_VALIDITY_DAYS: i64 = 3650; // 10 years
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(CA_VALIDITY_DAYS);

    Ok(params)
}

/// Generate a wildcard cert for `*.{domain_suffix}` + bare `{domain_suffix}`.
fn generate_wildcard_cert(
    ca_key_pem: &str,
    ca_cert_pem: &str,
    domain_suffix: &str,
) -> anyhow::Result<(String, String)> {
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    let ca_params = build_ca_params()?;
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, format!("*.{domain_suffix}"));
    params.subject_alt_names = vec![
        SanType::DnsName(format!("*.{domain_suffix}").try_into()?),
        SanType::DnsName(domain_suffix.to_string().try_into()?),
    ];

    const SERVER_CERT_VALIDITY_DAYS: i64 = 365;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(SERVER_CERT_VALIDITY_DAYS);

    let cert = params.signed_by(&server_key, &issuer)?;
    let chain_pem = format!("{}{}", cert.pem(), ca_cert_pem);
    Ok((chain_pem, server_key.serialize_pem()))
}

/// Generate a cert for a single hostname (e.g. `myapp.localhost`).
/// Returns (cert_pem, key_pem) — the leaf certificate only (no chain).
fn generate_single_host_cert(
    ca_key_pem: &str,
    ca_cert_pem: &str,
    hostname: &str,
) -> anyhow::Result<(String, String)> {
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    let ca_params = build_ca_params()?;
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let _ = ca_cert_pem; // CA cert added to chain by caller

    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(DnType::CommonName, hostname);
    params.subject_alt_names = vec![SanType::DnsName(hostname.to_string().try_into()?)];

    const CERT_VALIDITY_DAYS: i64 = 365;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(CERT_VALIDITY_DAYS);

    let cert = params.signed_by(&server_key, &issuer)?;
    Ok((cert.pem(), server_key.serialize_pem()))
}

fn suffix_matches(meta_path: &Path, domain_suffix: &str) -> bool {
    match fs::read_to_string(meta_path) {
        Ok(stored) => stored.trim() == domain_suffix,
        Err(_) => false,
    }
}
