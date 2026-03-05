use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use parking_lot::RwLock;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
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

    /// Build a `DynamicCertResolver` that uses the wildcard cert for the
    /// primary suffix and generates per-hostname certs on demand for
    /// `.localhost` domains (since `*.localhost` wildcards are rejected
    /// by browsers per RFC 6761 / PSL).
    pub fn build_resolver(&self, domain_suffix: &str) -> anyhow::Result<DynamicCertResolver> {
        let wildcard_key = load_certified_key(self.cert_path(), self.key_path())?;
        Ok(DynamicCertResolver {
            domain_suffix: domain_suffix.to_string(),
            wildcard_key: Arc::new(wildcard_key),
            ca_key_pem: self.ca_key_pem.clone(),
            ca_cert_pem: self.ca_cert_pem.clone(),
            cert_cache: RwLock::new(HashMap::new()),
        })
    }
}

/// Resolves TLS certificates per SNI hostname.
///
/// - `*.{domain_suffix}` requests → served by the pre-generated wildcard cert
/// - `foo.localhost` requests → cert generated on demand and cached
pub struct DynamicCertResolver {
    domain_suffix: String,
    wildcard_key: Arc<CertifiedKey>,
    ca_key_pem: String,
    ca_cert_pem: String,
    cert_cache: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicCertResolver")
            .field("domain_suffix", &self.domain_suffix)
            .field("cert_cached", &self.cert_cache.read().len())
            .finish()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let suffix_dot = format!(".{}", self.domain_suffix);

        // Single-level subdomain under primary suffix (e.g. myapp.coulson.local)
        // → wildcard cert covers it
        if sni.ends_with(&suffix_dot) || sni == self.domain_suffix {
            let prefix = sni.strip_suffix(&suffix_dot).unwrap_or("");
            if !prefix.contains('.') {
                return Some(self.wildcard_key.clone());
            }
            // Multi-level subdomain (e.g. sub.myapp.coulson.local) — wildcard
            // only matches one label, so generate a per-hostname cert on demand.
            return self.resolve_on_demand(sni);
        }

        // .localhost → per-hostname cert (on demand)
        if sni.ends_with(&format!(".{LOCALHOST_SUFFIX}")) || sni == LOCALHOST_SUFFIX {
            return self.resolve_on_demand(sni);
        }

        // Unknown domain — try wildcard as best effort
        Some(self.wildcard_key.clone())
    }
}

impl DynamicCertResolver {
    /// Look up or generate a per-hostname cert, caching the result.
    fn resolve_on_demand(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        // Fast path: cache hit
        if let Some(key) = self.cert_cache.read().get(sni) {
            return Some(key.clone());
        }
        // Slow path: generate and cache
        match generate_single_host_cert(&self.ca_key_pem, &self.ca_cert_pem, sni) {
            Ok(key) => {
                let key = Arc::new(key);
                self.cert_cache.write().insert(sni.to_string(), key.clone());
                debug!(sni, "generated on-demand cert");
                Some(key)
            }
            Err(err) => {
                warn!(sni, error = %err, "failed to generate on-demand cert");
                Some(self.wildcard_key.clone())
            }
        }
    }
}

/// Build a `rustls::ServerConfig` using the dynamic cert resolver.
pub fn build_server_config(resolver: Arc<DynamicCertResolver>) -> rustls::ServerConfig {
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver)
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
fn generate_single_host_cert(
    ca_key_pem: &str,
    ca_cert_pem: &str,
    hostname: &str,
) -> anyhow::Result<CertifiedKey> {
    let ca_key = KeyPair::from_pem(ca_key_pem)?;
    let ca_params = build_ca_params()?;
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(DnType::CommonName, hostname);
    params.subject_alt_names = vec![SanType::DnsName(hostname.to_string().try_into()?)];

    const CERT_VALIDITY_DAYS: i64 = 365;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(CERT_VALIDITY_DAYS);

    let cert = params.signed_by(&server_key, &issuer)?;

    // Convert to rustls types
    let cert_der = cert.der().to_vec();
    let ca_cert_der = pem_to_der(ca_cert_pem)?;
    let key_der = server_key.serialize_der();

    let certs = vec![
        rustls::pki_types::CertificateDer::from(cert_der),
        rustls::pki_types::CertificateDer::from(ca_cert_der),
    ];
    let private_key =
        rustls::pki_types::PrivateKeyDer::try_from(key_der).map_err(|e| anyhow::anyhow!("{e}"))?;
    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key)?;

    Ok(CertifiedKey::new(certs, signing_key))
}

/// Load a PEM cert chain + key from files into a `CertifiedKey`.
fn load_certified_key(cert_path: &str, key_path: &str) -> anyhow::Result<CertifiedKey> {
    let cert_pem = fs::read(cert_path).context("failed to read cert file")?;
    let key_pem = fs::read(key_path).context("failed to read key file")?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .context("failed to parse cert PEM")?;

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .context("failed to parse key PEM")?
        .context("no private key found in PEM")?;

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)?;
    Ok(CertifiedKey::new(certs, signing_key))
}

/// Extract the first PEM block as DER bytes.
fn pem_to_der(pem: &str) -> anyhow::Result<Vec<u8>> {
    let cert = rustls_pemfile::certs(&mut pem.as_bytes())
        .next()
        .context("no cert in PEM")?
        .context("failed to parse PEM")?;
    Ok(cert.to_vec())
}

fn suffix_matches(meta_path: &Path, domain_suffix: &str) -> bool {
    match fs::read_to_string(meta_path) {
        Ok(stored) => stored.trim() == domain_suffix,
        Err(_) => false,
    }
}
