//! Outbound TLS keeps the bundled roots and ring backend used before reqwest 0.13.

use std::sync::Arc;

/// Builds an HTTP client without relying on a process-wide crypto provider.
pub fn client_builder() -> reqwest::ClientBuilder {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    builder_with_roots(roots)
}

#[allow(clippy::expect_used)] // The fixed ring provider supports both versions.
fn builder_with_roots(roots: rustls::RootCertStore) -> reqwest::ClientBuilder {
    // Use an explicit provider so standalone clients neither depend on forge
    // adapter initialization nor inherit an unrelated process-wide provider.
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .expect("ring supports TLS 1.2 and 1.3")
    .with_root_certificates(roots)
    .with_no_client_auth();
    reqwest::Client::builder().tls_backend_preconfigured(tls)
}

#[cfg(test)]
#[path = "../../tests/support/outbound_tls.rs"]
mod tests;
