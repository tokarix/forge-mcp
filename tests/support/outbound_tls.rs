//! Shared handshake contract, compiled independently into server and transport.
#![allow(clippy::expect_used)]

use rustls::pki_types::pem::PemObject;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

const CERT: &[u8] = include_bytes!("../fixtures/localhost.pem");
const KEY: &[u8] = include_bytes!("../fixtures/localhost-key.pem");

fn endpoint() -> (u16, std::thread::JoinHandle<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS fixture");
    let port = listener.local_addr().expect("local address").port();
    let thread = std::thread::spawn(move || {
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![
                rustls::pki_types::CertificateDer::from_pem_slice(CERT)
                    .expect("fixture certificate"),
            ],
            rustls::pki_types::PrivateKeyDer::from_pem_slice(KEY).expect("fixture key"),
        )
        .expect("fixture certificate");
        let (socket, _) = listener.accept().expect("accept TLS client");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("write timeout");
        let connection = rustls::ServerConnection::new(Arc::new(config)).expect("TLS server");
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut request = [0; 4096];
        if stream.read(&mut request).is_err() {
            return false;
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("response");
        stream.flush().expect("flush response");
        true
    });
    (port, thread)
}

#[tokio::test]
async fn standalone_client_validates_trust_and_hostname() {
    // A fresh process prevents other tests from hiding an initialization bug.
    const CHILD: &str = "FORGE_MCP_TLS_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "http_client::tests::standalone_client_validates_trust_and_hostname",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .expect("isolated TLS test");
        assert!(status.success());
        return;
    }
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    // No forge adapter and no global provider installation precede construction.
    let client = super::client_builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("standalone client");
    let (port, server) = endpoint();
    let error = client
        .get(format!("https://localhost:{port}/"))
        .send()
        .await
        .expect_err("bundled roots must reject the fixture certificate");
    assert!(error.is_connect());
    assert!(!server.join().expect("TLS thread"));

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from_pem_slice(CERT).expect("fixture certificate"))
        .expect("trust fixture");
    let client = super::builder_with_roots(roots)
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client trusting fixture");
    let (port, server) = endpoint();
    let response = client
        .get(format!("https://localhost:{port}/"))
        .send()
        .await
        .expect("trusted TLS handshake");
    assert_eq!(response.text().await.expect("response body"), "ok");
    assert!(server.join().expect("TLS thread"));

    let (port, server) = endpoint();
    let error = client
        .get(format!("https://127.0.0.1:{port}/"))
        .send()
        .await
        .expect_err("trusted certificate must still match the hostname");
    assert!(error.is_connect());
    assert!(!server.join().expect("TLS thread"));
}
