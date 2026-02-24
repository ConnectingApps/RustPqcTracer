use std::fmt;
use std::sync::{Arc, Mutex};
use rustls::client::{ClientSessionStore, Resumption};
use rustls::client::{Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::NamedGroup;
use rustls_pki_types::ServerName;

/// Shared TLS metadata captured during the handshake.
#[derive(Default, Debug)]
struct Captured {
    group: Option<String>,
    cipher: Option<String>,
}

/// A `ClientSessionStore` that intercepts post-handshake callbacks to record
/// the negotiated KX group (`set_kx_hint`) and cipher suite (`insert_tls13_ticket`).
struct CapturingSessionStore {
    state: Arc<Mutex<Captured>>,
}

impl fmt::Debug for CapturingSessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapturingSessionStore")
    }
}

impl ClientSessionStore for CapturingSessionStore {
    // Called after every successful handshake with the group that was used.
    fn set_kx_hint(&self, _server_name: ServerName<'static>, group: NamedGroup) {
        self.state.lock().unwrap().group = Some(format!("{:?}", group));
    }

    fn kx_hint(&self, _server_name: &ServerName<'_>) -> Option<NamedGroup> {
        None
    }

    // TLS 1.2 session – suite() is not public, so nothing to capture.
    fn set_tls12_session(&self, _server_name: ServerName<'static>, _value: Tls12ClientSessionValue) {}

    fn tls12_session(&self, _server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        None
    }

    fn remove_tls12_session(&self, _server_name: &ServerName<'static>) {}

    // TLS 1.3 ticket – record cipher suite from the session value.
    fn insert_tls13_ticket(&self, _server_name: ServerName<'static>, value: Tls13ClientSessionValue) {
        let mut s = self.state.lock().unwrap();
        if s.cipher.is_none() {
            s.cipher = Some(format!("{:?}", value.suite().common.suite));
        }
    }

    fn take_tls13_ticket(&self, _server_name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        None
    }
}

#[tokio::main]
async fn main() {
    // Install aws-lc-rs as the process-level crypto provider (required when
    // `prefer-post-quantum` is enabled, since it brings in aws-lc-rs alongside ring).
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install crypto provider");

    let host = "www.google.com";
    let url = format!("https://{}", host);
    println!("Requesting: {}", url);

    // Shared state populated during the TLS handshake.
    let captured = Arc::new(Mutex::new(Captured::default()));

    let session_store = Arc::new(CapturingSessionStore {
        state: captured.clone(),
    });

    // Build a rustls ClientConfig that uses our capturing session store.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Attach our capturing store via the public `resumption` field.
    tls_config.resumption = Resumption::store(session_store);

    // Hand the pre-built rustls config to reqwest – one single async HTTP request.
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()
        .expect("failed to build client");

    let response = client
        .get(&url)
        .send()
        .await
        .expect("request failed");

    let status = response.status();

    // Read the captured TLS metadata.
    let state = captured.lock().unwrap();
    let group = state.group.as_deref().unwrap_or("Not available");
    let cipher = state.cipher.as_deref().unwrap_or("Not available");

    println!("Status code: {}", status);
    println!("Negotiated group: {}", group);
    println!("Cipher suite: {}", cipher);
}
