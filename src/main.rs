use std::fmt;
use std::sync::{Arc, Mutex};
use rustls::client::{ClientSessionStore, Resumption};
use rustls::client::{Tls12ClientSessionValue, Tls13ClientSessionValue};
use rustls::NamedGroup;
use rustls_pki_types::ServerName;

/// TLS metadata captured during a single request's handshake.
pub struct TlsResponse {
    pub response: reqwest::Response,
    pub group: Option<String>,
    pub cipher: Option<String>,
}

/// Per-request TLS metadata populated by the session store callbacks.
#[derive(Default, Debug)]
struct Captured {
    group: Option<String>,
    cipher: Option<String>,
}

/// A `ClientSessionStore` that routes TLS handshake callbacks into whatever
/// per-request `Captured` is currently active.
///
/// The shared `active` pointer is set just before a request is sent and
/// cleared immediately after – always outside any `.await` point.
struct CapturingSessionStore {
    active: Arc<Mutex<Option<Arc<Mutex<Captured>>>>>,
}

impl fmt::Debug for CapturingSessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapturingSessionStore")
    }
}

impl ClientSessionStore for CapturingSessionStore {
    // Called after every successful handshake with the group that was used.
    fn set_kx_hint(&self, _server_name: ServerName<'static>, group: NamedGroup) {
        let slot = self.active.lock().unwrap().clone();
        if let Some(captured) = slot {
            captured.lock().unwrap().group = Some(format!("{:?}", group));
        }
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
        let slot = self.active.lock().unwrap().clone();
        if let Some(captured) = slot {
            let mut c = captured.lock().unwrap();
            if c.cipher.is_none() {
                c.cipher = Some(format!("{:?}", value.suite().common.suite));
            }
        }
    }

    fn take_tls13_ticket(&self, _server_name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        None
    }
}

/// A reusable HTTP client that captures TLS handshake metadata for every request.
///
/// Owns a single shared `reqwest::Client` (with connection pooling) and a single
/// rustls configuration built once at construction time. Per-request capture
/// context is installed and removed around each `.await` – no lock is ever held
/// across an await point.
pub struct TlsAwareClient {
    client: reqwest::Client,
    active_capture: Arc<Mutex<Option<Arc<Mutex<Captured>>>>>,
}

impl TlsAwareClient {
    /// Build the client, configuring rustls once.
    pub fn new() -> Self {
        let active_capture: Arc<Mutex<Option<Arc<Mutex<Captured>>>>> =
            Arc::new(Mutex::new(None));

        let session_store = Arc::new(CapturingSessionStore {
            active: active_capture.clone(),
        });

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        tls_config.resumption = Resumption::store(session_store);

        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .build()
            .expect("failed to build reqwest client");

        Self { client, active_capture }
    }

    /// Execute any `reqwest::Request` and return the response together with
    /// the negotiated TLS key-exchange group and cipher suite.
    ///
    /// Accepts GET / POST / PUT / PATCH / DELETE / … without special handling.
    pub async fn execute(&self, request: reqwest::Request) -> Result<TlsResponse, reqwest::Error> {
        // 1. Create a fresh capture context for this request.
        let captured = Arc::new(Mutex::new(Captured::default()));

        // 2. Activate it (lock scope ends before .await).
        {
            let mut active = self.active_capture.lock().unwrap();
            *active = Some(captured.clone());
        }

        // 3. Send the request through the shared, pooled client.
        let response = self.client.execute(request).await?;

        // 4. Deactivate capture (lock scope ends immediately).
        {
            let mut active = self.active_capture.lock().unwrap();
            *active = None;
        }

        // 5. Read captured values.
        let state = captured.lock().unwrap();
        Ok(TlsResponse {
            response,
            group: state.group.clone(),
            cipher: state.cipher.clone(),
        })
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

    // Build the reusable TLS-aware client once.
    let tls_client = TlsAwareClient::new();

    // Build a plain reqwest::Request (GET, but any method works).
    let req = reqwest::Client::new()
        .get(&url)
        .build()
        .expect("failed to build request");

    let result = tls_client.execute(req).await.expect("request failed");

    let group = result.group.as_deref().unwrap_or("Not available");
    let cipher = result.cipher.as_deref().unwrap_or("Not available");

    println!("Status code: {}", result.response.status());
    println!("Negotiated group: {}", group);
    println!("Cipher suite: {}", cipher);
}
