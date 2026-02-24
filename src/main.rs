use pqctracer::TlsAwareClient;

async fn trace_host(tls_client: &TlsAwareClient, host: &str) {
    let url = format!("https://{}", host);
    println!("Requesting: {}", url);

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

#[tokio::main]
async fn main() {
    // Install aws-lc-rs as the process-level crypto provider (required when
    // `prefer-post-quantum` is enabled, since it brings in aws-lc-rs alongside ring).
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install crypto provider");

    // Build the reusable TLS-aware client once.
    let tls_client = TlsAwareClient::new();

    trace_host(&tls_client, "www.google.com").await;
    println!();
    trace_host(&tls_client, "www.bing.com").await;
}
