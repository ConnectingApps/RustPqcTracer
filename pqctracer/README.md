# pqctracer

A reusable Rust library that provides a TLS-aware HTTP client capable of capturing post-quantum cryptography (PQC) handshake metadata for every request.

## What is PQC and Why Does It Matter?

Post-quantum cryptography (PQC) refers to cryptographic algorithms designed to resist attacks from quantum computers. Classical key-exchange algorithms such as X25519 are considered vulnerable to sufficiently powerful quantum computers. Hybrid schemes like `X25519MLKEM768` combine classical and post-quantum algorithms, providing security even if one of the two is broken.

Knowing whether your HTTPS connections actually negotiate a post-quantum key-exchange group matters because PQC adoption requires support on **both** the client **and** the server side. Even if your client is configured to prefer post-quantum algorithms, the server must also support them — otherwise the TLS handshake falls back to a classical group. This library lets you observe exactly what was negotiated for every request, so you can audit and track PQC adoption across the services you depend on.

You can also use [quantumsafeaudit.com](https://quantumsafeaudit.com) to check whether your browser and a given web server support PQC.

## Features

- Captures the negotiated TLS key-exchange group (e.g. `X25519MLKEM768`) per request
- Captures the negotiated cipher suite (e.g. `TLS13_AES_256_GCM_SHA384`) per request
- Built on top of `reqwest` and `rustls` with `prefer-post-quantum` support
- Single shared connection-pooled client; per-request capture context is lock-free across `.await` points

## Usage

```rust
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
```

## Example Output

```
Requesting: https://www.google.com
Status code: 200 OK
Negotiated group: X25519MLKEM768
Cipher suite: TLS13_AES_256_GCM_SHA384

Requesting: https://www.bing.com
Status code: 200 OK
Negotiated group: X25519
Cipher suite: TLS13_AES_256_GCM_SHA384
```

The output above illustrates that PQC usage depends on **both** the client and the server. Google supports the hybrid post-quantum group `X25519MLKEM768`, so the handshake upgrades to a quantum-safe key exchange. Bing, however, only negotiates the classical `X25519` group, meaning no post-quantum protection is used for that connection — even though the client supports it.

## Author

Created by [Daan Cohen](https://www.linkedin.com/in/daanacohen). Feel free to reach out via LinkedIn if you need help or have questions about this package.

## License

GPL-3.0

