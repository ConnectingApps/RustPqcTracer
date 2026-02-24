# pqctracer

A reusable Rust library that provides a TLS-aware HTTP client capable of capturing post-quantum cryptography (PQC) handshake metadata for every request.

## Features

- Captures the negotiated TLS key-exchange group (e.g. `X25519MLKEM768`) per request
- Captures the negotiated cipher suite (e.g. `TLS13_AES_256_GCM_SHA384`) per request
- Built on top of `reqwest` and `rustls` with `prefer-post-quantum` support
- Single shared connection-pooled client; per-request capture context is lock-free across `.await` points

## Usage

```rust
use pqctracer::TlsAwareClient;

#[tokio::main]
async fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install crypto provider");

    let tls_client = TlsAwareClient::new();

    let req = reqwest::Client::new()
        .get("https://www.google.com")
        .build()
        .expect("failed to build request");

    let result = tls_client.execute(req).await.expect("request failed");

    println!("Status:  {}", result.response.status());
    println!("Group:   {}", result.group.as_deref().unwrap_or("Not available"));
    println!("Cipher:  {}", result.cipher.as_deref().unwrap_or("Not available"));
}
```

## License

MIT
