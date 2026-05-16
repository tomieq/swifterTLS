# SwifterTLS

SwifterTLS is a small Swift package that adds a TLS 1.3 `SecureSocket` implementation for [Swifter](https://github.com/tomieq/swifter)-style HTTP servers.

It is useful when you want to run a local or embedded Swift HTTP server over HTTPS without putting a reverse proxy in front of it.

## Features

- TLS 1.3 server-side handshake
- `TLS_AES_128_GCM_SHA256`
- X25519, P-256, P-384, and P-521 key exchange through Swift Crypto
- ECDSA P-256 certificate authentication with `ecdsa_secp256r1_sha256`
- PEM encoded PKCS#8 private keys
- Single certificate or PEM certificate chain support
- Integration through Swifter's `secureSocketType`

## Requirements

- Swift 5.10+
- macOS 11+
- iOS 14+
- Linux with Swift Crypto support
- A Swifter server using the `tls` branch compatible with this package
- A P-256 ECDSA private key and matching certificate

## Installation

Add SwifterTLS to your `Package.swift` dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/tomieq/swifterTLS.git", from: "1.0.0"),
    .package(url: "https://github.com/tomieq/swifter.git", from: "3.2.0")
]
```

Then add the products to the target that starts your server:

```swift
.target(
    name: "MyServer",
    dependencies: [
        .product(name: "SwifterTLS", package: "swifterTLS"),
        .product(name: "Swifter", package: "swifter")
    ]
)
```

## Quick Start

```swift
import Foundation
import Swifter
import SwifterTLS

let tlsConfiguration = TLSConfiguration(
    privateKeyPEM: """
    -----BEGIN PRIVATE KEY-----
    ... PKCS#8 P-256 private key ...
    -----END PRIVATE KEY-----
    """,
    certificatePEM: """
    -----BEGIN CERTIFICATE-----
    ... leaf certificate for localhost or your hostname ...
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    ... intermediate or CA certificate, if needed ...
    -----END CERTIFICATE-----
    """
)

let server = HttpServer()
server.secureSocketFactory = { socket in
    TLSSocket(socket, tlsConfiguration: tlsConfiguration)
}

server.get["/"] = { _, _ in
    .ok(.text("Hello over TLS"))
}

try server.start(8443, forceIPv4: true)
RunLoop.main.run()
```

Open the server with:

```sh
curl -k https://localhost:8443/
```

Use `-k` only for local self-signed certificates. For normal clients, install or trust the issuing CA.

## Certificates

`TLSConfiguration` takes two PEM strings:

- `privateKeyPEM`: a PKCS#8 P-256 ECDSA private key using `-----BEGIN PRIVATE KEY-----`
- `certificatePEM`: one or more X.509 certificates using `-----BEGIN CERTIFICATE-----`

When providing a certificate chain, put certificates in this order:

1. Leaf/server certificate matching `privateKeyPEM`
2. Intermediate certificates, if any
3. Root CA certificate, if you intentionally want to send it

Many public TLS servers do not send the root CA because clients are expected to already have the trust anchor. For private/local CAs, sending the root can help with debugging, but clients still need to trust that CA before they accept the connection.

You can inspect what the server sends with:

```sh
openssl s_client -connect localhost:8443 -servername localhost -showcerts
```

If Chrome shows only the leaf certificate, compare that with `openssl s_client -showcerts`. Browser certificate viewers often show a verified path built from the local trust store, which is not always the same thing as the raw certificate list sent by the server.

## Demo

This repository includes a demo HTTPS server:

```sh
swift run Demo
```

By default it starts on port `8082`:

```sh
curl -k https://localhost:8082/
```

To view the sent certificate chain:

```sh
openssl s_client -connect localhost:8082 -servername localhost -showcerts
```

## Current Scope

SwifterTLS currently implements a focused subset of TLS 1.3 for server use:

- TLS 1.3 only
- Server-side sockets only
- One configured certificate identity per process
- P-256 ECDSA certificates only
- X25519, P-256, P-384, and P-521 key shares
- `TLS_AES_128_GCM_SHA256` only
- No client certificate authentication
- No ALPN negotiation
- No SNI-based certificate selection
- No TLS 1.2 fallback

These constraints keep the implementation compact and easy to audit, but they also mean it is not a drop-in replacement for a full TLS stack.

## Development

Run tests with:

```sh
swift test
```

Run the demo with:

```sh
swift run Demo
```

## Troubleshooting

### `TLS handshake failed: missingConfiguration`

Call `TLSSocket.configure(_:)` before assigning `server.secureSocketType` or accepting connections.

### The browser rejects the certificate

Make sure the certificate SAN contains the hostname you are using, for example `localhost`, and make sure the issuing CA is trusted by the client.

### The certificate chain is incomplete

Ensure `certificatePEM` contains every certificate block you want to send, with the leaf certificate first. Then verify the raw handshake with:

```sh
openssl s_client -connect localhost:8443 -servername localhost -showcerts
```

### OpenSSL reports ASN.1 or X.509 parsing errors

Check each certificate separately:

```sh
openssl x509 -in certificate.pem -noout -subject -issuer -serial
```

The PEM may decode from base64 but still contain invalid X.509 DER. In that case the TLS server can send the bytes, but clients may reject or hide that certificate.
