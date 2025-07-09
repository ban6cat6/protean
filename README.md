# Protean (Charm)

Protean is a fork of the uTLS library, designed to provide a robust and extensible framework for creating TLS camouflage connections.

## Features

- **Cryptographically Sound**: Employs an HMQV-based Authenticated Key Exchange (AKE) protocol to ensure secure key exchange with identity protection and weak Perfect Forward Secrecy (wPFS).
- **Extensibility**: Supports flexible extensions for QUIC, HTTP fingerprint and post-handshake messages simulation, leveraging the TLS connection towards the minic target.
- **Protocol Compatibility**: Supports TLS 1.3 and TLS 1.2.

## Usage

Check the [compatibility tests](./tests/compatibility_test.go)

## How it works

Protean actively exposes client's ephemeral private keys during the handshake process by a secure means, allowing the server to authenticate the client and perform a delegated handshake towards the target server. By this mean, the server could acquire any necessary server fingerprints as it required, like performing an MITM attack. The implementation is detailed in the protocol [specification](docs/protocol.md)

## Comparison

| Feature                      | Protean                                        | ShadowTLS (v3)                                                | REALITY                                                 |
| ---------------------------- | ---------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------- |
| **Base Library**             | uTLS (Go)                                      | Custom (Rustls-based)                                         | Modified Go crypto/tls                                  |
| **Supported TLS Versions**   | TLS 1.3, TLS 1.2                               | TLS 1.3                                                       | TLS 1.3                                                 |
| **Cryptographic Security**   | HMQV-based AKE with identity-concealed, wPFS   | PSK-based, no Forward Secrecy, detectable HMAC tainting \[1\] | Short ID authentication, **non-disclosable** public key |
| **Active Probe Resistance**  | Yes                                            | Yes                                                           | Yes                                                     |
| **Hijacking Resistance**     | Yes                                            | Yes                                                           | Yes                                                     |
| **Replay Attack Resistance** | Yes                                            | Yes                                                           | Yes                                                     |
| **Post-Handshake Messages**  | Extensible, customizable                       | Vulnerable to detection (NewSessionTicket issues \[1\])       | Limited, reliant on cached fingerprints                 |
| **Extensibility**            | High, could relay/modify any upstream messages | Limited, application data layer is backed by Shadowsocks      | Low, dependence on specific protocol features           |

**References**:
  * \[1\] Aparecium: https://github.com/ban6cat6/aparecium

## Clarification

Protean is not intended to offer a complete solution for application protocol layer camouflage or to implement specific application protocols; rather, it serves as a modular platform for building customised TLS-based camouflage proxies.
