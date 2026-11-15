package quic

/**
 * Pure-Cangjie QUIC v1 / HTTP3 stack.
 *
 * Packages:
 *   quic.crypto     - cryptographic primitives (SHA-2, AES-GCM, ChaCha20-Poly1305,
 *                     X25519, P-256, RSA, Ed25519, X.509, trust store)
 *   quic.tls        - TLS 1.3 handshake (QUIC profile, no record layer)
 *   quic.transport  - RFC 9000/9001/9002 transport
 *   quic.http3      - RFC 9114 + RFC 9204 (QPACK)
 */
public let VERSION: String = "0.1.0"
