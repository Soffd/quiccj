package quic.crypto

/** Software implementation of the per-connection cryptography interface. Select via PURE_CRYPTO. */
public open class CryptoBackend {
    /** ML-KEM-768 (decapsulation key, encapsulation key), when supplied by the provider. */
    public open func mlkem768Keys(): Option<(Array<UInt8>, Array<UInt8>)> { None }

    public open func mlkem768Open(key: Array<UInt8>, ciphertext: Array<UInt8>): Array<UInt8> {
        throw Exception("ML-KEM-768 unavailable")
    }

    public open prop supportsEd25519: Bool { get() { true } }

    public open func digest(alg: HashAlg, message: Array<UInt8>): Array<UInt8> {
        return hashOf(alg, message)
    }

    public open func x25519(privateKey: Array<UInt8>, peerPublic: Array<UInt8>): Array<UInt8> {
        return X25519.scalarmult(privateKey, peerPublic)
    }

    public open func headerMask(chacha: Bool, key: Array<UInt8>, sample: Array<UInt8>): Array<UInt8> {
        if (chacha) {
            return ChaCha20.mask(key, sample)
        }
        let mask = Array<UInt8>(16, repeat: 0)
        Aes(key).encryptBlock(sample, 0, mask, 0)
        return mask
    }

    public open func seal(chacha: Bool, key: Array<UInt8>, nonce: Array<UInt8>, aad: Array<UInt8>,
        packet: Array<UInt8>, offset: Int64, length: Int64): Unit {
        if (chacha) {
            ChaCha20Poly1305(key).seal(nonce, aad, packet, offset, length)
        } else {
            AesGcm(key).seal(nonce, aad, packet, offset, length, packet, offset + length)
        }
    }

    public open func openPacket(chacha: Bool, key: Array<UInt8>, nonce: Array<UInt8>, aad: Array<UInt8>,
        packet: Array<UInt8>, offset: Int64, length: Int64, tagOffset: Int64): Bool {
        if (chacha) {
            return ChaCha20Poly1305(key).open(nonce, aad, packet, offset, length, tagOffset)
        }
        return AesGcm(key).open(nonce, aad, packet, offset, length, packet, tagOffset)
    }

    public open func p256Public(privateKey: Array<UInt8>): Array<UInt8> {
        let point = CURVE_P256.mul(CURVE_P256.generator(), privateKey)
        let x = CURVE_P256.toAffineX(point).toBytesBE(32)
        let y = CURVE_P256.toAffineY(point).toBytesBE(32)
        return concat([4], concat(x, y))
    }

    public open func p256(privateKey: Array<UInt8>, peerPublic: Array<UInt8>): Array<UInt8> {
        let point = CURVE_P256.mul(CURVE_P256.decodePoint(peerPublic), privateKey)
        if (point.infinity) {
            throw Exception("invalid P-256 shared secret")
        }
        return CURVE_P256.toAffineX(point).toBytesBE(32)
    }

    public open func p256Private(): Array<UInt8> {
        let order = hexDecode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        let limit = BigUint.fromBytesBE(order, 8)
        var key = randomBytes(32)
        var scalar = BigUint.fromBytesBE(key, 8)
        while (scalar.isZero() || scalar.cmp(limit) >= 0) {
            key = randomBytes(32)
            scalar = BigUint.fromBytesBE(key, 8)
        }
        return key
    }

    public open func verifyChain(chain: Array<X509Cert>, count: Int64, store: TrustStore, host: String,
        now: Int64): Bool {
        return verifyCertificateChain(chain, count, store, host, now, backend: this)
    }

    public open func verifyPeerChain(chain: Array<X509Cert>, count: Int64, store: TrustStore, host: String,
        now: Int64, staple: Array<UInt8>): Bool {
        return !store.requireStapledOcsp && verifyChain(chain, count, store, host, now)
    }

    public open func verifyCertificate(cert: X509Cert, issuer: X509Cert): Bool {
        return cert.verifySignedBy(issuer)
    }

    public open func verifyHandshake(cert: X509Cert, scheme: Int64, message: Array<UInt8>,
        signature: Array<UInt8>): Bool {
        if (scheme == 0x0807 && cert.keyType == "ED25519") {
            return verifyEd25519(cert.spki, message, signature)
        }
        if (scheme >= 0x0804 && scheme <= 0x0806 && cert.keyType == "RSA") {
            let alg = if (scheme == 0x0804) { HashAlg.Sha256 } else if (scheme == 0x0805) {
                HashAlg.Sha384
            } else {
                HashAlg.Sha512
            }
            return rsaVerifyPss(cert.spki, digest(alg, message), signature, alg)
        }
        if (cert.keyType != "EC") {
            return false
        }
        let (curve, alg) = if (scheme == 0x0403 && cert.curveOid == "1.2.840.10045.3.1.7") {
            (CURVE_P256, HashAlg.Sha256)
        } else if (scheme == 0x0503 && cert.curveOid == "1.3.132.0.34") {
            (CURVE_P384, HashAlg.Sha384)
        } else {
            return false
        }
        let der = Der(signature, 0, signature.size)
        let seq = der.enter(0x30)
        let r = seq.readIntegerBytes()
        let s = seq.readIntegerBytes()
        return der.eof() && seq.eof() && curve.verify(cert.spki, digest(alg, message), r, s)
    }
}

public let PURE_CRYPTO = CryptoBackend()
