package quic.crypto

/*
 * RSA PKCS#1 v1.5 signature verification (public-key operation only).
 */

private let SHA256_PREFIX: String = "3031300d060960864801650304020105000420"
private let SHA512_PREFIX: String = "3051300d060960864801650304020305000440"
private let SHA384_PREFIX: String = "3041300d060960864801650304020205000430"

public func rsaVerifyPkcs1(keyDer: Array<UInt8>, digest: Array<UInt8>, sig: Array<UInt8>,
    sigAlg: String): Bool {
    var prefix: Array<UInt8>
    if (sigAlg == "1.2.840.113549.1.1.11" || sigAlg == "1.2.840.113549.1.1.1") {
        prefix = hexDecode(SHA256_PREFIX)
    } else if (sigAlg == "1.2.840.113549.1.1.12") {
        prefix = hexDecode(SHA384_PREFIX)
    } else if (sigAlg == "1.2.840.113549.1.1.13") {
        prefix = hexDecode(SHA512_PREFIX)
    } else {
        return false
    }
    try {
        let (em, _) = rsaPublic(keyDer, sig)
        // EM = 0x00 || 0x01 || PS(0xFF...) || 0x00 || T
        if (em.size < 11 || em[0] != 0 || em[1] != 1) {
            return false
        }
        var pos = 2
        while (pos < em.size && em[pos] == 0xFF) {
            pos++
        }
        if (pos < 10 || pos >= em.size || em[pos] != 0) {
            return false
        }
        pos++
        let t = sliceBytes(em, pos, em.size - pos)
        let expected = concat(prefix, digest)
        return ctEqual(t, expected)
    } catch (err: Exception) {
        return false
    }
}


private func rsaPublic(key: Array<UInt8>, signature: Array<UInt8>): (Array<UInt8>, Int64) {
    let der = Der(key, 0, key.size)
    let seq = der.enter(0x30)
    let modulus = seq.readIntegerBytes()
    let exponent = seq.readIntegerBytes()
    if (!der.eof() || !seq.eof() || modulus.size < 128 || modulus.size > 1024 ||
        exponent.size == 0 || exponent.size > 8 || signature.size != modulus.size) {
        throw Exception("invalid RSA parameters")
    }
    let limbs = (modulus.size + 3) / 4
    let n = BigUint.fromBytesBE(modulus, limbs)
    let e = BigUint.fromBytesBE(exponent, limbs)
    let s = BigUint.fromBytesBE(signature, limbs)
    if (!n.isOdd() || !e.isOdd() || e.bitLen() < 2 || s.cmp(n) >= 0) {
        throw Exception("invalid RSA public operation")
    }
    let ctx = MontCtx(n.w, limbs)
    let value = ctx.fromMont(ctx.pow(ctx.toMont(s), e))
    return (value.toBytesBE(modulus.size), n.bitLen())
}

/** RFC 8017 EMSA-PSS verification with MGF1 and salt length equal to the hash length (TLS 1.3). */
public func rsaVerifyPss(key: Array<UInt8>, digest: Array<UInt8>, signature: Array<UInt8>,
    alg: HashAlg): Bool {
    try {
        let (encoded, bits) = rsaPublic(key, signature)
        let hashLen = hashSize(alg)
        let emBits = bits - 1
        let emLen = (emBits + 7) / 8
        if (digest.size != hashLen || emLen < 2 * hashLen + 2 || encoded[encoded.size - 1] != 0xbc) {
            return false
        }
        if (emLen < encoded.size && encoded[0] != 0) {
            return false
        }
        let em = sliceBytes(encoded, encoded.size - emLen, emLen)
        let unused = 8 * emLen - emBits
        let mask = UInt8(0xff >> unused)
        if ((em[0] & !mask) != 0) {
            return false
        }
        let dbLen = emLen - hashLen - 1
        let hash = sliceBytes(em, dbLen, hashLen)
        let seed = concat(hash, [0, 0, 0, 0])
        var offset = 0
        var counter: UInt32 = 0
        while (offset < dbLen) {
            putBeU32(seed, hashLen, counter)
            let block = hashOf(alg, seed)
            for (i in 0..block.size) {
                if (offset == dbLen) {
                    break
                }
                em[offset] ^= block[i]
                offset++
            }
            counter++
        }
        em[0] &= mask
        let padding = dbLen - hashLen - 1
        var mismatch: UInt8 = em[padding] ^ 1
        for (i in 0..padding) {
            mismatch |= em[i]
        }
        let salted = ByteWriter(8 + 2 * hashLen)
        salted.putBytes(Array<UInt8>(8, repeat: 0))
        salted.putBytes(digest)
        salted.putBytes(em, padding + 1, hashLen)
        return mismatch == 0 && ctEqual(hash, hashOf(alg, salted.toArray()))
    } catch (e: Exception) {
        return false
    }
}
