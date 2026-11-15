package quic.crypto

/*
 * RSA PKCS#1 v1.5 signature verification (public-key operation only).
 */

private let SHA256_PREFIX: String = "3031300d060960864801650304020105000420"
private let SHA384_PREFIX: String = "3041300d060960864801650304020205000430"

public func rsaVerifyPkcs1(keyDer: Array<UInt8>, digest: Array<UInt8>, sig: Array<UInt8>,
    sigAlg: String): Bool {
    var prefix: Array<UInt8>
    if (sigAlg == "1.2.840.113549.1.1.11" || sigAlg == "1.2.840.113549.1.1.1") {
        prefix = hexDecode(SHA256_PREFIX)
    } else if (sigAlg == "1.2.840.113549.1.1.12") {
        prefix = hexDecode(SHA384_PREFIX)
    } else {
        return false
    }
    try {
        let d = Der(keyDer, 0, keyDer.size)
        let seq = d.enter(0x30)
        let nBytes = seq.readIntegerBytes()
        let eBytes = seq.readIntegerBytes()
        let k = (nBytes.size + 3) / 4
        if (sig.size != nBytes.size) {
            return false
        }
        // modulus limbs
        let limbs = Array<UInt32>(k, repeat: 0)
        var i = 0
        while (i < k) {
            let off = nBytes.size - (i + 1) * 4
            if (off >= 0) {
                limbs[i] = beU32(nBytes, off)
            } else {
                var v: UInt32 = 0
                var b = 0
                while (b < 4 + off) {
                    v = (v << 8) | UInt32(nBytes[b])
                    b++
                }
                limbs[i] = v
            }
            i++
        }
        let ctx = MontCtx(limbs, k)
        let s = BigUint.fromBytesBE(sig, k)
        let e = BigUint.fromBytesBE(eBytes, k)
        let sMont = ctx.toMont(s)
        let mMont = ctx.pow(sMont, e)
        let m = ctx.fromMont(mMont)
        let em = m.toBytesBE(k * 4)
        // EM = 0x00 || 0x01 || PS(0xFF...) || 0x00 || T
        if (em.size < 11 || em[0] != 0 || em[1] != 1) {
            return false
        }
        var pos = 2
        while (pos < em.size && em[pos] == 0xFF) {
            pos++
        }
        if (pos >= em.size || em[pos] != 0) {
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
