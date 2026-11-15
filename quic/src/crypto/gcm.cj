package quic.crypto

/*
 * GHASH (GF(2^128), reduction x^128 + x^7 + x^2 + x + 1) and AES-GCM.
 *
 * The 128-bit field element is kept as (hi, lo) where the coefficient of x^0
 * lives in the most significant bit of `hi`, matching the GCM bit order.
 * Multiplication uses a 4-bit table per key, so each block costs 32 lookups.
 */

private func buildRed(): Array<UInt64> {
    let t = Array<UInt64>(16, repeat: 0)
    var j = 0
    while (j < 16) {
        var v: UInt64 = 0
        var b = 0
        while (b < 4) {
            if (((j >> b) & 1) == 1) {
                // bit b is x^(127-b); x^4 turns it into x^(128 + 3 - b)
                v = v ^ (0xE1u64 << (53 + b))
            }
            b++
        }
        t[j] = v
        j++
    }
    return t
}

private let GHASH_RED: Array<UInt64> = buildRed()

public class GhashKey {
    private let hHi: UInt64
    private let hLo: UInt64
    private let tHi: Array<UInt64>
    private let tLo: Array<UInt64>

    public init(hHi: UInt64, hLo: UInt64) {
        this.hHi = hHi
        this.hLo = hLo
        let th = Array<UInt64>(16, repeat: 0)
        let tl = Array<UInt64>(16, repeat: 0)
        // powers[j] = H * x^j, j = 0..3
        let ph = Array<UInt64>(4, repeat: 0)
        let pl = Array<UInt64>(4, repeat: 0)
        var curHi = hHi
        var curLo = hLo
        var j = 0
        while (j < 4) {
            ph[j] = curHi
            pl[j] = curLo
            // cur = cur * x  (128-bit right shift, reduce the x^127 bit)
            let lowbit = curLo & 1
            curLo = (curLo >> 1) | ((curHi & 1) << 63)
            curHi = curHi >> 1
            if (lowbit == 1) {
                curHi = curHi ^ (0xE1u64 << 56)
            }
            j++
        }
        // Inside a nibble the MSB is the lowest degree, so bit b maps to x^(3-b).
        var n = 0
        while (n < 16) {
            var b = 0
            while (b < 4) {
                if (((n >> b) & 1) == 1) {
                    th[n] = th[n] ^ ph[3 - b]
                    tl[n] = tl[n] ^ pl[3 - b]
                }
                b++
            }
            n++
        }
        tHi = th
        tLo = tl
    }

    @OverflowWrapping
    private func step(zHi: UInt64, zLo: UInt64, nibble: Int64): (UInt64, UInt64) {
        // z = z * x^4 + nibble * H ; multiply by x^4 is a 128-bit right shift.
        // The four bits that fall off are the low nibble of the *low* word.
        let lowNib = Int64(zLo & 0xF)
        let nhi = (zHi >> 4) ^ GHASH_RED[lowNib] ^ tHi[nibble]
        let nlo = ((zLo >> 4) | (zHi << 60)) ^ tLo[nibble]
        return (nhi, nlo)
    }

    /** y = (y ^ block) * H */
    @OverflowWrapping
    public func absorb(yHi: UInt64, yLo: UInt64, block: Array<UInt8>, off: Int64): (UInt64,
        UInt64) {
        let xHi = yHi ^ beU64(block, off)
        let xLo = yLo ^ beU64(block, off + 8)
        // Multiply (y ^ block) by H: Horner from the highest-degree nibble
        // (low nibble of the low word) down to the lowest (high nibble of hi).
        var zHi: UInt64 = 0
        var zLo: UInt64 = 0
        var i = 0
        while (i < 16) {
            let r = step(zHi, zLo, Int64((xLo >> (i * 4)) & 0xF))
            zHi = r[0]
            zLo = r[1]
            i++
        }
        i = 0
        while (i < 16) {
            let r = step(zHi, zLo, Int64((xHi >> (i * 4)) & 0xF))
            zHi = r[0]
            zLo = r[1]
            i++
        }
        return (zHi, zLo)
    }

    /** Absorb `len` bytes, zero-padding the final partial block. */
    @OverflowWrapping
    public func absorbPadded(yHi: UInt64, yLo: UInt64, data: Array<UInt8>, off: Int64,
        len: Int64): (UInt64, UInt64) {
        var zHi = yHi
        var zLo = yLo
        var pos = 0
        while (pos + 16 <= len) {
            let r = absorb(zHi, zLo, data, off + pos)
            zHi = r[0]
            zLo = r[1]
            pos = pos + 16
        }
        if (pos < len) {
            let last = Array<UInt8>(16, repeat: 0)
            var i = 0
            while (pos + i < len) {
                last[i] = data[off + pos + i]
                i++
            }
            let r = absorb(zHi, zLo, last, 0)
            zHi = r[0]
            zLo = r[1]
        }
        return (zHi, zLo)
    }
}

public class AesGcm {
    private let aes: Aes
    private let gh: GhashKey
    private let hHi: UInt64
    private let hLo: UInt64

    public init(key: Array<UInt8>) {
        aes = Aes(key)
        let zero = Array<UInt8>(16, repeat: 0)
        let h = Array<UInt8>(16, repeat: 0)
        aes.encryptBlock(zero, 0, h, 0)
        hHi = beU64(h, 0)
        hLo = beU64(h, 8)
        gh = GhashKey(hHi, hLo)
    }

    public prop tagSize: Int64 {
        get() {
            16
        }
    }

    private func computeTag(nonce: Array<UInt8>, aad: Array<UInt8>, data: Array<UInt8>,
        off: Int64, len: Int64): Array<UInt8> {
        // J0
        let j0 = Array<UInt8>(16, repeat: 0)
        if (nonce.size == 12) {
            copyBytes(j0, 0, nonce, 0, 12)
            j0[15] = 1
        } else {
            // GHASH-based derivation for non-96-bit nonces (not used by QUIC)
            let r = gh.absorbPadded(0, 0, nonce, 0, nonce.size)
            let lenBlock = Array<UInt8>(16, repeat: 0)
            putBeU64(lenBlock, 8, UInt64(nonce.size) * 8)
            let r2 = gh.absorb(r[0], r[1], lenBlock, 0)
            putBeU64(j0, 0, r2[0])
            putBeU64(j0, 8, r2[1])
        }
        var yHi: UInt64 = 0
        var yLo: UInt64 = 0
        let r0 = gh.absorbPadded(yHi, yLo, aad, 0, aad.size)
        yHi = r0[0]
        yLo = r0[1]
        let r1 = gh.absorbPadded(yHi, yLo, data, off, len)
        yHi = r1[0]
        yLo = r1[1]
        let lenBlock = Array<UInt8>(16, repeat: 0)
        putBeU64(lenBlock, 0, UInt64(aad.size) * 8)
        putBeU64(lenBlock, 8, UInt64(len) * 8)
        let r2 = gh.absorb(yHi, yLo, lenBlock, 0)
        yHi = r2[0]
        yLo = r2[1]
        let s = Array<UInt8>(16, repeat: 0)
        putBeU64(s, 0, yHi)
        putBeU64(s, 8, yLo)
        let ek = Array<UInt8>(16, repeat: 0)
        aes.encryptBlock(j0, 0, ek, 0)
        var i = 0
        while (i < 16) {
            s[i] = s[i] ^ ek[i]
            i++
        }
        return s
    }

    /** Encrypt `data[off..off+len)` in place and write the 16-byte tag. */
    public func seal(nonce: Array<UInt8>, aad: Array<UInt8>, data: Array<UInt8>, off: Int64,
        len: Int64, tagOut: Array<UInt8>, tagOff: Int64): Unit {
        let j0 = Array<UInt8>(16, repeat: 0)
        if (nonce.size == 12) {
            copyBytes(j0, 0, nonce, 0, 12)
            j0[15] = 1
        } else {
            let tag0 = computeTag(nonce, aad, data, off, len)
            // not reached in QUIC; keep deterministic fallback
            copyBytes(j0, 0, tag0, 0, 16)
        }
        let ctr = Array<UInt8>(16, repeat: 0)
        copyBytes(ctr, 0, j0, 0, 16)
        incrementCtr(ctr)
        aes.ctrXor(data, off, len, ctr)
        let tag = computeTag(nonce, aad, data, off, len)
        copyBytes(tagOut, tagOff, tag, 0, 16)
    }

    /** Decrypt in place; returns false (and leaves data untouched) on tag mismatch. */
    public func open(nonce: Array<UInt8>, aad: Array<UInt8>, data: Array<UInt8>, off: Int64,
        len: Int64, tag: Array<UInt8>, tagOff: Int64): Bool {
        let expected = computeTag(nonce, aad, data, off, len)
        let actual = sliceBytes(tag, tagOff, 16)
        if (!ctEqual(expected, actual)) {
            return false
        }
        let j0 = Array<UInt8>(16, repeat: 0)
        copyBytes(j0, 0, nonce, 0, 12)
        j0[15] = 1
        let ctr = Array<UInt8>(16, repeat: 0)
        copyBytes(ctr, 0, j0, 0, 16)
        incrementCtr(ctr)
        aes.ctrXor(data, off, len, ctr)
        return true
    }

    @OverflowWrapping
    private func incrementCtr(ctr: Array<UInt8>): Unit {
        var c = 15
        while (c >= 12) {
            ctr[c] = ctr[c] + 1
            if (ctr[c] != 0) {
                break
            }
            c--
        }
    }
}

/** One-shot helper: returns ciphertext||tag. */
public func aesGcmSeal(key: Array<UInt8>, nonce: Array<UInt8>, aad: Array<UInt8>,
    plaintext: Array<UInt8>): Array<UInt8> {
    let gcm = AesGcm(key)
    let out = Array<UInt8>(plaintext.size + 16, repeat: 0)
    copyBytes(out, 0, plaintext, 0, plaintext.size)
    gcm.seal(nonce, aad, out, 0, plaintext.size, out, plaintext.size)
    return out
}

public func aesGcmOpen(key: Array<UInt8>, nonce: Array<UInt8>, aad: Array<UInt8>,
    ciphertext: Array<UInt8>): Option<Array<UInt8>> {
    if (ciphertext.size < 16) {
        return None
    }
    let gcm = AesGcm(key)
    let body = Array<UInt8>(ciphertext.size - 16, repeat: 0)
    copyBytes(body, 0, ciphertext, 0, body.size)
    let ok = gcm.open(nonce, aad, body, 0, body.size, ciphertext, body.size)
    if (!ok) {
        return None
    }
    return Some(body)
}
