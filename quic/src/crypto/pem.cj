package quic.crypto

/*
 * PEM (RFC 7468) decoding, byte-oriented so PEM offsets are never confused
 * with character indices.
 */

private func b64Val(c: UInt8): Int64 {
    if (c >= 65 && c <= 90) {
        return Int64(c - 65)
    }
    if (c >= 97 && c <= 122) {
        return Int64(c - 97) + 26
    }
    if (c >= 48 && c <= 57) {
        return Int64(c - 48) + 52
    }
    if (c == 43) {
        return 62
    }
    if (c == 47) {
        return 63
    }
    return -1
}

public func base64Decode(text: String): Array<UInt8> {
    let raw = text.toArray()
    let out = Array<UInt8>(raw.size / 4 * 3 + 3, repeat: 0)
    var o = 0
    var acc: UInt32 = 0
    var bits = 0
    var i = 0
    while (i < raw.size) {
        let c = raw[i]
        i++
        if (c == 61) {
            break
        }
        let v = b64Val(c)
        if (v < 0) {
            continue
        }
        acc = (acc << 6) | UInt32(v)
        bits = bits + 6
        if (bits >= 8) {
            bits = bits - 8
            out[o] = UInt8((acc >> UInt32(bits)) & 0xFF)
            o++
        }
    }
    return sliceBytes(out, 0, o)
}

public func base64Encode(data: Array<UInt8>): String {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toArray()
    let cap = (data.size / 3 + 1) * 4
    let out = Array<UInt8>(cap, repeat: 0)
    var o = 0
    var i = 0
    var acc: UInt32 = 0
    var bits = 0
    while (i < data.size) {
        acc = (acc << 8) | UInt32(data[i])
        bits = bits + 8
        while (bits >= 6) {
            bits = bits - 6
            out[o] = alphabet[Int64((acc >> UInt32(bits)) & 0x3F)]
            o++
        }
        i++
    }
    if (bits > 0) {
        out[o] = alphabet[Int64((acc << UInt32(6 - bits)) & 0x3F)]
        o++
    }
    while (o % 4 != 0) {
        out[o] = 61
        o++
    }
    return String.fromUtf8(sliceBytes(out, 0, o))
}

private func matchAt(data: Array<UInt8>, off: Int64, pat: Array<UInt8>): Bool {
    if (off + pat.size > data.size) {
        return false
    }
    var i = 0
    while (i < pat.size) {
        if (data[off + i] != pat[i]) {
            return false
        }
        i++
    }
    return true
}

/** Extract all CERTIFICATE blocks from a PEM bundle. */
public func pemCertificates(text: String): Array<Array<UInt8>> {
    let raw = text.toArray()
    let slots = 64
    let out = Array<Array<UInt8>>(slots, repeat: Array<UInt8>(0, repeat: 0))
    var count = 0
    let begin = "-----BEGIN CERTIFICATE-----".toArray()
    let endMark = "-----END CERTIFICATE-----".toArray()
    var i = 0
    while (i + begin.size <= raw.size && count < slots) {
        if (matchAt(raw, i, begin)) {
            var j = i + begin.size
            var e = -1
            while (j + endMark.size <= raw.size) {
                if (matchAt(raw, j, endMark)) {
                    e = j
                    break
                }
                j++
            }
            if (e < 0) {
                break
            }
            let b64 = String.fromUtf8(sliceBytes(raw, i + begin.size, e - (i + begin.size)))
            out[count] = base64Decode(b64)
            count++
            i = e + endMark.size
        } else {
            i++
        }
    }
    let result = Array<Array<UInt8>>(count, repeat: Array<UInt8>(0, repeat: 0))
    var k = 0
    while (k < count) {
        result[k] = out[k]
        k++
    }
    return result
}
