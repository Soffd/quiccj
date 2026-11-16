package quic.crypto

/*
 * Byte helpers shared by the whole stack.
 * Deliberately allocation-light: every routine takes explicit (offset, len).
 */

public func beU16(b: Array<UInt8>, off: Int64): UInt16 {
    return (UInt16(b[off]) << 8) | UInt16(b[off + 1])
}

public func beU24(b: Array<UInt8>, off: Int64): UInt32 {
    return (UInt32(b[off]) << 16) | (UInt32(b[off + 1]) << 8) | UInt32(b[off + 2])
}

public func beU32(b: Array<UInt8>, off: Int64): UInt32 {
    return (UInt32(b[off]) << 24) | (UInt32(b[off + 1]) << 16) |
        (UInt32(b[off + 2]) << 8) | UInt32(b[off + 3])
}

public func beU64(b: Array<UInt8>, off: Int64): UInt64 {
    return (UInt64(beU32(b, off)) << 32) | UInt64(beU32(b, off + 4))
}

public func putBeU16(b: Array<UInt8>, off: Int64, v: UInt16): Unit {
    b[off] = UInt8((v >> 8) & 0xFF)
    b[off + 1] = UInt8(v & 0xFF)
}

public func putBeU24(b: Array<UInt8>, off: Int64, v: UInt32): Unit {
    b[off] = UInt8((v >> 16) & 0xFF)
    b[off + 1] = UInt8((v >> 8) & 0xFF)
    b[off + 2] = UInt8(v & 0xFF)
}

public func putBeU32(b: Array<UInt8>, off: Int64, v: UInt32): Unit {
    b[off] = UInt8((v >> 24) & 0xFF)
    b[off + 1] = UInt8((v >> 16) & 0xFF)
    b[off + 2] = UInt8((v >> 8) & 0xFF)
    b[off + 3] = UInt8(v & 0xFF)
}

public func putBeU64(b: Array<UInt8>, off: Int64, v: UInt64): Unit {
    putBeU32(b, off, UInt32(v >> 32))
    putBeU32(b, off + 4, UInt32(v & 0xFFFF_FFFF))
}

public func concat(a: Array<UInt8>, b: Array<UInt8>): Array<UInt8> {
    let out = Array<UInt8>(a.size + b.size, repeat: 0)
    copyBytes(out, 0, a, 0, a.size)
    copyBytes(out, a.size, b, 0, b.size)
    return out
}

public func concat3(a: Array<UInt8>, b: Array<UInt8>, c: Array<UInt8>): Array<UInt8> {
    let out = Array<UInt8>(a.size + b.size + c.size, repeat: 0)
    copyBytes(out, 0, a, 0, a.size)
    copyBytes(out, a.size, b, 0, b.size)
    copyBytes(out, a.size + b.size, c, 0, c.size)
    return out
}

public func copyBytes(dst: Array<UInt8>, dstOff: Int64, src: Array<UInt8>, srcOff: Int64,
    len: Int64): Unit {
    if (len != 0) {
        src.copyTo(dst, srcOff, dstOff, len)
    }
}

public func sliceBytes(src: Array<UInt8>, off: Int64, len: Int64): Array<UInt8> {
    let out = Array<UInt8>(len, repeat: 0)
    copyBytes(out, 0, src, off, len)
    return out
}

/** Constant-time equality for tags, Finished verify_data, etc. */
public func ctEqual(a: Array<UInt8>, b: Array<UInt8>): Bool {
    if (a.size != b.size) {
        return false
    }
    var diff: UInt8 = 0
    var i = 0
    while (i < a.size) {
        diff = diff | (a[i] ^ b[i])
        i++
    }
    return diff == 0
}

public func xorInto(a: Array<UInt8>, b: Array<UInt8>): Unit {
    var i = 0
    while (i < a.size) {
        a[i] = a[i] ^ b[i]
        i++
    }
}

public func fillBytes(a: Array<UInt8>, v: UInt8): Unit {
    var i = 0
    while (i < a.size) {
        a[i] = v
        i++
    }
}

private let HEX_DIGITS: Array<UInt8> = [48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100,
    101, 102]

public func hexEncode(data: Array<UInt8>): String {
    let out = Array<UInt8>(data.size * 2, repeat: 0)
    var i = 0
    while (i < data.size) {
        let v = data[i]
        out[i * 2] = HEX_DIGITS[Int64((v >> 4) & 0x0F)]
        out[i * 2 + 1] = HEX_DIGITS[Int64(v & 0x0F)]
        i++
    }
    return String.fromUtf8(out)
}

private func hexVal(c: UInt8): Int64 {
    if (c >= 48 && c <= 57) {
        return Int64(c - 48)
    }
    if (c >= 97 && c <= 102) {
        return Int64(c - 97) + 10
    }
    if (c >= 65 && c <= 70) {
        return Int64(c - 65) + 10
    }
    return -1
}

public func hexDecode(s: String): Array<UInt8> {
    let raw = s.toArray()
    let out = Array<UInt8>(raw.size / 2, repeat: 0)
    var i = 0
    while (i < out.size) {
        let hi = hexVal(raw[i * 2])
        let lo = hexVal(raw[i * 2 + 1])
        if (hi < 0 || lo < 0) {
            throw Exception("invalid hex string")
        }
        out[i] = UInt8((hi << 4) | lo)
        i++
    }
    return out
}

public func asciiBytes(s: String): Array<UInt8> {
    return s.toArray()
}

public func toLowerAscii(s: String): String {
    let raw = s.toArray()
    let out = Array<UInt8>(raw.size, repeat: 0)
    var i = 0
    while (i < raw.size) {
        let c = raw[i]
        out[i] = if (c >= 65 && c <= 90) { c + 32 } else { c }
        i++
    }
    return String.fromUtf8(out)
}
