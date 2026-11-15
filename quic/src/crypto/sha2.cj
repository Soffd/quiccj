package quic.crypto

/*
 * SHA-256 (FIPS 180-4) and SHA-384 / SHA-512.
 * Pure Cangjie, streaming API, no external dependencies.
 */

private let SHA256_K: Array<UInt32> = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

@OverflowWrapping
private func rotr32(x: UInt32, n: UInt32): UInt32 {
    return (x >> n) | (x << (32 - n))
}

@OverflowWrapping
private func sha256Compress(state: Array<UInt32>, block: Array<UInt8>, off: Int64): Unit {
    let w = Array<UInt32>(64, repeat: 0)
    var i = 0
    while (i < 16) {
        w[i] = beU32(block, off + i * 4)
        i++
    }
    while (i < 64) {
        let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3)
        let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w[i] = w[i - 16] + s0 + w[i - 7] + s1
        i++
    }
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    i = 0
    while (i < 64) {
        let bigS1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
        let ch = (e & f) ^ ((!e) & g)
        let t1 = h + bigS1 + ch + SHA256_K[i] + w[i]
        let bigS0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
        let maj = (a & b) ^ (a & c) ^ (b & c)
        let t2 = bigS0 + maj
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
        i++
    }
    state[0] = state[0] + a
    state[1] = state[1] + b
    state[2] = state[2] + c
    state[3] = state[3] + d
    state[4] = state[4] + e
    state[5] = state[5] + f
    state[6] = state[6] + g
    state[7] = state[7] + h
}

public class Sha256 {
    private static let IV: Array<UInt32> = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    private var state: Array<UInt32>
    private var buf: Array<UInt8>
    private var bufLen: Int64
    private var total: UInt64

    public init() {
        state = Array<UInt32>(8, repeat: 0)
        buf = Array<UInt8>(64, repeat: 0)
        bufLen = 0
        total = 0
        reset()
    }

    public func reset(): Unit {
        var i = 0
        while (i < 8) {
            state[i] = IV[i]
            i++
        }
        fillBytes(buf, 0)
        bufLen = 0
        total = 0
    }

    public prop size: Int64 {
        get() {
            32
        }
    }

    public func update(data: Array<UInt8>): Unit {
        update(data, 0, data.size)
    }

    public func update(data: Array<UInt8>, off: Int64, len: Int64): Unit {
        total = total + UInt64(len)
        var pos = off
        var remaining = len
        if (bufLen > 0) {
            let need = 64 - bufLen
            let take = if (remaining < need) { remaining } else { need }
            copyBytes(buf, bufLen, data, pos, take)
            bufLen = bufLen + take
            pos = pos + take
            remaining = remaining - take
            if (bufLen == 64) {
                sha256Compress(state, buf, 0)
                bufLen = 0
            }
        }
        while (remaining >= 64) {
            sha256Compress(state, data, pos)
            pos = pos + 64
            remaining = remaining - 64
        }
        if (remaining > 0) {
            copyBytes(buf, 0, data, pos, remaining)
            bufLen = remaining
        }
    }

    private func padAndCompress(): Unit {
        let bitLen = total << 3
        buf[bufLen] = 0x80
        bufLen = bufLen + 1
        if (bufLen > 56) {
            while (bufLen < 64) {
                buf[bufLen] = 0
                bufLen = bufLen + 1
            }
            sha256Compress(state, buf, 0)
            bufLen = 0
        }
        while (bufLen < 56) {
            buf[bufLen] = 0
            bufLen = bufLen + 1
        }
        putBeU64(buf, 56, bitLen)
        sha256Compress(state, buf, 0)
        bufLen = 0
    }

    public func finish(): Array<UInt8> {
        padAndCompress()
        let out = Array<UInt8>(32, repeat: 0)
        var i = 0
        while (i < 8) {
            putBeU32(out, i * 4, state[i])
            i++
        }
        reset()
        return out
    }

    public func finishCopy(): Array<UInt8> {
        let saveState = Array<UInt32>(8, repeat: 0)
        var i = 0
        while (i < 8) {
            saveState[i] = state[i]
            i++
        }
        let saveBuf = Array<UInt8>(64, repeat: 0)
        copyBytes(saveBuf, 0, buf, 0, 64)
        let saveBufLen = bufLen
        let saveTotal = total
        let out = finish()
        i = 0
        while (i < 8) {
            state[i] = saveState[i]
            i++
        }
        copyBytes(buf, 0, saveBuf, 0, 64)
        bufLen = saveBufLen
        total = saveTotal
        return out
    }
}

private let SHA512_K: Array<UInt64> = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
]

@OverflowWrapping
private func rotr64(x: UInt64, n: UInt64): UInt64 {
    return (x >> n) | (x << (64 - n))
}

@OverflowWrapping
private func sha512Compress(state: Array<UInt64>, block: Array<UInt8>, off: Int64): Unit {
    let w = Array<UInt64>(80, repeat: 0)
    var i = 0
    while (i < 16) {
        w[i] = beU64(block, off + i * 8)
        i++
    }
    while (i < 80) {
        let s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
        let s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
        w[i] = w[i - 16] + s0 + w[i - 7] + s1
        i++
    }
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]
    i = 0
    while (i < 80) {
        let bigS1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
        let ch = (e & f) ^ ((!e) & g)
        let t1 = h + bigS1 + ch + SHA512_K[i] + w[i]
        let bigS0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
        let maj = (a & b) ^ (a & c) ^ (b & c)
        let t2 = bigS0 + maj
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
        i++
    }
    state[0] = state[0] + a
    state[1] = state[1] + b
    state[2] = state[2] + c
    state[3] = state[3] + d
    state[4] = state[4] + e
    state[5] = state[5] + f
    state[6] = state[6] + g
    state[7] = state[7] + h
}

/**
 * SHA-512 family core. `is384` selects the SHA-384 IV and 48-byte output.
 */
public class Sha512 {
    private static let IV512: Array<UInt64> = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    ]
    private static let IV384: Array<UInt64> = [
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    ]
    private var state: Array<UInt64>
    private var buf: Array<UInt8>
    private var bufLen: Int64
    private var total: UInt64
    private let is384: Bool

    private init(use384: Bool) {
        is384 = use384
        state = Array<UInt64>(8, repeat: 0)
        buf = Array<UInt8>(128, repeat: 0)
        bufLen = 0
        total = 0
        reset()
    }

    public static func sha384(): Sha512 {
        return Sha512(true)
    }

    public static func sha512(): Sha512 {
        return Sha512(false)
    }

    public func reset(): Unit {
        var i = 0
        while (i < 8) {
            state[i] = if (is384) { IV384[i] } else { IV512[i] }
            i++
        }
        fillBytes(buf, 0)
        bufLen = 0
        total = 0
    }

    public prop size: Int64 {
        get() {
            if (is384) {
                48
            } else {
                64
            }
        }
    }

    public func update(data: Array<UInt8>): Unit {
        update(data, 0, data.size)
    }

    public func update(data: Array<UInt8>, off: Int64, len: Int64): Unit {
        total = total + UInt64(len)
        var pos = off
        var remaining = len
        if (bufLen > 0) {
            let need = 128 - bufLen
            let take = if (remaining < need) { remaining } else { need }
            copyBytes(buf, bufLen, data, pos, take)
            bufLen = bufLen + take
            pos = pos + take
            remaining = remaining - take
            if (bufLen == 128) {
                sha512Compress(state, buf, 0)
                bufLen = 0
            }
        }
        while (remaining >= 128) {
            sha512Compress(state, data, pos)
            pos = pos + 128
            remaining = remaining - 128
        }
        if (remaining > 0) {
            copyBytes(buf, 0, data, pos, remaining)
            bufLen = remaining
        }
    }

    public func finish(): Array<UInt8> {
        let bitLen = total << 3
        if (bufLen > 112) {
            buf[bufLen] = 0x80
            bufLen = bufLen + 1
            while (bufLen < 128) {
                buf[bufLen] = 0
                bufLen = bufLen + 1
            }
            sha512Compress(state, buf, 0)
            bufLen = 0
        } else {
            buf[bufLen] = 0x80
            bufLen = bufLen + 1
        }
        while (bufLen < 120) {
            buf[bufLen] = 0
            bufLen = bufLen + 1
        }
        putBeU64(buf, 120, bitLen)
        sha512Compress(state, buf, 0)
        let outSize = if (is384) { 48 } else { 64 }
        let out = Array<UInt8>(outSize, repeat: 0)
        var i = 0
        while (i < outSize / 8) {
            putBeU64(out, i * 8, state[i])
            i++
        }
        reset()
        return out
    }
}

public func sha256(data: Array<UInt8>): Array<UInt8> {
    let h = Sha256()
    h.update(data)
    return h.finish()
}

public func sha256(data: Array<UInt8>, off: Int64, len: Int64): Array<UInt8> {
    let h = Sha256()
    h.update(data, off, len)
    return h.finish()
}

public func sha384(data: Array<UInt8>): Array<UInt8> {
    let h = Sha512.sha384()
    h.update(data)
    return h.finish()
}

public func sha512(data: Array<UInt8>): Array<UInt8> {
    let h = Sha512.sha512()
    h.update(data)
    return h.finish()
}
