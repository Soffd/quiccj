package quic.crypto

/** RFC 8439 ChaCha20, including the QUIC header protection variant. */
public class ChaCha20 {
    private static func littleEndian(data: Array<UInt8>, off: Int64): UInt32 {
        return UInt32(data[off]) | (UInt32(data[off + 1]) << 8) |
            (UInt32(data[off + 2]) << 16) | (UInt32(data[off + 3]) << 24)
    }

    private static func rotate(v: UInt32, n: Int64): UInt32 {
        return (v << n) | (v >> (32 - n))
    }

    @OverflowWrapping
    private static func quarter(x: Array<UInt32>, a: Int64, b: Int64, c: Int64, d: Int64): Unit {
        x[a] += x[b]
        x[d] = rotate(x[d] ^ x[a], 16)
        x[c] += x[d]
        x[b] = rotate(x[b] ^ x[c], 12)
        x[a] += x[b]
        x[d] = rotate(x[d] ^ x[a], 8)
        x[c] += x[d]
        x[b] = rotate(x[b] ^ x[c], 7)
    }

    @OverflowWrapping
    public static func block(key: Array<UInt8>, nonce: Array<UInt8>, counter: UInt32): Array<UInt8> {
        if (key.size != 32 || nonce.size != 12) {
            throw Exception("invalid ChaCha20 key or nonce length")
        }
        let state: Array<UInt32> = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0, 0, 0, 0, 0, 0, 0, 0, counter,
            littleEndian(nonce, 0), littleEndian(nonce, 4), littleEndian(nonce, 8)
        ]
        for (i in 0..8) {
            state[4 + i] = littleEndian(key, i * 4)
        }
        let work = Array<UInt32>(16, { i => state[i] })
        for (_ in 0..10) {
            quarter(work, 0, 4, 8, 12)
            quarter(work, 1, 5, 9, 13)
            quarter(work, 2, 6, 10, 14)
            quarter(work, 3, 7, 11, 15)
            quarter(work, 0, 5, 10, 15)
            quarter(work, 1, 6, 11, 12)
            quarter(work, 2, 7, 8, 13)
            quarter(work, 3, 4, 9, 14)
        }
        let output = Array<UInt8>(64, repeat: 0)
        for (i in 0..16) {
            let word = work[i] + state[i]
            for (j in 0..4) {
                output[i * 4 + j] = UInt8((word >> (j * 8)) & 0xff)
            }
        }
        return output
    }

    public static func mask(key: Array<UInt8>, sample: Array<UInt8>): Array<UInt8> {
        return block(key, sliceBytes(sample, 4, 12), littleEndian(sample, 0))
    }

    static func apply(key: Array<UInt8>, nonce: Array<UInt8>, bytes: Array<UInt8>,
        offset: Int64, length: Int64): Unit {
        var cursor = 0
        var counter: UInt32 = 1
        while (cursor < length) {
            let mask = block(key, nonce, counter)
            let count = if (length - cursor < 64) { length - cursor } else { 64 }
            for (i in 0..count) {
                bytes[offset + cursor + i] ^= mask[i]
            }
            cursor += count
            counter++
        }
    }
}

private let POLY_FIELD = MontCtx([0xfffffffb, 0xffffffff, 0xffffffff, 0xffffffff, 3], 5)

public class ChaCha20Poly1305 {
    private let key: Array<UInt8>

    public init(key: Array<UInt8>) {
        this.key = key
    }

    private func tag(nonce: Array<UInt8>, aad: Array<UInt8>, bytes: Array<UInt8>,
        offset: Int64, length: Int64): Array<UInt8> {
        let oneTime = ChaCha20.block(key, nonce, 0)
        for (i in [3, 7, 11, 15]) {
            oneTime[i] &= 15
        }
        for (i in [4, 8, 12]) {
            oneTime[i] &= 252
        }
        let r = POLY_FIELD.toMont(BigUint.fromBytesLE(sliceBytes(oneTime, 0, 16), 5))
        var h = BigUint(5)
        h = accumulate(h, r, aad, 0, aad.size)
        h = accumulate(h, r, bytes, offset, length)
        let sizes = Array<UInt8>(16, repeat: 0)
        for (i in 0..8) {
            sizes[i] = UInt8((UInt64(aad.size) >> (i * 8)) & 0xff)
            sizes[i + 8] = UInt8((UInt64(length) >> (i * 8)) & 0xff)
        }
        h = POLY_FIELD.fromMont(accumulate(h, r, sizes, 0, 16))
        let s = BigUint.fromBytesLE(sliceBytes(oneTime, 16, 16), 5)
        h.add(s)
        fillBytes(oneTime, 0)
        return h.toBytesLE(16)
    }

    private func accumulate(initial: BigUint, r: BigUint, input: Array<UInt8>,
        offset: Int64, length: Int64): BigUint {
        var h = initial
        let block = Array<UInt8>(17, repeat: 0)
        var cursor = 0
        while (cursor < length) {
            let n = if (length - cursor < 16) { length - cursor } else { 16 }
            fillBytes(block, 0)
            copyBytes(block, 0, input, offset + cursor, n)
            // AEAD pads AAD and ciphertext to whole blocks before Poly1305.
            block[16] = 1
            let word = POLY_FIELD.toMont(BigUint.fromBytesLE(block, 5))
            h = POLY_FIELD.mul(POLY_FIELD.add(h, word), r)
            cursor += n
        }
        return h
    }

    public func seal(nonce: Array<UInt8>, aad: Array<UInt8>, bytes: Array<UInt8>,
        offset: Int64, length: Int64): Unit {
        ChaCha20.apply(key, nonce, bytes, offset, length)
        copyBytes(bytes, offset + length, tag(nonce, aad, bytes, offset, length), 0, 16)
    }

    public func open(nonce: Array<UInt8>, aad: Array<UInt8>, bytes: Array<UInt8>,
        offset: Int64, length: Int64, tagOffset: Int64): Bool {
        if (!ctEqual(tag(nonce, aad, bytes, offset, length), sliceBytes(bytes, tagOffset, 16))) {
            return false
        }
        ChaCha20.apply(key, nonce, bytes, offset, length)
        return true
    }
}
