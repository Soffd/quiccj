package quic.crypto

/*
 * Fixed-capacity unsigned big integers with Montgomery modular arithmetic.
 *
 * Limbs are 32-bit, little-endian. Everything is allocation-light and uses
 * 64-bit intermediates; no 128-bit type is required.
 */

public class BigUint {
    public var w: Array<UInt32>
    public var n: Int64

    public init(cap: Int64) {
        w = Array<UInt32>(cap, repeat: 0)
        n = 0
    }

    public static func fromBytesBE(bytes: Array<UInt8>, cap: Int64): BigUint {
        let r = BigUint(cap)
        var i = bytes.size - 1
        var limb = 0
        var shift = 0
        var cur: UInt32 = 0
        while (i >= 0) {
            cur = cur | (UInt32(bytes[i]) << UInt32(shift))
            shift = shift + 8
            if (shift == 32) {
                r.w[limb] = cur
                limb++
                cur = 0
                shift = 0
            }
            i--
        }
        if (shift > 0) {
            r.w[limb] = cur
            limb++
        }
        r.n = limb
        r.trim()
        return r
    }

    public static func fromBytesLE(bytes: Array<UInt8>, cap: Int64): BigUint {
        let rev = Array<UInt8>(bytes.size, repeat: 0)
        var i = 0
        while (i < bytes.size) {
            rev[i] = bytes[bytes.size - 1 - i]
            i++
        }
        return fromBytesBE(rev, cap)
    }

    public func toBytesLE(size: Int64): Array<UInt8> {
        let be = toBytesBE(size)
        let out = Array<UInt8>(size, repeat: 0)
        var i = 0
        while (i < size) {
            out[i] = be[size - 1 - i]
            i++
        }
        return out
    }

    public static func fromUInt64(v: UInt64, cap: Int64): BigUint {
        let r = BigUint(cap)
        r.w[0] = UInt32(v & 0xFFFF_FFFF)
        r.w[1] = UInt32(v >> 32)
        r.n = 2
        r.trim()
        return r
    }

    public func trim(): Unit {
        while (n > 0 && w[n - 1] == 0) {
            n--
        }
    }

    public func copyFrom(o: BigUint): Unit {
        var i = 0
        while (i < w.size) {
            w[i] = if (i < o.w.size) { o.w[i] } else { 0 }
            i++
        }
        n = o.n
    }

    public func clone(): BigUint {
        let r = BigUint(w.size)
        var i = 0
        while (i < w.size) {
            r.w[i] = w[i]
            i++
        }
        r.n = n
        return r
    }

    public func isZero(): Bool {
        return n == 0
    }

    public func isOdd(): Bool {
        if (n == 0) {
            return false
        }
        return (w[0] & 1) == 1
    }

    public func bit(i: Int64): Bool {
        let limb = i / 32
        if (limb >= n) {
            return false
        }
        return ((w[limb] >> UInt32(i % 32)) & 1) == 1
    }

    public func bitLen(): Int64 {
        if (n == 0) {
            return 0
        }
        var v = w[n - 1]
        var bits = (n - 1) * 32
        while (v != 0) {
            bits++
            v = v >> 1
        }
        return bits
    }

    public func cmp(o: BigUint): Int64 {
        if (n != o.n) {
            return if (n < o.n) { -1 } else { 1 }
        }
        var i = n - 1
        while (i >= 0) {
            if (w[i] != o.w[i]) {
                return if (w[i] < o.w[i]) { -1 } else { 1 }
            }
            i--
        }
        return 0
    }

    @OverflowWrapping
    public func add(o: BigUint): Unit {
        let lim = if (o.n > n) { o.n } else { n }
        var carry: UInt64 = 0
        var i = 0
        while (i < lim || carry != 0) {
            if (i >= w.size) {
                throw Exception("BigUint overflow in add")
            }
            let a: UInt64 = if (i < n) { UInt64(w[i]) } else { 0 }
            let b: UInt64 = if (i < o.n) { UInt64(o.w[i]) } else { 0 }
            let s = a + b + carry
            w[i] = UInt32(s & 0xFFFF_FFFF)
            carry = s >> 32
            i++
        }
        n = i
        trim()
    }

    @OverflowWrapping
    public func sub(o: BigUint): Unit {
        var borrow: UInt64 = 0
        var i = 0
        while (i < n) {
            let a = UInt64(w[i])
            let b: UInt64 = if (i < o.n) { UInt64(o.w[i]) } else { 0 }
            let d = a - b - borrow
            w[i] = UInt32(d & 0xFFFF_FFFF)
            borrow = if ((d >> 63) != 0) { 1 } else { 0 }
            i++
        }
        trim()
    }

    @OverflowWrapping
    public func shl1(): Unit {
        var carry: UInt32 = 0
        var i = 0
        while (i < n) {
            let nv = (w[i] << 1) | carry
            carry = w[i] >> 31
            w[i] = nv
            i++
        }
        if (carry != 0) {
            if (n >= w.size) {
                throw Exception("BigUint overflow in shl1")
            }
            w[n] = carry
            n++
        }
    }

    @OverflowWrapping
    public func shr1(): Unit {
        var i = n - 1
        var carry: UInt32 = 0
        while (i >= 0) {
            let nv = (w[i] >> 1) | carry
            carry = (w[i] & 1) << 31
            w[i] = nv
            i--
        }
        trim()
    }

    @OverflowWrapping
    public func mulLow(o: BigUint, out: Array<UInt32>, outLen: Int64): Unit {
        var i = 0
        while (i < outLen) {
            out[i] = 0
            i++
        }
        i = 0
        while (i < n) {
            var carry: UInt64 = 0
            let ai = UInt64(w[i])
            var j = 0
            while (j < o.n) {
                let idx = i + j
                if (idx >= outLen) {
                    break
                }
                let cur = UInt64(out[idx]) + ai * UInt64(o.w[j]) + carry
                out[idx] = UInt32(cur & 0xFFFF_FFFF)
                carry = cur >> 32
                j++
            }
            var idx = i + j
            while (carry != 0 && idx < outLen) {
                let cur = UInt64(out[idx]) + carry
                out[idx] = UInt32(cur & 0xFFFF_FFFF)
                carry = cur >> 32
                idx++
            }
            i++
        }
    }

    public func toBytesBE(size: Int64): Array<UInt8> {
        let out = Array<UInt8>(size, repeat: 0)
        var i = 0
        while (i < size) {
            let bitPos = i * 8
            let limb = bitPos / 32
            let shift = bitPos % 32
            var v: UInt32 = 0
            if (limb < n) {
                v = w[limb] >> UInt32(shift)
                if (shift > 0 && limb + 1 < n) {
                    v = v | (w[limb + 1] << UInt32(32 - shift))
                }
            }
            out[size - 1 - i] = UInt8(v & 0xFF)
            i++
        }
        return out
    }
}

/** Montgomery context for an odd modulus. */
public class MontCtx {
    public let k: Int64
    public let mod: Array<UInt32>
    private let n0inv: UInt32
    public let r2: BigUint

    @OverflowWrapping
    private static func computeN0Inv(mod: Array<UInt32>, k: Int64): UInt32 {
        // Newton iteration for -n^{-1} mod 2^32
        var inv: UInt32 = 1
        var i = 0
        while (i < 5) {
            inv = inv * (2 - mod[0] * inv)
            i++
        }
        return 0 - inv
    }

    public init(modulus: Array<UInt32>, k: Int64) {
        this.k = k
        mod = Array<UInt32>(k, repeat: 0)
        var i = 0
        while (i < k) {
            mod[i] = modulus[i]
            i++
        }
        n0inv = computeN0Inv(mod, k)
        // R^2 mod n computed by 2k doublings of 1
        let r = BigUint(k + 2)
        r.w[0] = 1
        r.n = 1
        let m = BigUint(k + 2)
        m.n = k
        i = 0
        while (i < k) {
            m.w[i] = mod[i]
            i++
        }
        var step = 0
        while (step < 2 * 32 * k) {
            r.shl1()
            if (r.cmp(m) >= 0) {
                r.sub(m)
            }
            step++
        }
        r2 = r
    }

    private static func wToBytes(w: Array<UInt32>, k: Int64): Array<UInt8> {
        let out = Array<UInt8>(k * 4, repeat: 0)
        var i = 0
        while (i < k) {
            putBeU32(out, (k - 1 - i) * 4, w[i])
            i++
        }
        return out
    }

    public func isZero(a: BigUint): Bool {
        return a.isZero()
    }

    /** a*b*R^{-1} mod n (CIOS). */
    @OverflowWrapping
    public func mul(a: BigUint, b: BigUint): BigUint {
        let t = Array<UInt32>(k + 2, repeat: 0)
        var i = 0
        while (i < k) {
            let ai = if (i < a.n) { a.w[i] } else { 0u32 }
            var carry: UInt64 = 0
            var j = 0
            while (j < k) {
                let bj = if (j < b.n) { b.w[j] } else { 0u32 }
                let cur = UInt64(t[j]) + UInt64(ai) * UInt64(bj) + carry
                t[j] = UInt32(cur & 0xFFFF_FFFF)
                carry = cur >> 32
                j++
            }
            var s = UInt64(t[k]) + carry
            t[k] = UInt32(s & 0xFFFF_FFFF)
            t[k + 1] = UInt32(s >> 32)
            let m = t[0] * n0inv
            var c2 = (UInt64(t[0]) + UInt64(m) * UInt64(mod[0])) >> 32
            j = 1
            while (j < k) {
                let cur = UInt64(t[j]) + UInt64(m) * UInt64(mod[j]) + c2
                t[j - 1] = UInt32(cur & 0xFFFF_FFFF)
                c2 = cur >> 32
                j++
            }
            let s2 = UInt64(t[k]) + c2
            t[k - 1] = UInt32(s2 & 0xFFFF_FFFF)
            t[k] = UInt32(UInt64(t[k + 1]) + (s2 >> 32))
            t[k + 1] = 0
            i++
        }
        let res = BigUint(k + 2)
        i = 0
        while (i <= k) {
            res.w[i] = t[i]
            i++
        }
        res.n = k + 1
        res.trim()
        let m = BigUint(k + 2)
        m.n = k
        i = 0
        while (i < k) {
            m.w[i] = mod[i]
            i++
        }
        if (res.cmp(m) >= 0) {
            res.sub(m)
        }
        return res
    }

    public func toMont(a: BigUint): BigUint {
        return mul(a, r2)
    }

    public func fromMont(a: BigUint): BigUint {
        let one = BigUint(k + 2)
        one.w[0] = 1
        one.n = 1
        return mul(a, one)
    }

    public func one(): BigUint {
        let one = BigUint(k + 2)
        one.w[0] = 1
        one.n = 1
        return toMont(one)
    }

    public func negate(a: BigUint): BigUint {
        if (a.isZero()) {
            return BigUint(k + 2)
        }
        let m = BigUint(k + 2)
        m.n = k
        var i = 0
        while (i < k) {
            m.w[i] = mod[i]
            i++
        }
        let r = m.clone()
        r.sub(a)
        return r
    }

    public func add(a: BigUint, b: BigUint): BigUint {
        let r = a.clone()
        r.add(b)
        let m = BigUint(k + 2)
        m.n = k
        var i = 0
        while (i < k) {
            m.w[i] = mod[i]
            i++
        }
        if (r.cmp(m) >= 0) {
            r.sub(m)
        }
        return r
    }

    public func sub(a: BigUint, b: BigUint): BigUint {
        let r = a.clone()
        if (r.cmp(b) >= 0) {
            r.sub(b)
        } else {
            let m = BigUint(k + 2)
            m.n = k
            var i = 0
            while (i < k) {
                m.w[i] = mod[i]
                i++
            }
            r.add(m)
            r.sub(b)
        }
        return r
    }

    /** Inverse via Fermat: a^(n-2) mod n (n must be prime). */
    public func inverse(a: BigUint): BigUint {
        let e = BigUint(k + 2)
        e.n = k
        var i = 0
        while (i < k) {
            e.w[i] = mod[i]
            i++
        }
        // e = n - 2
        var borrow: UInt64 = 2
        i = 0
        while (i < e.n && borrow != 0) {
            let v = UInt64(e.w[i])
            let d = v - borrow
            e.w[i] = UInt32(d & 0xFFFF_FFFF)
            borrow = if ((d >> 63) != 0) { 1 } else { 0 }
            i++
        }
        e.trim()
        return pow(a, e)
    }

    /** base^exp in Montgomery form. */
    @OverflowWrapping
    public func pow(base: BigUint, exp: BigUint): BigUint {
        var result = one()
        var b = base.clone()
        var i = 0
        let bits = exp.bitLen()
        while (i < bits) {
            if (exp.bit(i)) {
                result = mul(result, b)
            }
            b = mul(b, b)
            i++
        }
        return result
    }
}
