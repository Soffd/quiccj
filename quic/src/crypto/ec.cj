package quic.crypto

/*
 * Generic short-Weierstrass curve over a prime field (a = -3), with ECDSA
 * verification. Instantiated for NIST P-256 and P-384.
 *
 * All field elements live in Montgomery form; points use Jacobian coordinates.
 */

public class EcPoint {
    public var x: BigUint
    public var y: BigUint
    public var z: BigUint
    public var infinity: Bool
    public var cap: Int64

    public init(cap: Int64) {
        this.cap = cap
        x = BigUint(cap)
        y = BigUint(cap)
        z = BigUint(cap)
        infinity = true
    }
}

public class EcCurve {
    public let p: MontCtx
    public let n: MontCtx
    public let limbs: Int64
    public let byteLen: Int64
    private let b: BigUint
    private let aMont: BigUint
    private let threeMont: BigUint
    private let twoMont: BigUint
    private let gx: BigUint
    private let gy: BigUint
    private let pPlain: BigUint
    private let sqrtExp: BigUint

    private static func ctxFromHex(h: String, k: Int64): MontCtx {
        let bytes = hexDecode(h)
        let limbs = Array<UInt32>(k, repeat: 0)
        var i = 0
        while (i < k) {
            limbs[i] = beU32(bytes, (k - 1 - i) * 4)
            i++
        }
        return MontCtx(limbs, k)
    }

    public init(pHex: String, nHex: String, bHex: String, gxHex: String, gyHex: String,
        k: Int64) {
        limbs = k
        byteLen = k * 4
        p = EcCurve.ctxFromHex(pHex, k)
        n = EcCurve.ctxFromHex(nHex, k)
        pPlain = BigUint.fromBytesBE(hexDecode(pHex), k)
        b = p.toMont(BigUint.fromBytesBE(hexDecode(bHex), k))
        let aPlain = BigUint.fromBytesBE(hexDecode(pHex), k)
        aPlain.sub(BigUint.fromUInt64(3, k))
        aMont = p.toMont(aPlain)
        threeMont = p.toMont(BigUint.fromUInt64(3, k))
        twoMont = p.toMont(BigUint.fromUInt64(2, k))
        gx = p.toMont(BigUint.fromBytesBE(hexDecode(gxHex), k))
        gy = p.toMont(BigUint.fromBytesBE(hexDecode(gyHex), k))
        // sqrt exponent (p+1)/4
        let e = pPlain.clone()
        e.add(BigUint.fromUInt64(1, k))
        e.shr1()
        e.shr1()
        sqrtExp = e
    }

    public func point(): EcPoint {
        return EcPoint(limbs)
    }

    public func generator(): EcPoint {
        let g = EcPoint(limbs)
        g.x = gx
        g.y = gy
        g.z = p.one()
        g.infinity = false
        return g
    }

    private func copyPoint(src: EcPoint): EcPoint {
        let r = EcPoint(limbs)
        r.x = src.x
        r.y = src.y
        r.z = src.z
        r.infinity = src.infinity
        return r
    }

    public func double(pt: EcPoint): EcPoint {
        let r = EcPoint(limbs)
        if (pt.infinity || pt.y.isZero()) {
            return r
        }
        let y2 = p.mul(pt.y, pt.y)
        let four = p.toMont(BigUint.fromUInt64(4, limbs))
        let s = p.mul(p.mul(pt.x, y2), four)
        let x2 = p.mul(pt.x, pt.x)
        let m1 = p.mul(threeMont, x2)
        let z2 = p.mul(pt.z, pt.z)
        let z4 = p.mul(z2, z2)
        let m2 = p.mul(aMont, z4)
        let m = p.add(m1, m2)
        let x3 = p.sub(p.mul(m, m), p.add(s, s))
        let y4 = p.mul(y2, y2)
        let eight = p.toMont(BigUint.fromUInt64(8, limbs))
        let y3 = p.sub(p.mul(m, p.sub(s, x3)), p.mul(eight, y4))
        let z3 = p.mul(twoMont, p.mul(pt.y, pt.z))
        r.x = x3
        r.y = y3
        r.z = z3
        r.infinity = false
        return r
    }

    public func add(p1: EcPoint, p2: EcPoint): EcPoint {
        if (p1.infinity) {
            return copyPoint(p2)
        }
        if (p2.infinity) {
            return copyPoint(p1)
        }
        let z1z1 = p.mul(p1.z, p1.z)
        let z2z2 = p.mul(p2.z, p2.z)
        let u1 = p.mul(p1.x, z2z2)
        let u2 = p.mul(p2.x, z1z1)
        let s1 = p.mul(p.mul(p1.y, p2.z), z2z2)
        let s2 = p.mul(p.mul(p2.y, p1.z), z1z1)
        if (u1.cmp(u2) == 0) {
            if (s1.cmp(s2) != 0) {
                return EcPoint(limbs)
            }
            return double(p1)
        }
        let h = p.sub(u2, u1)
        let i = p.mul(p.add(h, h), p.add(h, h))
        let j = p.mul(h, i)
        let rr = p.add(p.sub(s2, s1), p.sub(s2, s1))
        let v = p.mul(u1, i)
        let x3 = p.sub(p.sub(p.mul(rr, rr), j), p.add(v, v))
        let y3 = p.sub(p.mul(rr, p.sub(v, x3)), p.mul(p.add(s1, s1), j))
        let z3 = p.mul(p.sub(p.sub(p.mul(p.add(p1.z, p2.z), p.add(p1.z, p2.z)), z1z1), z2z2), h)
        let r = EcPoint(limbs)
        r.x = x3
        r.y = y3
        r.z = z3
        r.infinity = false
        return r
    }

    /** scalar (big-endian bytes) * pt */
    public func mul(pt: EcPoint, scalar: Array<UInt8>): EcPoint {
        var r = EcPoint(limbs)
        let bits = scalar.size * 8
        var i = bits - 1
        while (i >= 0) {
            r = double(r)
            let byte = scalar[scalar.size - 1 - i / 8]
            if (((byte >> UInt8(i % 8)) & 1) == 1) {
                r = add(r, pt)
            }
            i--
        }
        return r
    }

    public func toAffineX(pt: EcPoint): BigUint {
        if (pt.infinity) {
            return BigUint(limbs)
        }
        let zinv = p.inverse(pt.z)
        let zinv2 = p.mul(zinv, zinv)
        return p.fromMont(p.mul(pt.x, zinv2))
    }

    public func toAffineY(pt: EcPoint): BigUint {
        if (pt.infinity) {
            return BigUint(limbs)
        }
        let zinv = p.inverse(pt.z)
        let zinv3 = p.mul(p.mul(zinv, zinv), zinv)
        return p.fromMont(p.mul(pt.y, zinv3))
    }

    public func decompress(xBytes: Array<UInt8>, odd: Bool): Option<EcPoint> {
        let px = p.toMont(BigUint.fromBytesBE(xBytes, limbs))
        let x3 = p.mul(px, p.mul(px, px))
        let ax = p.mul(aMont, px)
        let rhs = p.add(p.add(x3, ax), b)
        let yMont = p.pow(rhs, sqrtExp)
        if (p.mul(yMont, yMont).cmp(rhs) != 0) {
            return None
        }
        let yPlain = p.fromMont(yMont)
        let isOdd = yPlain.isOdd()
        let ty = if (isOdd == odd) { yMont } else { p.negate(yMont) }
        let pt = EcPoint(limbs)
        pt.x = px
        pt.y = ty
        pt.z = p.one()
        pt.infinity = false
        return Some(pt)
    }

    public func decodePoint(encoded: Array<UInt8>): EcPoint {
        if (encoded.size != 1 + 2 * byteLen || encoded[0] != 4) {
            throw Exception("invalid EC point encoding")
        }
        let x = BigUint.fromBytesBE(sliceBytes(encoded, 1, byteLen), limbs)
        let y = BigUint.fromBytesBE(sliceBytes(encoded, 1 + byteLen, byteLen), limbs)
        if (x.cmp(pPlain) >= 0 || y.cmp(pPlain) >= 0) {
            throw Exception("EC coordinate out of range")
        }
        let point = EcPoint(limbs)
        point.x = p.toMont(x)
        point.y = p.toMont(y)
        point.z = p.one()
        point.infinity = false
        let x3 = p.mul(point.x, p.mul(point.x, point.x))
        let rhs = p.add(p.add(x3, p.mul(aMont, point.x)), b)
        if (p.mul(point.y, point.y).cmp(rhs) != 0) {
            throw Exception("point is not on the curve")
        }
        return point
    }

    /** Verify ECDSA over this curve. `spki` is the uncompressed SEC1 point. */
    public func verify(spki: Array<UInt8>, hash: Array<UInt8>, rBytes: Array<UInt8>,
        sBytes: Array<UInt8>): Bool {
        if (rBytes.size > byteLen || sBytes.size > byteLen) {
            return false
        }
        let q = try {
            decodePoint(spki)
        } catch (e: Exception) {
            return false
        }
        let rPlain = BigUint.fromBytesBE(rBytes, limbs)
        let sPlain = BigUint.fromBytesBE(sBytes, limbs)
        let zero = BigUint(limbs)
        if (rPlain.cmp(zero) <= 0 || sPlain.cmp(zero) <= 0) {
            return false
        }
        if (rPlain.cmp(pPlain) >= 0) {
            return false
        }
        // r,s must be < n
        let nBig = EcCurve.orderPlain(n)
        if (rPlain.cmp(nBig) >= 0 || sPlain.cmp(nBig) >= 0) {
            return false
        }
        let e = BigUint.fromBytesBE(
            if (hash.size >= byteLen) { sliceBytes(hash, 0, byteLen) } else {
                leftPad(hash, byteLen)
            }, limbs)
        let w = n.fromMont(n.inverse(n.toMont(sPlain)))
        let u1 = n.fromMont(n.mul(n.toMont(e), n.toMont(w)))
        let u2 = n.fromMont(n.mul(n.toMont(rPlain), n.toMont(w)))
        let p1 = mul(generator(), u1.toBytesBE(byteLen))
        let p2 = mul(q, u2.toBytesBE(byteLen))
        let sum = add(p1, p2)
        if (sum.infinity) {
            return false
        }
        let xAff = toAffineX(sum)
        let v = xAff.clone()
        if (v.cmp(nBig) >= 0) {
            v.sub(nBig)
        }
        return v.cmp(rPlain) == 0
    }

    private static func orderPlain(n: MontCtx): BigUint {
        let m = BigUint(n.k + 2)
        m.n = n.k
        var i = 0
        while (i < n.k) {
            m.w[i] = n.mod[i]
            i++
        }
        return m
    }

    private static func leftPad(data: Array<UInt8>, size: Int64): Array<UInt8> {
        let out = Array<UInt8>(size, repeat: 0)
        let off = size - data.size
        copyBytes(out, off, data, 0, data.size)
        return out
    }
}

public let CURVE_P256: EcCurve = EcCurve(
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 8)

public let CURVE_P384: EcCurve = EcCurve(
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 12)
