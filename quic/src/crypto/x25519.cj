package quic.crypto

/*
 * X25519 (RFC 7748) built on the generic Montgomery arithmetic.
 */

public class X25519 {
    private static func pCtx(): MontCtx {
        let m = Array<UInt32>(8, repeat: 0)
        m[0] = 0xFFFF_FFED
        var i = 1
        while (i < 7) {
            m[i] = 0xFFFF_FFFF
            i++
        }
        m[7] = 0x7FFF_FFFF
        return MontCtx(m, 8)
    }

    public static func clamp(scalar: Array<UInt8>): Array<UInt8> {
        let k = Array<UInt8>(32, repeat: 0)
        copyBytes(k, 0, scalar, 0, if (scalar.size < 32) { scalar.size } else { 32 })
        k[0] = k[0] & 248
        k[31] = (k[31] & 127) | 64
        return k
    }

    /** Compute the X25519 function: scalar * u. */
    public static func scalarmult(scalar: Array<UInt8>, u: Array<UInt8>): Array<UInt8> {
        let ctx = pCtx()
        let k = clamp(scalar)
        let uBytes = Array<UInt8>(32, repeat: 0)
        copyBytes(uBytes, 0, u, 0, if (u.size < 32) { u.size } else { 32 })
        // mask the top bit per RFC 7748 decodeUCoordinate
        uBytes[31] = uBytes[31] & 127

        let x1 = ctx.toMont(BigUint.fromBytesLE(uBytes, 8))
        let one = ctx.one()
        let zero = BigUint(8)
        var x2 = one
        var z2 = zero
        var x3 = x1
        var z3 = one
        let a24 = ctx.toMont(BigUint.fromUInt64(121665, 8))
        var swap = false

        var t = 254
        while (t >= 0) {
            let kt = ((k[t / 8] >> UInt8(t % 8)) & 1) == 1
            swap = swap != kt
            if (swap) {
                let tx = x2
                x2 = x3
                x3 = tx
                let tz = z2
                z2 = z3
                z3 = tz
            }
            swap = kt
            let a = ctx.add(x2, z2)
            let aa = ctx.mul(a, a)
            let b = ctx.sub(x2, z2)
            let bb = ctx.mul(b, b)
            let e = ctx.sub(aa, bb)
            let c = ctx.add(x3, z3)
            let d = ctx.sub(x3, z3)
            let da = ctx.mul(d, a)
            let cb = ctx.mul(c, b)
            let dacb = ctx.add(da, cb)
            let dacb2 = ctx.mul(dacb, dacb)
            let damcb = ctx.sub(da, cb)
            let damcb2 = ctx.mul(damcb, damcb)
            x3 = dacb2
            z3 = ctx.mul(x1, damcb2)
            x2 = ctx.mul(aa, bb)
            let t1 = ctx.mul(a24, e)
            let t2 = ctx.add(aa, t1)
            z2 = ctx.mul(e, t2)
            t--
        }
        if (swap) {
            let tx = x2
            x2 = x3
            x3 = tx
            let tz = z2
            z2 = z3
            z3 = tz
        }
        let inv = ctx.inverse(z2)
        let out = ctx.mul(x2, inv)
        return ctx.fromMont(out).toBytesLE(32)
    }

    public static func basePoint(): Array<UInt8> {
        let b = Array<UInt8>(32, repeat: 0)
        b[0] = 9
        return b
    }

    public static func publicKey(privateKey: Array<UInt8>): Array<UInt8> {
        return scalarmult(privateKey, basePoint())
    }
}
