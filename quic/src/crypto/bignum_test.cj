package quic.crypto

import std.unittest.*
import std.unittest.testmacro.*

@Test
class BigUintTest {
    static func p25519(): MontCtx {
        // p = 2^255 - 19, 8 little-endian 32-bit limbs
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

    static func mulMod(ctx: MontCtx, a: BigUint, b: BigUint): BigUint {
        let am = ctx.toMont(a)
        let bm = ctx.toMont(b)
        return ctx.fromMont(ctx.mul(am, bm))
    }

    @TestCase
    func montMulAndPow() {
        let ctx = p25519()
        let a = BigUint.fromBytesBE(hexDecode(
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"), 8)
        let b = BigUint.fromBytesBE(hexDecode(
            "1f4b4e2c9d0d5b3a4a1f3f0a9c8b7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c"), 8)
        let prod = mulMod(ctx, a, b)
        @Expect(hexEncode(prod.toBytesBE(32)),
            "4544a0d9cda70f15b1f12beeb9cf893c1e81047f6bf265281e967d43ac1a660e")

        let three = BigUint.fromUInt64(3, 8)
        let e = BigUint.fromUInt64(1000, 8)
        let am = ctx.toMont(three)
        let pw = ctx.pow(am, e)
        @Expect(hexEncode(ctx.fromMont(pw).toBytesBE(32)),
            "3b62e66d29506d8b00f2640821913c54344233c23b1b7ca4d497cb0083629939")

        let inv = ctx.fromMont(ctx.inverse(ctx.toMont(a)))
        @Expect(hexEncode(inv.toBytesBE(32)),
            "6df4433f6383824572761aa75b416e3f7c1c4f77410b39d5bcf573c357635f58")
    }

    @TestCase
    func bytesRoundTrip() {
        let a = BigUint.fromBytesBE(hexDecode("0102030405060708090a0b0c0d0e0f"), 8)
        @Expect(hexEncode(a.toBytesBE(15)), "0102030405060708090a0b0c0d0e0f")
        let b = BigUint.fromBytesBE(hexDecode("00"), 8)
        @Expect(b.isZero(), true)
    }
}
