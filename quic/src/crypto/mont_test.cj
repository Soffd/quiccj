package quic.crypto

import std.unittest.*
import std.unittest.testmacro.*

@Test
class MontFieldTest {
    static func p25519(): MontCtx {
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

    static func mulMod(ctx: MontCtx, ah: String, bh: String): String {
        let a = BigUint.fromBytesBE(hexDecode(ah), 8)
        let b = BigUint.fromBytesBE(hexDecode(bh), 8)
        let r = ctx.fromMont(ctx.mul(ctx.toMont(a), ctx.toMont(b)))
        return hexEncode(r.toBytesBE(32))
    }

    @TestCase
    func randomMul() {
        let ctx = p25519()
        @Expect(mulMod(ctx, "691f8412128b2f330c5c7fd0a6a3a4506513270e269e0d37f2a74de452e6b438",
            "1b7b3ae681e74ef5e8e25d940ed904759531985d5d9dc9f81818e811892f902b"),
            "0fe6eb9ad8658698a8aab758303c133e2f4f833986a64bfc17a85dfcee5bd51d")
        @Expect(mulMod(ctx, "4688b7671738f7d93d9c172411e20b8f6b0d549b6f03675a1600a35a099950d8",
            "50b8599c39263059f28c105d1fb17c2390c192cfd3ac94af0f21ddb66cad4a26"),
            "715bfcabff4b9babae7867e6335a0dd0eefe459d9b7b53a495176ccae4eed899")
        @Expect(mulMod(ctx, "0658f14e658cda1495e60af593bd04cf0fd630f1f29d0da9953f48f1a09f76b5",
            "35a659214a23d5962217beaddbc496cb8e81973e0becd7b03898d190f9ebdacc"),
            "1dd96095f5f127da3d3fba035303ccac3382b33a1d9146a38dc38e57012d962f")
        @Expect(mulMod(ctx, "574bdd4ad0eda82f8f6d05584ef8aa38922766581e27a1c08a6a63ec24ede6a4",
            "0c789ae95f557203301850c5a38fd547923a736994e3bf911a61dbe22e44158b"),
            "5c835259d34ead88e4bcc278ab478695ce828cd85c2d0f423e087e81a562a86b")
    }

    @TestCase
    func randomPow() {
        let ctx = p25519()
        let a = BigUint.fromBytesBE(hexDecode(
            "3f8a829234b9b5df9e7769b10f4205b4907a70c31012f037b64ce4228c38fb29"), 8)
        let e = BigUint.fromBytesBE(hexDecode(
            "763353c395e761d17731af10506bf2efc6f877186d76b07e881ed162ae2eb154"), 8)
        let r = ctx.fromMont(ctx.pow(ctx.toMont(a), e))
        @Expect(hexEncode(r.toBytesBE(32)),
            "3ed6de9e8f7aff03f287efc9d59df0d1cc93f03d14b81866fadc1bb462aa64ef")
    }
}
