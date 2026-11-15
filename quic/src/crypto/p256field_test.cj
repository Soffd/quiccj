package quic.crypto

import std.unittest.*
import std.unittest.testmacro.*

@Test
class P256FieldTest {
    @TestCase
    func p256MulVectors() {
        let p = CURVE_P256
        let a1 = BigUint.fromBytesBE(hexDecode(
            "73ab48767734d7c1c7fde805ec99108ddb5b5fab8f4d3e27dda1494c73cf256d"), 8)
        let b1 = BigUint.fromBytesBE(hexDecode(
            "79cb9e86830c71c2cdcc69292f45e678309d6b79965eda32dae445508201e2bd"), 8)
        let r1 = p.p.fromMont(p.p.mul(p.p.toMont(a1), p.p.toMont(b1)))
        @Expect(hexEncode(r1.toBytesBE(32)),
            "cd2a6f6ba79d916080d3037a0bbfbaf484de96609193f16d3ae13a2f37742ff8")

        let a2 = BigUint.fromBytesBE(hexDecode(
            "244caf9c4dabb4817253edc6181879932fa91425cb0088539d2c67eda13ffe79"), 8)
        let b2 = BigUint.fromBytesBE(hexDecode(
            "986e86cb0ab8ab67a26b7f62b1852f27e3eff9c0cf44dd3f89e7d15f17362f25"), 8)
        let r2 = p.p.fromMont(p.p.mul(p.p.toMont(a2), p.p.toMont(b2)))
        @Expect(hexEncode(r2.toBytesBE(32)),
            "7fee2239059d5516377a8e8ac4f28b1061dacfb5915929238b76ec75e3a334bb")
    }
}
