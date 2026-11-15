package quic.crypto

import std.unittest.*
import std.unittest.testmacro.*

@Test
class P256Test {
    @TestCase
    func ecdsaVerifyOpensslVector() {
        let p = CURVE_P256
        let pub = hexDecode(
            "046a6ae8d3145877fa98b102e1207a1fb0b5dfee5422087236297d4a2d6ac07faad63a7e05929c05ebddd955508d0f36af74de268cc14f88edec841777cee27828")
        let msg = "cangjie quic test message".toArray()
        let h = sha256(msg)
        let r = hexDecode("ee7650508efc2ea482a4aee661b1471e8d8763dfda83e87199eeeac8af19aef5")
        let s = hexDecode("685f4a2e0e7740cf3a1c99845a0ba65d04918a0fb8d994b7e1c2787c2e469e39")
        @Expect(p.verify(pub, h, r, s), true)
        let h2 = sha256("cangjie quic test messagX".toArray())
        @Expect(p.verify(pub, h2, r, s), false)
    }

    @TestCase
    func pointDecompressMatches() {
        let p = CURVE_P256
        let pub = hexDecode(
            "046a6ae8d3145877fa98b102e1207a1fb0b5dfee5422087236297d4a2d6ac07faad63a7e05929c05ebddd955508d0f36af74de268cc14f88edec841777cee27828")
        let q = p.decompress(sliceBytes(pub, 1, 32), (pub[64] & 1) == 1)
        @Expect(q.isSome(), true)
        let aff = p.toAffineY(q.getOrThrow())
        println("DBG affineY " + hexEncode(aff.toBytesBE(32)))
        println("DBG affineX " + hexEncode(p.toAffineX(q.getOrThrow()).toBytesBE(32)))
        @Expect(hexEncode(aff.toBytesBE(32)),
            "d63a7e05929c05ebddd955508d0f36af74de268cc14f88edec841777cee27828")
    }
}
