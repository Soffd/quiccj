package quic.crypto

import std.unittest.*
import std.unittest.testmacro.*

@Test
class X25519Test {
    @TestCase
    func rfc7748Vectors() {
        let k1 = hexDecode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        let u1 = hexDecode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        println("DBG x25519: " + hexEncode(X25519.scalarmult(k1, u1)))
        @Expect(hexEncode(X25519.scalarmult(k1, u1)),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

        let k2 = hexDecode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        let u2 = hexDecode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
        @Expect(hexEncode(X25519.scalarmult(k2, u2)),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    }

    @TestCase
    func rfc7748DiffieHellman() {
        let alicePriv = hexDecode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let bobPriv = hexDecode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        let alicePub = X25519.publicKey(alicePriv)
        let bobPub = X25519.publicKey(bobPriv)
        @Expect(hexEncode(alicePub),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        @Expect(hexEncode(bobPub),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        let s1 = X25519.scalarmult(alicePriv, bobPub)
        let s2 = X25519.scalarmult(bobPriv, alicePub)
        @Expect(hexEncode(s1), hexEncode(s2))
        @Expect(hexEncode(s1),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    }
}
