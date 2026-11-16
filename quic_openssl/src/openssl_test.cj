package quic_openssl

import quic.crypto.*
import std.unittest.*
import std.unittest.testmacro.*

@Test
class OpenSslTest {
    @TestCase
    func agreesWithPureBackendForP256() {
        let backend = OpenSslBackend()
        let scalar = Array<UInt8>(32, repeat: 0)
        scalar[31] = 2
        let other = Array<UInt8>(32, repeat: 0)
        other[31] = 3
        let peer = PURE_CRYPTO.p256Public(other)
        @Expect(hexEncode(backend.p256Public(scalar)), hexEncode(PURE_CRYPTO.p256Public(scalar)))
        @Expect(hexEncode(backend.p256(scalar, peer)), hexEncode(PURE_CRYPTO.p256(scalar, peer)))
    }

    @TestCase
    func agreesWithPureBackendForDigests() {
        let backend = OpenSslBackend()
        let bytes = "abc".toArray()
        for (alg in [HashAlg.Sha256, HashAlg.Sha384, HashAlg.Sha512]) {
            @Expect(hexEncode(backend.digest(alg, bytes)), hexEncode(hashOf(alg, bytes)))
        }
    }

    @TestCase
    func rejectedPacketDoesNotExposeUnauthenticatedPlaintext() {
        let backend = OpenSslBackend()
        let nonce = Array<UInt8>(12, repeat: 0)
        for (chacha in [false, true]) {
            let key = Array<UInt8>(if (chacha) { 32 } else { 16 }, repeat: 1)
            let packet = concat([1, 2, 3], Array<UInt8>(16, repeat: 0))
            PURE_CRYPTO.seal(chacha, key, nonce, [5], packet, 0, 3)
            packet[18] ^= 1
            let ciphertext = hexEncode(packet)
            @Expect(backend.openPacket(chacha, key, nonce, [5], packet, 0, 3, 3), false)
            @Expect(hexEncode(packet), ciphertext)
            packet[18] ^= 1
            @Expect(backend.openPacket(chacha, key, nonce, [5], packet, 0, 3, 3), true)
            @Expect(hexEncode(sliceBytes(packet, 0, 3)), "010203")
        }
    }

}
