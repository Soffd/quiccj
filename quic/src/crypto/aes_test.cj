package quic.crypto

import std.unittest.*
import std.unittest.testmacro.*

@Test
class AesTest {
    @TestCase
    func aes128Block() {
        let key = hexDecode("000102030405060708090a0b0c0d0e0f")
        let pt = hexDecode("00112233445566778899aabbccddeeff")
        let out = Array<UInt8>(16, repeat: 0)
        Aes(key).encryptBlock(pt, 0, out, 0)
        @Expect(hexEncode(out), "69c4e0d86a7b0430d8cdb78070b4c55a")
    }

    @TestCase
    func aes256Block() {
        let key = hexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let pt = hexDecode("00112233445566778899aabbccddeeff")
        let out = Array<UInt8>(16, repeat: 0)
        Aes(key).encryptBlock(pt, 0, out, 0)
        @Expect(hexEncode(out), "8ea2b7ca516745bfeafc49904b496089")
    }

    @TestCase
    func gcmEmpty() {
        let key = hexDecode("00000000000000000000000000000000")
        let nonce = hexDecode("000000000000000000000000")
        let tag = Array<UInt8>(16, repeat: 0)
        let data = Array<UInt8>(0, repeat: 0)
        AesGcm(key).seal(nonce, [], data, 0, 0, tag, 0)
        @Expect(hexEncode(tag), "58e2fccefa7e3061367f1d57a4e7455a")
    }

    @TestCase
    func gcmSingleBlock() {
        let key = hexDecode("00000000000000000000000000000000")
        let nonce = hexDecode("000000000000000000000000")
        let out = aesGcmSeal(key, nonce, [],
            hexDecode("00000000000000000000000000000000"))
        @Expect(hexEncode(out),
            "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
    }

    @TestCase
    func gcmAadVector() {
        let key = hexDecode("feffe9928665731c6d6a8f9467308308")
        let nonce = hexDecode("cafebabefacedbaddecaf888")
        let pt = hexDecode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
        let aad = hexDecode("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        let out = aesGcmSeal(key, nonce, aad, pt)
        @Expect(hexEncode(sliceBytes(out, 0, 60)),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
        @Expect(hexEncode(sliceBytes(out, 60, 16)), "5bc94fbc3221a5db94fae95ae7121a47")
    }

    @TestCase
    func gcmRoundTripAndTamper() {
        let key = hexDecode("0123456789abcdef0123456789abcdef")
        let nonce = hexDecode("00112233445566778899aabb")
        let pt = hexDecode("deadbeefcafebabe00112233445566778899")
        let aad = hexDecode("a1a2a3a4a5")
        let sealed = aesGcmSeal(key, nonce, aad, pt)
        let opened = aesGcmOpen(key, nonce, aad, sealed)
        @Expect(opened.isSome(), true)
        @Expect(hexEncode(opened.getOrThrow()), hexEncode(pt))
        sealed[3] = sealed[3] ^ 1
        @Expect(aesGcmOpen(key, nonce, aad, sealed).isNone(), true)
    }
}
