package quic.crypto

import std.unittest.*
import std.unittest.testmacro.*

@Test
class Sha2Test {
    @TestCase
    func sha256KnownAnswers() {
        @Expect(hexEncode(sha256("".toArray())),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        @Expect(hexEncode(sha256("abc".toArray())),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        @Expect(hexEncode(sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toArray())),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        let million = Array<UInt8>(1000000, repeat: 97)
        @Expect(hexEncode(sha256(million)),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }

    @TestCase
    func sha384KnownAnswers() {
        @Expect(hexEncode(sha384("".toArray())),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
        @Expect(hexEncode(sha384("abc".toArray())),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")
    }

    @TestCase
    func sha512KnownAnswers() {
        @Expect(hexEncode(sha512("".toArray())),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
        @Expect(hexEncode(sha512("abc".toArray())),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
    }

    @TestCase
    func streamingMatchesOneShot() {
        let msg = Array<UInt8>(200, repeat: 0)
        var i = 0
        while (i < msg.size) {
            msg[i] = UInt8(i & 0xFF)
            i++
        }
        let one = sha256(msg)
        let h = Sha256()
        // Feed in awkward chunks crossing the 64-byte block boundary.
        h.update(msg, 0, 1)
        h.update(msg, 1, 62)
        h.update(msg, 63, 64)
        h.update(msg, 127, 73)
        @Expect(hexEncode(h.finish()), hexEncode(one))
        let s = Sha512.sha384()
        s.update(msg, 0, 100)
        s.update(msg, 100, 100)
        @Expect(hexEncode(s.finish()), hexEncode(sha384(msg)))
    }

    @TestCase
    func hexRoundTrip() {
        let b = hexDecode("00ff10abcdef")
        @Expect(b.size, 6)
        @Expect(b[0], 0)
        @Expect(b[1], 255)
        @Expect(hexEncode(b), "00ff10abcdef")
    }
}
