package quic.transport

import quic.crypto.*
import std.unittest.*
import std.unittest.testmacro.*

@Test
class PacketTest {
    @TestCase
    func rfc9001InitialSecrets() {
        let dcid = hexDecode("8394c8f03e515708")
        let (c, s) = PacketCrypto.initialSecrets(dcid)
        @Expect(hexEncode(c.key), "1f369613dd76d5467730efcbe3b1a22d")
        @Expect(hexEncode(c.iv), "fa044b2f42a3fd3b46fb255c")
        @Expect(hexEncode(c.hp), "9f50449e04a0e810283a1e9933adedd2")
        @Expect(hexEncode(s.key), "cf3a5331653c364c88f0f379b6067e37")
        @Expect(hexEncode(s.iv), "0ac1493ca1905853b0bba03e")
        @Expect(hexEncode(s.hp), "c206b8d9b9f0f37644430b490eeaa314")
    }

    @TestCase
    func varintRoundTrip() {
        let values: Array<UInt64> = [0, 37, 15293, 494878333, 151288809941952652]
        var i = 0
        while (i < values.size) {
            let w = ByteWriter(8)
            Varint.write(w, values[i])
            let r = ByteReader(w.toArray())
            @Expect(Varint.read(r), values[i])
            i++
        }
        // canonical encodings
        let w = ByteWriter(8)
        Varint.write(w, 494878333)
        @Expect(hexEncode(w.toArray()), "9d7f3e7d")
    }

    @TestCase
    func transportParamsRoundTrip() {
        let p = TransportParams()
        p.initialSourceConnectionId = hexDecode("0011223344556677")
        p.maxIdleTimeout = 30000
        p.initialMaxData = 1000000
        let enc = p.encode()
        let q = TransportParams.decode(enc)
        @Expect(q.maxIdleTimeout, 30000)
        @Expect(q.initialMaxData, 1000000)
        @Expect(hexEncode(q.initialSourceConnectionId), "0011223344556677")
    }
}
