package quic.http3

import quic.crypto.*
import std.unittest.*
import std.unittest.testmacro.*

@Test
class QpackTest {
    @TestCase
    func allStaticEntriesAndMultibyteIndex() {
        @Expect(QPACK_STATIC.size / 2, 99)
        let field = H3Header()
        field.name = "x-frame-options"
        field.value = "sameorigin"
        let encoded = qpackEncode([field])
        @Expect(hexEncode(encoded), "0000ff23")
        @Expect(qpackDecode(encoded, [], 0)[0].value, "sameorigin")
    }

    @TestCase
    func huffmanNameAndValue() {
        @Expect(String.fromUtf8(huffmanDecode(hexDecode("f1e3c2e5f23a6ba0ab90f4ff"))),
            "www.example.com")
        let block = hexDecode("00002df2b543a4bf0161")
        @Expect(qpackDecode(block, [], 0)[0].name, "x-name")
    }

    @TestCase
    func dynamicAbsoluteAndPostBaseIndices() {
        let decoder = QpackDecoder()
        decoder.instruction(ByteReader([0x3f, 0x21])) // capacity 64
        decoder.instruction(ByteReader(hexDecode("c003616263")))
        let relative = decoder.fields([2, 0, 0x80])[0]
        let postBase = decoder.fields([2, 0x80, 0x10])[0]
        @Expect(relative[0].name, ":authority")
        @Expect(relative[0].value, "abc")
        @Expect(postBase[0].value, "abc")
    }
}
