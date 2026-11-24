package quic.http3

import std.unittest.*
import std.unittest.testmacro.*
import std.fs.File
import std.env.getVariable
import std.convert.Parsable
import quic.crypto.*
import quic.transport.Varint

@Test
class ParserMutationTest {
    @TestCase
    @OverflowWrapping
    func mutateWireFormats() {
        let cert = pemCertificates(String.fromUtf8(File.readFrom("testdata/chain.pem")))[0]
        let seeds = [cert, hexDecode("0103020020"), hexDecode("0280004000"), hexDecode("0000d9"),
            hexDecode("ffffffffffffffff")]
        let iterations = Int64.parse(getVariable("QUICCJ_FUZZ_CASES").getOrDefault({ => "1024" }))
        var state = UInt32.parse(getVariable("QUICCJ_FUZZ_SEED").getOrDefault({ => "20261124" }))
        for (i in 0..iterations) {
            let seed = seeds[i % seeds.size]
            state = state * 1664525 + 1013904223
            let size = if (i % 3 == 0) { Int64(state) % (seed.size + 1) } else { seed.size }
            let data = seed[0..size].clone()
            for (_ in 0..(i % 8 + 1)) {
                state = state * 1664525 + 1013904223
                if (size > 0) { data[Int64(state >> 8) % size] ^= UInt8(state & 255) }
            }
            for (target in 0..4) {
                try {
                    match (target) {
                        case 0 => X509Cert.parse(data); ()
                        case 1 => Varint.read(ByteReader(data)); ()
                        case 2 => readFrame(ByteReader(data)); ()
                        case _ => qpackDecode(data, [], 0); ()
                    }
                } catch (bounds: IndexOutOfBoundsException) {
                    throw bounds
                } catch (rejected: Exception) {
                    // Malformed inputs are an expected parse outcome. Panics escape the harness.
                }
            }
        }
    }
}
