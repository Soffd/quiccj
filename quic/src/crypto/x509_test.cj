package quic.crypto

import std.unittest.*
import std.unittest.testmacro.*
import std.fs.*

@Test
class X509Test {
    @TestCase
    func strictDerObjectIds() {
        @Expect(Der.parse(hexDecode("0603883703")).readOid(), "2.999.3")
        @Expect(oidRejected(hexDecode("06022a80")), true)
        @Expect(oidRejected(hexDecode("06032a8001")), true)
        @Expect(oidRejected(hexDecode("060b2a81808080808080808000")), true)
    }

    @TestCase
    func strictCertificateTime() {
        @Expect(readUtcTime("500101000000Z"), -631152000)
        @Expect(readUtcTime("700101000000Z"), 0)
        @Expect(timeRejected("230229120000Z"), true)
        @Expect(timeRejected("241301000000Z"), true)
        @Expect(timeRejected("240101240000Z"), true)
        @Expect(timeRejected("240101000000+0000"), true)
        @Expect(timeRejected("2401010000Z"), true)
    }

    private func oidRejected(bytes: Array<UInt8>): Bool {
        try {
            Der.parse(bytes).readOid()
            return false
        } catch (e: Exception) {
            return true
        }
    }

    private func readUtcTime(time: String): Int64 {
        let raw = time.toArray()
        return Der.parse(concat([0x17, UInt8(raw.size)], raw)).readTime()
    }

    private func timeRejected(time: String): Bool {
        try {
            readUtcTime(time)
            return false
        } catch (e: Exception) {
            return true
        }
    }

    @TestCase
    func parseCloudflareChain() {
        let pem = String.fromUtf8(File.readFrom("testdata/chain.pem"))
        let blocks = pemCertificates(pem)
        @Expect(blocks.size, 3)
        let leaf = X509Cert.parse(blocks[0])
        println("DBG subject " + leaf.subject.full)
        println("DBG issuer  " + leaf.issuer.full)
        println("DBG keyType " + leaf.keyType + " curve " + leaf.curveOid)
        println("DBG sigAlg  " + leaf.sigAlg)
        println("DBG san0    " + leaf.sans[0])
        println("DBG eku     " + "${leaf.ekuPresent} ${leaf.ekuServerAuth}")
        @Expect(leaf.subject.cn, "cloudflare-quic.com")
        @Expect(leaf.matchesHost("cloudflare-quic.com"), true)
        @Expect(leaf.matchesHost("a.cloudflare-quic.com"), true)
        @Expect(leaf.matchesHost("evil.example"), false)
        @Expect(leaf.keyType, "EC")
    }

    @TestCase
    func verifyCloudflareChain() {
        let chainPem = String.fromUtf8(File.readFrom("testdata/chain.pem"))
        let blocks = pemCertificates(chainPem)
        let chain = Array<X509Cert>(8, repeat: X509Cert())
        var i = 0
        while (i < blocks.size) {
            chain[i] = X509Cert.parse(blocks[i])
            i++
        }
        let store = TrustStore.fromFile("testdata/roots.pem")
        @Expect(store.count, 5)
        // 2026-11-15
        let ok = verifyCertificateChain(chain, blocks.size, store, "cloudflare-quic.com", 1794773559)
        @Expect(ok, true)
        let bad = verifyCertificateChain(chain, blocks.size, store, "wrong.example.com", 1794773559)
        @Expect(bad, false)
    }
}
