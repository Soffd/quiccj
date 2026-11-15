package quic.crypto

import std.unittest.*
import std.unittest.testmacro.*
import std.fs.*

@Test
class X509Test {
    static func readText(path: String): String {
        let f = File(path, OpenMode.Read)
        let buf = Array<UInt8>(65536, repeat: 0)
        let n = f.read(buf)
        f.close()
        return String.fromUtf8(sliceBytes(buf, 0, n))
    }

    @TestCase
    func parseCloudflareChain() {
        let pem = readText("testdata/chain.pem")
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
        let chainPem = readText("testdata/chain.pem")
        let rootsPem = readText("testdata/roots.pem")
        let blocks = pemCertificates(chainPem)
        let chain = Array<X509Cert>(8, repeat: X509Cert())
        var i = 0
        while (i < blocks.size) {
            chain[i] = X509Cert.parse(blocks[i])
            i++
        }
        let store = TrustStore()
        store.addPem(rootsPem)
        @Expect(store.count, 5)
        // 2026-11-15
        let ok = verifyCertificateChain(chain, blocks.size, store, "cloudflare-quic.com", 1794773559)
        @Expect(ok, true)
        let bad = verifyCertificateChain(chain, blocks.size, store, "wrong.example.com", 1794773559)
        @Expect(bad, false)
    }
}
