package quic.crypto

import std.unittest.*
import std.unittest.testmacro.*
import std.fs.*

@Test
class X509Test {
    @TestCase
    func ed25519Rfc8032Vector() {
        let key = hexDecode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        let sig = hexDecode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        @Expect(verifyEd25519(key, [], sig), true)
        @Expect(verifyEd25519(key, [1], sig), false)
        sig[63] |= 128
        @Expect(verifyEd25519(key, [], sig), false)
    }

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
    func negativePathAndLeafPolicies() {
        let chain = pemCertificates(String.fromUtf8(File.readFrom("testdata/chain.pem")))
        let leaf = X509Cert.parse(chain[0])
        let intermediate = X509Cert.parse(chain[1])
        let root = TrustStore()
        root.addDer(chain[2])
        let at = leaf.notBefore + 1
        for (backend in [PURE_CRYPTO, NativeCryptoBackend()]) {
            @Expect(backend.verifyChain([leaf, intermediate], 2, root, "cloudflare-quic.com", at), true)
            @Expect(backend.verifyChain([leaf], 1, root, "cloudflare-quic.com", at), false)
            @Expect(backend.verifyChain([leaf, intermediate], 2, root, "cloudflare-quic.com", leaf.notAfter + 1), false)
            @Expect(backend.verifyChain([leaf, intermediate], 2, root, "cloudflare-quic.com", leaf.notBefore - 1), false)
            @Expect(backend.verifyChain([leaf, intermediate], 2, root, "a.b.cloudflare-quic.com", at), false)
            @Expect(backend.verifyChain([leaf, intermediate], 2, root, "wrong.example", at), false)
        }
        @Expect(leaf.matchesHost("a..cloudflare-quic.com"), false)
        @Expect(intermediate.permitsServer(at), false)
        root.requireCrl = true
        for (backend in [PURE_CRYPTO, NativeCryptoBackend()]) {
            @Expect(backend.verifyChain([leaf, intermediate], 2, root, "cloudflare-quic.com", at), false)
        }
    }

    @TestCase
    func malformedAnchorCannotPartiallyUpdateStore() {
        let store = TrustStore()
        let pem = String.fromUtf8(File.readFrom("testdata/roots.pem"))
        for (suffix in ["-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----!-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----AA==-----END CERTIFICATE-----"]) {
            var rejected = false
            try { store.addPem(pem + suffix) } catch (e: Exception) { rejected = true }
            @Expect(rejected, true)
            @Expect(store.count, 0)
        }
    }

    @TestCase
    func idnaHostUsesWireName() {
        @Expect(asciiHost("中文.example"), "xn--fiq228c.example")
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
