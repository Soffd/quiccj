package quic.tls

import quic.crypto.*
import std.fs.File
import std.unittest.*
import std.unittest.testmacro.*

@Test
class TlsRetryTest {
    @TestCase
    func helloRetryRequestsP256AndUsesMessageHash() {
        let client = TlsClient("localhost", "h3", [1], TrustStore(), false)
        let firstHello = client.start()
        let retryExtensions = ByteWriter()
        retryExtensions.putU16(0x002b)
        retryExtensions.putVec16([3, 4])
        retryExtensions.putU16(0x0033)
        retryExtensions.putVec16([0, 0x17])
        retryExtensions.putU16(0x002c)
        retryExtensions.putVec16([0, 1, 0x42])
        let hrr = serverHello(
            hexDecode("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"),
            retryExtensions.toArray())
        client.onData(hrr, cryptoSpace: 0)
        @Assert(client.state, 1)
        let secondHello = client.takeOutput()
        let clientExtensions = ByteReader(secondHello, 4, secondHello.size)
        clientExtensions.readBytes(34)
        clientExtensions.readVec8()
        clientExtensions.readVec16()
        clientExtensions.readVec8()
        let extensions = ByteReader(clientExtensions.readVec16())
        var clientPublic: Array<UInt8> = []
        var cookiePresent = false
        while (!extensions.eof()) {
            let kind = extensions.readU16()
            let value = ByteReader(extensions.readVec16())
            if (kind == 0x0033) {
                let entry = ByteReader(value.readVec16())
                @Expect(entry.readU16(), 0x0017)
                clientPublic = entry.readVec16()
            } else if (kind == 0x002c) {
                @Expect(hexEncode(value.readVec16()), "42")
                cookiePresent = true
            }
        }
        @Assert(cookiePresent, true)
        @Assert(clientPublic.size, 65)
        let peerPrivate = Array<UInt8>(32, repeat: 0)
        peerPrivate[31] = 1
        let peerPublic = PURE_CRYPTO.p256Public(peerPrivate)
        let serverExtensions = ByteWriter()
        serverExtensions.putU16(0x002b)
        serverExtensions.putVec16([3, 4])
        serverExtensions.putU16(0x0033)
        let share = ByteWriter()
        share.putU16(0x0017)
        share.putVec16(peerPublic)
        serverExtensions.putVec16(share.toArray())
        let hello = serverHello(Array<UInt8>(32, repeat: 0x5a), serverExtensions.toArray())
        client.onData(hello, cryptoSpace: 0)
        @Assert(client.state, 2)
        // With private scalar 1, the shared secret is the client's affine x coordinate.
        let shared = sliceBytes(clientPublic, 1, 32)
        let alg = HashAlg.Sha256
        let zero = Array<UInt8>(32, repeat: 0)
        let early = hkdfExtract(alg, zero, zero)
        let handshake = hkdfExtract(alg, deriveSecret(alg, early, "derived", sha256([])), shared)
        let transcript = ByteWriter()
        transcript.putBytes([254, 0, 0, 32])
        transcript.putBytes(sha256(firstHello))
        transcript.putBytes(hrr)
        transcript.putBytes(secondHello)
        transcript.putBytes(hello)
        let expected = deriveSecret(alg, handshake, "s hs traffic", sha256(transcript.toArray()))
        @Expect(hexEncode(client.serverHs.secret), hexEncode(expected))
    }

    @TestCase
    func wrongCryptoSpaceRejectsHandshakeMessages() {
        let client = TlsClient("localhost", "h3", [1], TrustStore(), false)
        client.start()
        client.onData([2, 0, 0, 0], cryptoSpace: 1)
        @Expect(client.state, 7)
        @Expect(client.failure.contains("wrong QUIC encryption level"), true)
    }

    @TestCase
    func cryptoSpacesDoNotSharePartialTlsMessages() {
        let client = TlsClient("localhost", "h3", [1], TrustStore(), false)
        client.start()
        client.onData([2, 0], cryptoSpace: 0)
        client.onData([4, 0], cryptoSpace: 2)
        @Expect(client.state, 1)
        client.onData([0, 0], cryptoSpace: 0)
        @Expect(client.state, 7)
        @Expect(client.failure.contains("wrong QUIC encryption level"), false)
    }

    @TestCase
    func downgradeAndWrongFinishedAreRejected() {
        let downgrade = TlsClient("localhost", "h3", [1], TrustStore(), false)
        downgrade.start()
        downgrade.onData(serverHello(Array<UInt8>(32, repeat: 1), [0, 43, 0, 2, 3, 3]))
        @Expect(downgrade.state, 7)
        @Expect(downgrade.failure.contains("TLS 1.3"), true)

        let chain = pemCertificates(String.fromUtf8(File.readFrom("testdata/chain.pem")))
        let host = "cloudflare-quic.com"
        let store = TrustStore()
        store.addDer(chain[2])
        let ticket = TlsTicket(host, "h3", [1], Array<UInt8>(32, repeat: 42), 0x1301, 0, 60, false,
            [X509Cert.parse(chain[0]), X509Cert.parse(chain[1])])
        let options = TlsOptions(verificationTime: { => 1794773559 })
        let noTrust = TlsClient(host, "h3", [1], TrustStore(), true, ticket: Some(ticket), options: options)
        let expired = TlsClient(host, "h3", [1], store, true, ticket: Some(ticket),
            options: TlsOptions(verificationTime: { => 2000000000 }))
        for (rejected in [noTrust, expired]) {
            let hello = rejected.start()
            let body = ByteReader(hello, 4, hello.size)
            body.readBytes(34)
            body.readVec8()
            body.readVec16()
            body.readVec8()
            let extensions = ByteReader(body.readVec16())
            while (!extensions.eof()) {
                @Expect(extensions.readU16() == 41, false)
                extensions.readVec16()
            }
            rejected.destroy()
        }
        let client = TlsClient(host, "h3", [1], store, true, ticket: Some(ticket), options: options)
        client.start()
        let exts = ByteWriter()
        exts.putBytes([0, 43, 0, 2, 3, 4, 0, 41, 0, 2, 0, 0])
        let pub = Array<UInt8>(32, repeat: 0)
        pub[0] = 9
        exts.putBytes([0, 51, 0, 36, 0, 29, 0, 32])
        exts.putBytes(pub)
        client.onData(serverHello(Array<UInt8>(32, repeat: 1), exts.toArray()))
        @Assert(client.state, 2)
        client.onData([8, 0, 0, 16, 0, 14, 0, 16, 0, 5, 0, 3, 2, 104, 51, 0, 57, 0, 1, 0])
        @Assert(client.state, 3)
        let traffic = client.serverHs.secret
        client.onData(concat([20, 0, 0, 32], Array<UInt8>(32, repeat: 0)))
        @Expect(client.failure.contains("Finished"), true)
        @Expect(client.handshakeComplete, false)
        @Expect(ctEqual(traffic, Array<UInt8>(32, repeat: 0)), true)
        @Expect(ticket.usable(host, "h3"), true)
        ticket.destroy()
        @Expect(ticket.usable(host, "h3"), false)
    }

    private func serverHello(random: Array<UInt8>, extensions: Array<UInt8>): Array<UInt8> {
        let body = ByteWriter()
        body.putU16(0x0303)
        body.putBytes(random)
        body.putVec8([])
        body.putU16(0x1301)
        body.putU8(0)
        body.putVec16(extensions)
        let message = ByteWriter()
        message.putU8(2)
        message.putVec24(body.toArray())
        return message.toArray()
    }
}
