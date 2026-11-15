package quic.tls

import quic.crypto.*
import std.fs.*
import std.time.*

/*
 * TLS 1.3 client handshake, QUIC profile (RFC 9001 §4): no record layer.
 * Supports TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384 with X25519 or
 * P-256 key exchange, and verifies the server certificate chain.
 */

public class TlsDirection {
    public var key: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var iv: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var hp: Array<UInt8> = Array<UInt8>(0, repeat: 0)
}

public class TlsClient {
    public let host: String
    public let alpnList: Array<String>
    public let quicParams: Array<UInt8>
    public let store: TrustStore
    public var debug: Bool = false
    public let verifyPeer: Bool

    private var x25519Priv: Array<UInt8>
    private var x25519Pub: Array<UInt8>
    private var clientRandom: Array<UInt8>
    private var sessionId: Array<UInt8>
    private var transcript: ByteWriter
    private var hsBuf: ByteWriter
    private var outBuf: ByteWriter

    public var state: Int64
    public var failure: String
    public var cipherSuite: Int64
    public var hashAlg: HashAlg
    public var keyLen: Int64
    public var clientHs: TlsDirection
    public var serverHs: TlsDirection
    public var clientApp: TlsDirection
    public var serverApp: TlsDirection
    public var negotiatedAlpn: String
    public var peerParams: Array<UInt8>
    public var peerCert: X509Cert
    public var hasPeerCert: Bool
    public var handshakeComplete: Bool
    private var handshakeSecret: Array<UInt8>
    private var masterSecret: Array<UInt8>
    private var serverHsSecret: Array<UInt8>
    private var clientHsSecret: Array<UInt8>

    public init(host: String, alpn: String, quicParams: Array<UInt8>, store: TrustStore,
        verifyPeer: Bool) {
        this.host = host
        this.alpnList = [alpn]
        this.quicParams = quicParams
        this.store = store
        this.verifyPeer = verifyPeer
        x25519Priv = randomBytes(32)
        x25519Pub = X25519.publicKey(x25519Priv)
        clientRandom = randomBytes(32)
        sessionId = randomBytes(32)
        transcript = ByteWriter(4096)
        hsBuf = ByteWriter(4096)
        outBuf = ByteWriter(4096)
        state = 0
        failure = ""
        cipherSuite = 0
        hashAlg = HashAlg.Sha256
        keyLen = 16
        clientHs = TlsDirection()
        serverHs = TlsDirection()
        clientApp = TlsDirection()
        serverApp = TlsDirection()
        negotiatedAlpn = ""
        peerParams = Array<UInt8>(0, repeat: 0)
        peerCert = X509Cert()
        hasPeerCert = false
        handshakeComplete = false
        handshakeSecret = Array<UInt8>(0, repeat: 0)
        masterSecret = Array<UInt8>(0, repeat: 0)
        serverHsSecret = Array<UInt8>(0, repeat: 0)
        clientHsSecret = Array<UInt8>(0, repeat: 0)
    }

    private func hashLen(): Int64 {
        return hashSize(hashAlg)
    }

    private func transcriptHash(): Array<UInt8> {
        return hashOf(hashAlg, transcript.toArray())
    }

    private func addTranscript(msg: Array<UInt8>): Unit {
        transcript.putBytes(msg)
    }

    private func buildClientHello(): Array<UInt8> {
        let body = ByteWriter(1024)
        body.putU8(0x03)
        body.putU8(0x03)
        body.putBytes(clientRandom)
        // RFC 9001 section 8.4: QUIC forbids the TLS 1.3 middlebox-compat session id.
        body.putVec8(Array<UInt8>(0, repeat: 0))
        // cipher suites
        body.putU16(4)
        body.putU16(0x1301) // TLS_AES_128_GCM_SHA256
        body.putU16(0x1302) // TLS_AES_256_GCM_SHA384
        body.putU8(1)
        body.putU8(0) // null compression

        let ext = ByteWriter(512)
        // server_name: ServerNameList -> ServerName{ name_type, HostName }
        let sni = ByteWriter(64)
        let hostBytes = host.toArray()
        sni.putU16(UInt16(1 + 2 + hostBytes.size))
        sni.putU8(0) // host_name
        sni.putVec16(hostBytes)
        ext.putU16(0x0000)
        ext.putVec16(sni.toArray())

        // supported_groups: x25519, secp256r1
        let groups = ByteWriter(16)
        groups.putU16(4)
        groups.putU16(0x001d)
        groups.putU16(0x0017)
        ext.putU16(0x000a)
        ext.putVec16(groups.toArray())

        // signature_algorithms
        let sigs = ByteWriter(32)
        sigs.putU16(8)
        sigs.putU16(0x0403) // ecdsa_secp256r1_sha256
        sigs.putU16(0x0503) // ecdsa_secp384r1_sha384
        sigs.putU16(0x0804) // rsa_pss_rsae_sha256
        sigs.putU16(0x0401) // rsa_pkcs1_sha256
        ext.putU16(0x000d)
        ext.putVec16(sigs.toArray())

        // supported_versions
        let vers = ByteWriter(8)
        vers.putU8(2)
        vers.putU16(0x0304)
        ext.putU16(0x002b)
        ext.putVec16(vers.toArray())

        // key_share (x25519)
        let ks = ByteWriter(40)
        ks.putU16(36)
        ks.putU16(0x001d)
        ks.putVec16(x25519Pub)
        ext.putU16(0x0033)
        ext.putVec16(ks.toArray())

        // ALPN
        let alpn = ByteWriter(32)
        var list = ByteWriter(16)
        var i = 0
        while (i < alpnList.size) {
            list.putVec8(alpnList[i].toArray())
            i++
        }
        alpn.putVec16(list.toArray())
        ext.putU16(0x0010)
        ext.putVec16(alpn.toArray())

        // QUIC transport parameters
        ext.putU16(0x0039)
        ext.putVec16(quicParams)

        body.putU16(UInt16(ext.size))
        body.putBytes(ext.toArray())

        let content = body.toArray()
        let msg = ByteWriter(content.size + 4)
        msg.putU8(1) // client_hello
        msg.putU24(UInt32(content.size))
        msg.putBytes(content)
        return msg.toArray()
    }

    /** Begin the handshake; returns the ClientHello handshake bytes. */
    public func start(): Array<UInt8> {
        let ch = buildClientHello()
        addTranscript(ch)
        state = 1
        return ch
    }

    public func takeOutput(): Array<UInt8> {
        let out = outBuf.toArray()
        outBuf.clear()
        return out
    }

    public func onData(data: Array<UInt8>): Unit {
        hsBuf.putBytes(data)
        try {
            while (true) {
                let all = hsBuf.toArray()
                if (all.size < 4) {
                    return
                }
                let msgLen = Int64(beU24(all, 1))
                if (all.size < 4 + msgLen) {
                    return
                }
                let msg = sliceBytes(all, 0, 4 + msgLen)
                let rest = sliceBytes(all, 4 + msgLen, all.size - 4 - msgLen)
                hsBuf.clear()
                hsBuf.putBytes(rest)
                handleMessage(msg)
                if (state == 6 || state == 7) {
                    return
                }
            }
        } catch (e: Exception) {
            failure = "handshake error: ${e}"
            state = 7
        }
    }

    private func handleMessage(msg: Array<UInt8>): Unit {
        let msgType = msg[0]
        if (msgType == 2) {
            // The handshake traffic secrets cover ClientHello..ServerHello, so the
            // ServerHello must be in the transcript before keys are derived.
            addTranscript(msg)
            handleServerHello(msg)
        } else if (msgType == 8) {
            // EncryptedExtensions; ignore retransmitted duplicates.
            if (state < 2) {
                throw Exception("unexpected EncryptedExtensions")
            }
            if (state > 3) {
                return
            }
            addTranscript(msg)
            handleEncryptedExtensions(msg)
            state = 3
        } else if (msgType == 11) {
            if (state > 4) {
                return
            }
            addTranscript(msg)
            handleCertificate(msg)
            state = 4
        } else if (msgType == 15) {
            // The signature covers the transcript up to, but not including,
            // the CertificateVerify message itself (RFC 8446 section 4.4.3).
            handleCertificateVerify(msg)
            addTranscript(msg)
            state = 5
        } else if (msgType == 20) {
            if (state >= 6) {
                return
            }
            handleFinished(msg)
        } else if (msgType == 4) {
            // NewSessionTicket (after handshake) - ignored
        } else if (msgType == 24) {
            // KeyUpdate - handled by transport
        } else {
            throw Exception("unexpected handshake type ${msgType}")
        }
    }

    private func handleServerHello(msg: Array<UInt8>): Unit {
        let r = ByteReader(msg, 4, msg.size)
        let legacyVersion = r.readU16()
        let serverRandom = r.readBytes(32)
        let sid = r.readVec8()
        cipherSuite = Int64(r.readU16())
        let comp = r.readU8()
        if (cipherSuite == 0x1301) {
            hashAlg = HashAlg.Sha256
            keyLen = 16
        } else if (cipherSuite == 0x1302) {
            hashAlg = HashAlg.Sha384
            keyLen = 32
        } else {
            throw Exception("unsupported cipher suite ${cipherSuite}")
        }
        let extLen = Int64(r.readU16())
        let exts = ByteReader(r.data, r.pos, r.pos + extLen)
        var serverPub = Array<UInt8>(0, repeat: 0)
        var group: Int64 = 0
        while (!exts.eof()) {
            let t = exts.readU16()
            let body = exts.readVec16()
            if (t == 0x0033) {
                let ks = ByteReader(body)
                group = Int64(ks.readU16())
                serverPub = ks.readVec16()
            }
        }
        if (serverPub.size == 0) {
            throw Exception("no key_share in ServerHello")
        }
        var shared: Array<UInt8>
        if (group == 0x001d) {
            shared = X25519.scalarmult(x25519Priv, serverPub)
        } else {
            throw Exception("unsupported key share group ${group}")
        }
        deriveHandshakeSecrets(shared)
        state = 2
    }

    private func deriveHandshakeSecrets(shared: Array<UInt8>): Unit {
        let zeros = Array<UInt8>(hashLen(), repeat: 0)
        // RFC 8446 section 7.1: early_secret = HKDF-Extract(0, PSK) with a zero
        // PSK of Hash.length bytes (not an empty string).
        let earlySecret = hkdfExtract(hashAlg, zeros, zeros)
        let derived = deriveSecret(hashAlg, earlySecret, "derived", hashOf(hashAlg,
            Array<UInt8>(0, repeat: 0)))
        handshakeSecret = hkdfExtract(hashAlg, derived, shared)

        let th = transcriptHash()
        clientHsSecret = deriveSecret(hashAlg, handshakeSecret, "c hs traffic", th)
        serverHsSecret = deriveSecret(hashAlg, handshakeSecret, "s hs traffic", th)
        clientHs = trafficKeys(clientHsSecret)
        serverHs = trafficKeys(serverHsSecret)

        let derived2 = deriveSecret(hashAlg, handshakeSecret, "derived", hashOf(hashAlg,
            Array<UInt8>(0, repeat: 0)))
        masterSecret = hkdfExtract(hashAlg, derived2, zeros)
    }

    private func trafficKeys(secret: Array<UInt8>): TlsDirection {
        let k = TlsDirection()
        // RFC 9001 section 5.1: QUIC uses the labels "quic key"/"quic iv"/"quic hp".
        k.key = hkdfExpandLabel(hashAlg, secret, "quic key", Array<UInt8>(0, repeat: 0), keyLen)
        k.iv = hkdfExpandLabel(hashAlg, secret, "quic iv", Array<UInt8>(0, repeat: 0), 12)
        k.hp = hkdfExpandLabel(hashAlg, secret, "quic hp", Array<UInt8>(0, repeat: 0), keyLen)
        return k
    }

    private func handleEncryptedExtensions(msg: Array<UInt8>): Unit {
        let r = ByteReader(msg, 4, msg.size)
        let extLen = Int64(r.readU16())
        let exts = ByteReader(r.data, r.pos, r.pos + extLen)
        while (!exts.eof()) {
            let t = exts.readU16()
            let body = exts.readVec16()
            if (t == 0x0010) {
                let a = ByteReader(body)
                let listLen = Int64(a.readU16())
                let list = ByteReader(a.data, a.pos, a.pos + listLen)
                if (!list.eof()) {
                    negotiatedAlpn = String.fromUtf8(list.readVec8())
                }
            } else if (t == 0x0039) {
                peerParams = body
            }
        }
        if (negotiatedAlpn == "") {
            throw Exception("server did not negotiate ALPN")
        }
    }

    private func handleCertificate(msg: Array<UInt8>): Unit {
        let r = ByteReader(msg, 4, msg.size)
        let ctx = r.readVec8()
        let listLen = Int64(r.readU24())
        let list = ByteReader(r.data, r.pos, r.pos + listLen)
        var chain = Array<X509Cert>(8, repeat: X509Cert())
        var count = 0
        while (!list.eof() && count < 8) {
            let certData = list.readVec24()
            let exts = list.readVec16()
            chain[count] = X509Cert.parse(certData)
            count++
        }
        peerCert = chain[0]
        hasPeerCert = true
        if (verifyPeer) {
            let now = nowSeconds()
            let ok = verifyCertificateChain(chain, count, store, host, now)
            if (!ok) {
                throw Exception("certificate verification failed for ${host}")
            }
        }
    }

    private func handleCertificateVerify(msg: Array<UInt8>): Unit {
        let r = ByteReader(msg, 4, msg.size)
        let scheme = Int64(r.readU16())
        let sig = r.readVec16()
        let th = transcriptHash() // CH..Certificate
        let context = "TLS 1.3, server CertificateVerify".toArray()
        let content = Array<UInt8>(64 + context.size + 1 + th.size, repeat: 0x20)
        var off = 64
        copyBytes(content, off, context, 0, context.size)
        off = off + context.size
        content[off] = 0
        off++
        copyBytes(content, off, th, 0, th.size)
        var ok = false
        if (scheme == 0x0403) {
            let h = sha256(content)
            let rs = parseSig(sig)
            ok = CURVE_P256.verify(peerCert.spki, h, rs[0], rs[1])
        } else if (scheme == 0x0503) {
            let h = sha384(content)
            let rs = parseSig(sig)
            ok = CURVE_P384.verify(peerCert.spki, h, rs[0], rs[1])
        } else if (scheme == 0x0804) {
            ok = false // RSA-PSS not implemented
        }
        if (!ok) {
            throw Exception("CertificateVerify failed")
        }
    }

    private func parseSig(sig: Array<UInt8>): (Array<UInt8>, Array<UInt8>) {
        let d = Der(sig, 0, sig.size)
        let seq = d.enter(0x30)
        return (seq.readIntegerBytes(), seq.readIntegerBytes())
    }

    private func handleFinished(msg: Array<UInt8>): Unit {
        if (state != 5) {
            throw Exception("unexpected Finished")
        }
        let r = ByteReader(msg, 4, msg.size)
        let verify = r.readBytes(hashLen())
        let finishedKey = hkdfExpandLabel(hashAlg, serverHsSecret, "finished",
            Array<UInt8>(0, repeat: 0), hashLen())
        let expected = hmac(hashAlg, finishedKey, transcriptHash())
        if (!ctEqual(verify, expected)) {
            throw Exception("server Finished verify_data mismatch")
        }
        addTranscript(msg)
        // application secrets
        let th = transcriptHash()
        let clientAppSecret = deriveSecret(hashAlg, masterSecret, "c ap traffic", th)
        let serverAppSecret = deriveSecret(hashAlg, masterSecret, "s ap traffic", th)
        clientApp = trafficKeys(clientAppSecret)
        serverApp = trafficKeys(serverAppSecret)
        // client Finished
        let cFinKey = hkdfExpandLabel(hashAlg, clientHsSecret, "finished",
            Array<UInt8>(0, repeat: 0), hashLen())
        let cVerify = hmac(hashAlg, cFinKey, th)
        let fin = ByteWriter(cVerify.size + 4)
        fin.putU8(20)
        fin.putU24(UInt32(cVerify.size))
        fin.putBytes(cVerify)
        let finMsg = fin.toArray()
        addTranscript(finMsg)
        outBuf.putBytes(finMsg)
        handshakeComplete = true
        state = 6
    }
}

public func nowSeconds(): Int64 {
    return DateTime.now().toUnixTimeStamp().toSeconds()
}


