package quic.tls

import quic.crypto.*
import std.time.*
import std.net.IPAddress
import std.collection.HashSet

/*
 * TLS 1.3 client handshake, QUIC profile (RFC 9001 §4): no record layer.
 * Supports TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384 with X25519 or
 * P-256 key exchange, and verifies the server certificate chain.
 */

public class TlsDirection {
    public var key: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var iv: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var secret: Array<UInt8> = []
    public var hp: Array<UInt8> = Array<UInt8>(0, repeat: 0)
}

/** An authenticated TLS ticket. Store and transmit it as a session secret. */
public class TlsTicket {
    public let host: String
    public let alpn: String
    public let identity: Array<UInt8>
    public let psk: Array<UInt8>
    public let cipherSuite: Int64
    public let ageAdd: UInt32
    public let issuedAtMillis: Int64
    public let lifetimeSeconds: Int64
    public let earlyData: Bool

    init(host: String, alpn: String, identity: Array<UInt8>, psk: Array<UInt8>, cipherSuite: Int64,
        ageAdd: UInt32, lifetimeSeconds: Int64, earlyData: Bool) {
        this.host = host
        this.alpn = alpn
        this.identity = identity
        this.psk = psk
        this.cipherSuite = cipherSuite
        this.ageAdd = ageAdd
        this.issuedAtMillis = unixMillis()
        this.lifetimeSeconds = lifetimeSeconds
        this.earlyData = earlyData
    }

    public func usable(host: String, alpn: String): Bool {
        let age = unixMillis() - issuedAtMillis
        return this.host == host && this.alpn == alpn && age >= 0 && age < lifetimeSeconds * 1000
    }

    @OverflowWrapping
    func obfuscatedAge(): UInt32 {
        return UInt32(unixMillis() - issuedAtMillis) + ageAdd
    }
}

private func unixMillis(): Int64 {
    return DateTime.now().toUnixTimeStamp().toMilliseconds()
}

private func suiteHash(suite: Int64): HashAlg {
    return if (suite == 0x1302) { HashAlg.Sha384 } else { HashAlg.Sha256 }
}

public class TlsClient {
    public let host: String
    public let alpnList: Array<String>
    public let quicParams: Array<UInt8>
    public let store: TrustStore
    public var debug: Bool = false
    public let verifyPeer: Bool
    public let backend: CryptoBackend
    private let labelPrefix: String

    private var x25519Priv: Array<UInt8>
    private var x25519Pub: Array<UInt8>
    private var clientRandom: Array<UInt8>
    private var p256Priv: Array<UInt8> = []
    private var p256Pub: Array<UInt8> = []
    private var shareGroup: UInt16 = 0x001d
    private var retrySuite: Int64 = 0
    private var cookie: Array<UInt8> = []
    private let hrrRandom = hexDecode("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
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
    public let ticket: Option<TlsTicket>
    public let allowEarlyData: Bool
    public var newTicket: Option<TlsTicket> = None
    public var earlyAccepted = false
    public var resumed = false
    public var earlyKeys: Option<TlsDirection> = None
    private var offeredEarly = false
    private var resumptionMaster: Array<UInt8> = []
    private var masterSecret: Array<UInt8>
    private var serverHsSecret: Array<UInt8>
    private var clientHsSecret: Array<UInt8>

    public init(host: String, alpn: String, quicParams: Array<UInt8>, store: TrustStore,
        verifyPeer: Bool, backend!: CryptoBackend = PURE_CRYPTO, ticket!: Option<TlsTicket> = None,
        allowEarlyData!: Bool = false, labelPrefix!: String = "quic ") {
        this.host = host
        this.alpnList = [alpn]
        this.quicParams = quicParams
        this.store = store
        this.verifyPeer = verifyPeer
        this.backend = backend
        this.labelPrefix = labelPrefix
        this.ticket = if (let Some(candidate) <- ticket) {
            if (verifyPeer && candidate.usable(host, alpn)) { Some(candidate) } else { None }
        } else {
            None
        }
        this.allowEarlyData = allowEarlyData
        x25519Priv = randomBytes(32)
        let base = Array<UInt8>(32, repeat: 0)
        base[0] = 9
        x25519Pub = backend.x25519(x25519Priv, base)
        clientRandom = randomBytes(32)
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
        return backend.digest(hashAlg, transcript.toArray())
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
        body.putU16(6)
        body.putU16(0x1301) // TLS_AES_128_GCM_SHA256
        body.putU16(0x1302) // TLS_AES_256_GCM_SHA384
        body.putU16(0x1303) // TLS_CHACHA20_POLY1305_SHA256
        body.putU8(1)
        body.putU8(0) // null compression

        let ext = ByteWriter(512)
        let dnsName = try {
            IPAddress.parse(host)
            false
        } catch (e: Exception) {
            true
        }
        if (dnsName) {
            let sni = ByteWriter(64)
            let hostBytes = host.toArray()
            sni.putU16(UInt16(1 + 2 + hostBytes.size))
            sni.putU8(0)
            sni.putVec16(hostBytes)
            ext.putU16(0x0000)
            ext.putVec16(sni.toArray())
        }

        // supported_groups: x25519, secp256r1
        let groups = ByteWriter(16)
        groups.putU16(4)
        groups.putU16(0x001d)
        groups.putU16(0x0017)
        ext.putU16(0x000a)
        ext.putVec16(groups.toArray())

        // signature_algorithms
        let sigs = ByteWriter(32)
        sigs.putU16(16)
        sigs.putU16(0x0403) // ecdsa_secp256r1_sha256
        sigs.putU16(0x0503) // ecdsa_secp384r1_sha384
        sigs.putU16(0x0804) // rsa_pss_rsae_sha256
        sigs.putU16(0x0805) // rsa_pss_rsae_sha384
        sigs.putU16(0x0806) // rsa_pss_rsae_sha512
        sigs.putU16(0x0401) // rsa_pkcs1_sha256 (certificate chains)
        sigs.putU16(0x0501) // rsa_pkcs1_sha384 (certificate chains)
        sigs.putU16(0x0601) // rsa_pkcs1_sha512 (certificate chains)
        ext.putU16(0x000d)
        ext.putVec16(sigs.toArray())

        // supported_versions
        let vers = ByteWriter(8)
        vers.putU8(2)
        vers.putU16(0x0304)
        ext.putU16(0x002b)
        ext.putVec16(vers.toArray())

        let share = if (shareGroup == 0x001d) { x25519Pub } else { p256Pub }
        let ks = ByteWriter(share.size + 6)
        ks.putU16(UInt16(share.size + 4))
        ks.putU16(shareGroup)
        ks.putVec16(share)
        ext.putU16(0x0033)
        ext.putVec16(ks.toArray())
        if (cookie.size > 0) {
            let encoded = ByteWriter(cookie.size + 2)
            encoded.putVec16(cookie)
            ext.putU16(0x002c)
            ext.putVec16(encoded.toArray())
        }

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

        if (verifyPeer) {
            ext.putU16(0x002d) // psk_key_exchange_modes
            ext.putVec16([1, 1]) // psk_dhe_ke
        }
        var bindersSize: Int64 = 0
        let activeTicket = if (let Some(value) <- ticket) {
            if (retrySuite == 0 || hashSize(suiteHash(value.cipherSuite)) == hashLen()) {
                Some(value)
            } else {
                Option<TlsTicket>.None
            }
        } else {
            Option<TlsTicket>.None
        }
        if (let Some(session) <- activeTicket) {
            // RFC 8446 §4.2.11: PSK must be the final ClientHello extension.
            offeredEarly = allowEarlyData && session.earlyData && retrySuite == 0
            if (offeredEarly) {
                ext.putU16(0x002a)
                ext.putVec16([])
            }
            let identities = ByteWriter(session.identity.size + 8)
            identities.putVec16(session.identity)
            identities.putU32(session.obfuscatedAge())
            let hlen = hashSize(suiteHash(session.cipherSuite))
            bindersSize = hlen + 3
            ext.putU16(0x0029)
            ext.putU16(UInt16(2 + identities.size + bindersSize))
            ext.putVec16(identities.toArray())
        }

        body.putU16(UInt16(ext.size + bindersSize))
        body.putBytes(ext.toArray())
        let msg = ByteWriter(body.size + 4 + bindersSize)
        msg.putU8(1)
        msg.putU24(UInt32(body.size + bindersSize))
        msg.putBytes(body.toArray())
        if (let Some(session) <- activeTicket) {
            let alg = suiteHash(session.cipherSuite)
            let early = computeEarlySecret(alg, session.psk)
            let binderKey = deriveSecret(alg, early, "res binder", backend.digest(alg, []), backend: backend)
            let finished = hkdfExpandLabel(alg, binderKey, "finished", [], hashSize(alg), backend: backend)
            let hash = backend.digest(alg, concat(transcript.toArray(), msg.toArray()))
            let binder = hmac(alg, finished, hash, backend: backend)
            msg.putU16(UInt16(binder.size + 1))
            msg.putVec8(binder)
            if (offeredEarly) {
                let keyLen = if (session.cipherSuite == 0x1301) { 16 } else { 32 }
                let th = backend.digest(alg, msg.toArray())
                let secret = deriveSecret(alg, early, "c e traffic", th, backend: backend)
                earlyKeys = Some(packetKeys(secret, alg, keyLen))
            }
        }
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

    private let cryptoBuffers = [ByteWriter(1024), ByteWriter(4096), ByteWriter(1024)]

    // The standalone TLS driver can supply a contiguous transcript. QUIC
    // callers supply the packet number space and keep separate CRYPTO streams.
    public func onData(data: Array<UInt8>, cryptoSpace!: Int64 = -1): Unit {
        if (state == 7) {
            return
        }
        try {
            let buffer = if (cryptoSpace == -1) { hsBuf } else { cryptoBuffers[cryptoSpace] }
            buffer.putBytes(data)
            let reader = buffer.reader()
            while (reader.remaining() >= 4) {
                let kind = reader.data[reader.pos]
                if (cryptoSpace >= 0 && messageSpace(kind) != cryptoSpace) {
                    throw Exception("TLS handshake message at the wrong QUIC encryption level")
                }
                let length = 4 + Int64(beU24(reader.data, reader.pos + 1))
                if (reader.remaining() < length) {
                    break
                }
                handleMessage(reader.readBytes(length))
            }
            if (reader.pos != 0) {
                let remaining = reader.readBytes(reader.remaining())
                buffer.clear()
                buffer.putBytes(remaining)
            }
        } catch (e: Exception) {
            failure = "handshake error: " + e.toString()
            state = 7
        }
    }

    private func messageSpace(kind: UInt8): Int64 {
        match (kind) {
            case 2 => 0 // ServerHello and HelloRetryRequest
            case 8 | 11 | 15 | 20 => 1
            case 4 => 2 // NewSessionTicket
            case _ => -1
        }
    }

    private func handleMessage(msg: Array<UInt8>): Unit {
        let msgType = msg[0]
        if (msgType == 2 && state == 1) {
            handleServerHello(msg)
        } else if (msgType == 8 && state == 2) {
            addTranscript(msg)
            handleEncryptedExtensions(msg)
            state = 3
        } else if (msgType == 11 && state == 3 && !resumed) {
            addTranscript(msg)
            handleCertificate(msg)
            state = 4
        } else if (msgType == 15 && state == 4) {
            handleCertificateVerify(msg)
            addTranscript(msg)
            state = 5
        } else if (msgType == 20 && (state == 5 || (state == 3 && resumed))) {
            handleFinished(msg)
        } else if (msgType == 4 && state == 6) {
            handleTicket(msg)
        } else {
            throw Exception("unexpected handshake type " + "${msgType}")
        }
    }

    private func handleServerHello(msg: Array<UInt8>): Unit {
        let r = ByteReader(msg, 4, msg.size)
        let legacyVersion = r.readU16()
        let serverRandom = r.readBytes(32)
        let isRetry = ctEqual(serverRandom, hrrRandom)
        let sid = r.readVec8()
        cipherSuite = Int64(r.readU16())
        let compression = r.readU8()
        if (legacyVersion != 0x0303 || sid.size != 0 || compression != 0 ||
            (retrySuite != 0 && (isRetry || retrySuite != cipherSuite))) {
            throw Exception("invalid ServerHello")
        }
        match (cipherSuite) {
            case 0x1301 =>
                hashAlg = HashAlg.Sha256
                keyLen = 16
            case 0x1302 =>
                hashAlg = HashAlg.Sha384
                keyLen = 32
            case 0x1303 =>
                hashAlg = HashAlg.Sha256
                keyLen = 32
            case _ => throw Exception("unsupported cipher suite")
        }
        let exts = ByteReader(r.readVec16())
        var version = false
        var group: UInt16 = 0
        var serverPub: Array<UInt8> = []
        if (!r.eof()) {
            throw Exception("trailing ServerHello data")
        }
        while (!exts.eof()) {
            let kind = exts.readU16()
            let body = ByteReader(exts.readVec16())
            if (kind == 0x002b && !version) {
                version = body.readU16() == 0x0304
            } else if (kind == 0x0033 && group == 0) {
                group = body.readU16()
                if (!isRetry) {
                    serverPub = body.readVec16()
                }
            } else if (kind == 0x0029 && !isRetry && !resumed) {
                if (let Some(session) <- ticket) {
                    if (body.readU16() != 0 || hashSize(suiteHash(session.cipherSuite)) != hashLen()) {
                        throw Exception("invalid TLS PSK selection")
                    }
                    resumed = true
                } else {
                    throw Exception("unexpected TLS PSK selection")
                }
            } else if (kind == 0x002c && isRetry && cookie.size == 0) {
                cookie = body.readVec16()
                if (cookie.size == 0) {
                    throw Exception("empty HelloRetryRequest cookie")
                }
            } else {
                throw Exception("unexpected ServerHello extension")
            }
            if (!body.eof()) {
                throw Exception("invalid ServerHello extension")
            }
        }
        if (!version) {
            throw Exception("server did not select TLS 1.3")
        }
        if (isRetry) {
            if ((group == 0 && cookie.size == 0) || (group != 0 && group != 0x0017)) {
                throw Exception("invalid HelloRetryRequest group")
            }
            retrySuite = cipherSuite
            earlyKeys = None
            if (group == 0x0017) {
                shareGroup = group
                p256Priv = backend.p256Private()
                p256Pub = backend.p256Public(p256Priv)
            }
            let firstHash = transcriptHash()
            transcript.clear()
            transcript.putU8(254)
            transcript.putU24(UInt32(firstHash.size))
            transcript.putBytes(firstHash)
            addTranscript(msg)
            let hello = buildClientHello()
            addTranscript(hello)
            outBuf.putBytes(hello)
            return
        }
        if (group != shareGroup) {
            throw Exception("server chose a key share the client did not send")
        }
        let shared = if (group == 0x001d && serverPub.size == 32) {
            backend.x25519(x25519Priv, serverPub)
        } else if (group == 0x0017 && serverPub.size == 65) {
            backend.p256(p256Priv, serverPub)
        } else {
            throw Exception("invalid key share")
        }
        if (ctEqual(shared, Array<UInt8>(shared.size, repeat: 0))) {
            throw Exception("invalid all-zero shared secret")
        }
        fillBytes(x25519Priv, 0)
        fillBytes(p256Priv, 0)
        addTranscript(msg)
        deriveHandshakeSecrets(shared)
        fillBytes(shared, 0)
        state = 2
    }

    private func computeEarlySecret(alg: HashAlg, psk: Array<UInt8>): Array<UInt8> {
        let zeros = Array<UInt8>(hashSize(alg), repeat: 0)
        return hkdfExtract(alg, zeros, if (psk.size == 0) { zeros } else { psk }, backend: backend)
    }

    private func deriveHandshakeSecrets(shared: Array<UInt8>): Unit {
        let zeros = Array<UInt8>(hashLen(), repeat: 0)
        let earlySecret = computeEarlySecret(hashAlg, if (resumed) { ticket.getOrThrow().psk } else { [] })
        let derived = deriveSecret(hashAlg, earlySecret, "derived", backend.digest(hashAlg, []), backend: backend)
        handshakeSecret = hkdfExtract(hashAlg, derived, shared, backend: backend)

        let th = transcriptHash()
        clientHsSecret = deriveSecret(hashAlg, handshakeSecret, "c hs traffic", th, backend: backend)
        serverHsSecret = deriveSecret(hashAlg, handshakeSecret, "s hs traffic", th, backend: backend)
        clientHs = trafficKeys(clientHsSecret)
        serverHs = trafficKeys(serverHsSecret)

        let derived2 = deriveSecret(hashAlg, handshakeSecret, "derived", backend.digest(hashAlg, []), backend: backend)
        masterSecret = hkdfExtract(hashAlg, derived2, zeros, backend: backend)
    }

    private func trafficKeys(secret: Array<UInt8>): TlsDirection {
        return packetKeys(secret, hashAlg, keyLen)
    }

    private func packetKeys(secret: Array<UInt8>, alg: HashAlg, length: Int64): TlsDirection {
        let k = TlsDirection()
        k.secret = secret
        k.key = hkdfExpandLabel(alg, secret, labelPrefix + "key", [], length, backend: backend)
        k.iv = hkdfExpandLabel(alg, secret, labelPrefix + "iv", [], 12, backend: backend)
        k.hp = hkdfExpandLabel(alg, secret, labelPrefix + "hp", [], length, backend: backend)
        return k
    }

    private func handleEncryptedExtensions(msg: Array<UInt8>): Unit {
        let r = ByteReader(msg, 4, msg.size)
        let exts = ByteReader(r.readVec16())
        let seen = HashSet<UInt16>()
        if (!r.eof()) {
            throw Exception("invalid EncryptedExtensions")
        }
        while (!exts.eof()) {
            let kind = exts.readU16()
            let body = exts.readVec16()
            if (seen.contains(kind)) {
                throw Exception("duplicate TLS extension")
            }
            seen.add(kind)
            if (kind == 0x0010) {
                let a = ByteReader(body)
                let list = ByteReader(a.readVec16())
                negotiatedAlpn = String.fromUtf8(list.readVec8())
                if (!a.eof() || !list.eof()) {
                    throw Exception("invalid negotiated ALPN")
                }
            } else if (kind == 0x0039) {
                peerParams = body
            } else if (kind == 0x002a) {
                if (body.size != 0 || !offeredEarly || !resumed ||
                    ticket.getOrThrow().cipherSuite != cipherSuite) {
                    throw Exception("invalid TLS early_data extension")
                }
                earlyAccepted = true
            } else if (kind != 0x0000 && kind != 0x000a) {
                throw Exception("unexpected EncryptedExtensions extension")
            }
        }
        if (negotiatedAlpn != alpnList[0] || peerParams.size == 0) {
            throw Exception("missing HTTP/3 ALPN or QUIC transport parameters")
        }
    }

    private func handleCertificate(msg: Array<UInt8>): Unit {
        let r = ByteReader(msg, 4, msg.size)
        if (r.readVec8().size != 0) {
            throw Exception("invalid Certificate request context")
        }
        let list = ByteReader(r.readVec24())
        if (!r.eof()) {
            throw Exception("invalid Certificate message")
        }
        var chain = Array<X509Cert>(8, repeat: X509Cert())
        var count = 0
        while (!list.eof() && count < 8) {
            let certData = list.readVec24()
            list.readVec16()
            chain[count] = X509Cert.parse(certData)
            count++
        }
        if (count == 0 || !list.eof()) {
            throw Exception("invalid certificate chain length")
        }
        peerCert = chain[0]
        hasPeerCert = true
        if (verifyPeer) {
            let now = nowSeconds()
            let ok = backend.verifyChain(chain, count, store, host, now)
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
        if (!r.eof() || !backend.verifyHandshake(peerCert, scheme, content, sig)) {
            throw Exception("CertificateVerify failed")
        }
    }

    private func handleFinished(msg: Array<UInt8>): Unit {
        let r = ByteReader(msg, 4, msg.size)
        let verify = r.readBytes(hashLen())
        let finishedKey = hkdfExpandLabel(hashAlg, serverHsSecret, "finished",
            [], hashLen(), backend: backend)
        let expected = hmac(hashAlg, finishedKey, transcriptHash(), backend: backend)
        if (!r.eof() || !ctEqual(verify, expected)) {
            throw Exception("server Finished verify_data mismatch")
        }
        addTranscript(msg)
        // application secrets
        let th = transcriptHash()
        let clientAppSecret = deriveSecret(hashAlg, masterSecret, "c ap traffic", th, backend: backend)
        let serverAppSecret = deriveSecret(hashAlg, masterSecret, "s ap traffic", th, backend: backend)
        clientApp = trafficKeys(clientAppSecret)
        serverApp = trafficKeys(serverAppSecret)
        // client Finished
        let cFinKey = hkdfExpandLabel(hashAlg, clientHsSecret, "finished",
            [], hashLen(), backend: backend)
        let cVerify = hmac(hashAlg, cFinKey, th, backend: backend)
        let fin = ByteWriter(cVerify.size + 4)
        fin.putU8(20)
        fin.putU24(UInt32(cVerify.size))
        fin.putBytes(cVerify)
        let finMsg = fin.toArray()
        addTranscript(finMsg)
        resumptionMaster = deriveSecret(hashAlg, masterSecret, "res master", transcriptHash(), backend: backend)
        outBuf.putBytes(finMsg)
        handshakeComplete = true
        state = 6
    }
    private func handleTicket(msg: Array<UInt8>): Unit {
        if (!verifyPeer) { return }
        let r = ByteReader(msg, 4, msg.size)
        let lifetime = Int64(r.readU32())
        let ageAdd = r.readU32()
        let nonce = r.readVec8()
        let identity = r.readVec16()
        let exts = ByteReader(r.readVec16())
        if (!r.eof() || lifetime > 604800 || identity.size == 0) {
            throw Exception("invalid TLS NewSessionTicket")
        }
        if (lifetime == 0) { return }
        var early = false
        while (!exts.eof()) {
            let kind = exts.readU16()
            let value = exts.readVec16()
            if (kind == 0x002a) {
                if (early || value.size != 4 || beU32(value, 0) != 0xffffffff) {
                    throw Exception("invalid QUIC ticket early-data limit")
                }
                early = true
            }
        }
        let psk = hkdfExpandLabel(hashAlg, resumptionMaster, "resumption", nonce, hashLen(), backend: backend)
        newTicket = Some(TlsTicket(host, negotiatedAlpn, identity, psk, cipherSuite, ageAdd, lifetime, early))
    }

}

public func nowSeconds(): Int64 {
    return DateTime.now().toUnixTimeStamp().toSeconds()
}


