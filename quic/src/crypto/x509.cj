package quic.crypto

import std.env.getVariable
import std.fs.File
import std.net.IPAddress
import std.net.IPSocketAddress
import std.collection.ArrayList
import std.collection.HashSet

/*
 * X.509 certificate parsing and chain verification (ECDSA P-256/P-384
 * signatures, SAN/EKU/basicConstraints handling).
 */

public class X509Name {
    public var cn: String = ""
    public var org: String = ""
    public var full: String = ""
    private var encoded: Array<UInt8> = []

    func capture(encoded: Array<UInt8>): Unit {
        this.encoded = encoded
    }

    public func equals(o: X509Name): Bool {
        if (encoded.size > 0 && o.encoded.size > 0) {
            return ctEqual(encoded, o.encoded)
        }
        return full == o.full
    }
}

public class X509Cert {
    public var der: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var tbs: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var serial: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var issuer: X509Name = X509Name()
    public var subject: X509Name = X509Name()
    public var notBefore: Int64 = 0
    public var notAfter: Int64 = 0
    public var keyType: String = ""
    public var curveOid: String = ""
    public var publicKeyDer: Array<UInt8> = []
    public var spki: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var sigAlg: String = ""
    public var signature: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var sans: Array<String> = Array<String>(8, repeat: "")
    public var sanCount: Int64 = 0
    public var isCA: Bool = false
    public var ekuPresent: Bool = false
    public var ekuServerAuth: Bool = false
    public var keyUsagePresent: Bool = false
    public var keyUsageDigitalSignature: Bool = false
    public var basicConstraintsPresent: Bool = false
    private var pathLen: Int64 = Int64.Max
    private var unknownCritical = false
    private var keyCertSign = false
    private let ipSans = ArrayList<Array<UInt8>>()

    func permitsIssuer(depth: Int64, now: Int64): Bool {
        return isCA && depth <= pathLen && validAt(now) && !unknownCritical &&
            (!keyUsagePresent || keyCertSign) && (!ekuPresent || ekuServerAuth)
    }

    func permitsServer(now: Int64): Bool {
        return validAt(now) && !unknownCritical && (!ekuPresent || ekuServerAuth) &&
            (!keyUsagePresent || keyUsageDigitalSignature)
    }

    public func addSan(v: String): Unit {
        if (sanCount == sans.size) {
            let previous = sans
            sans = Array<String>(previous.size * 2, repeat: "")
            previous.copyTo(sans)
        }
        sans[sanCount] = v
        sanCount++
    }

    public func hasSan(v: String): Bool {
        var i = 0
        while (i < sanCount) {
            if (sans[i] == v) {
                return true
            }
            i++
        }
        return false
    }

    public static func parse(derBytes: Array<UInt8>): X509Cert {
        let c = X509Cert()
        c.der = derBytes
        let outer = Der(derBytes, 0, derBytes.size)
        let cert = outer.enter(0x30)
        if (!outer.eof()) {
            throw Exception("trailing DER after Certificate")
        }

        let tbsStart = cert.pos
        let tbs = cert.enter(0x30)
        let tbsEnd = cert.pos
        c.tbs = sliceBytes(derBytes, tbsStart, tbsEnd - tbsStart)

        let sigAlg = cert.enter(0x30)
        c.sigAlg = sigAlg.readOid()
        let (unused, signature) = cert.readBitString()
        if (!cert.eof() || unused != 0 || signature.size == 0) {
            throw Exception("invalid Certificate signature")
        }
        c.signature = signature

        if (tbs.peekTag() == 0xA0) {
            let v = tbs.enter(0xA0)
            let _ = v.readInt64()
        }
        c.serial = tbs.readIntegerBytes()
        let innerSig = tbs.enter(0x30)
        if (innerSig.readOid() != c.sigAlg) {
            throw Exception("certificate signature algorithms differ")
        }
        c.issuer = parseName(tbs.enter(0x30))
        let validity = tbs.enter(0x30)
        c.notBefore = validity.readTime()
        c.notAfter = validity.readTime()
        if (!validity.eof() || c.notAfter < c.notBefore) {
            throw Exception("invalid Certificate validity")
        }
        c.subject = parseName(tbs.enter(0x30))

        let keyStart = tbs.pos
        let spki = tbs.enter(0x30)
        c.publicKeyDer = sliceBytes(derBytes, keyStart, tbs.pos - keyStart)
        let alg = spki.enter(0x30)
        let algOid = alg.readOid()
        if (algOid == "1.2.840.10045.2.1") {
            c.keyType = "EC"
            c.curveOid = alg.readOid()
        } else if (algOid == "1.2.840.113549.1.1.1") {
            c.keyType = "RSA"
            if (!alg.eof()) {
                alg.readTLV()
            }
        } else if (algOid == "1.3.101.112") {
            c.keyType = "ED25519"
        } else {
            c.keyType = algOid
        }
        let (unusedKeyBits, publicKey) = spki.readBitString()
        if (!spki.eof() || unusedKeyBits != 0 || publicKey.size == 0) {
            throw Exception("invalid Certificate public key")
        }
        c.spki = publicKey

        let extensionOids = HashSet<String>()
        while (!tbs.eof()) {
            let t = tbs.readTLV()
            if (t[0] == 0xA3) {
                let exts = Der(derBytes, t[1], t[1] + t[2])
                let seq = exts.enter(0x30)
                if (!exts.eof() || seq.eof()) {
                    throw Exception("invalid Certificate extensions")
                }
                while (!seq.eof()) {
                    let ext = seq.enter(0x30)
                    let oid = ext.readOid()
                    if (extensionOids.contains(oid)) {
                        throw Exception("duplicate Certificate extension")
                    }
                    extensionOids.add(oid)
                    var critical = false
                    if (ext.peekTag() == 0x01) {
                        let flag = ext.readContent()
                        if (flag.size != 1 || (flag[0] != 0 && flag[0] != 0xff)) {
                            throw Exception("invalid Certificate extension critical flag")
                        }
                        critical = flag[0] != 0
                    }
                    let val = ext.readOctetString()
                    if (!ext.eof()) {
                        throw Exception("trailing data in Certificate extension")
                    }
                    applyExtension(c, oid, val, critical)
                }
            }
        }
        return c
    }

    private static func parseName(nameSeq: Der): X509Name {
        let n = X509Name()
        n.capture(sliceBytes(nameSeq.data, nameSeq.pos, nameSeq.end - nameSeq.pos))
        var first = true
        var full = ""
        while (!nameSeq.eof()) {
            let set = nameSeq.enter(0x31)
            while (!set.eof()) {
                let atv = set.enter(0x30)
                let oid = atv.readOid()
                let t = atv.readTLV()
                let value = String.fromUtf8(sliceBytes(atv.data, t[1], t[2]))
                if (oid == "2.5.4.3") {
                    n.cn = value
                } else if (oid == "2.5.4.10") {
                    n.org = value
                }
                if (!first) {
                    full = full + ","
                }
                full = full + oid + "=" + value
                first = false
            }
        }
        n.full = full
        return n
    }

    private static func applyExtension(c: X509Cert, oid: String, val: Array<UInt8>, critical: Bool): Unit {
        let d = Der(val, 0, val.size)
        if (oid == "2.5.29.17") {
            let seq = d.enter(0x30)
            while (!seq.eof()) {
                let t = seq.readTLV()
                if (t[0] == 0x82) {
                    c.addSan(String.fromUtf8(sliceBytes(val, t[1], t[2])))
                } else if (t[0] == 0x87) {
                    if (t[2] != 4 && t[2] != 16) {
                        throw Exception("invalid certificate IP address")
                    }
                    c.ipSans.add(sliceBytes(val, t[1], t[2]))
                }
            }
        } else if (oid == "2.5.29.19") {
            c.basicConstraintsPresent = true
            let seq = d.enter(0x30)
            if (!seq.eof() && seq.peekTag() == 0x01) {
                c.isCA = seq.readContent()[0] != 0
            }
            if (!seq.eof()) {
                c.pathLen = seq.readInt64()
                if (!c.isCA || c.pathLen < 0 || !seq.eof()) {
                    throw Exception("invalid certificate path length")
                }
            }
        } else if (oid == "2.5.29.15") {
            c.keyUsagePresent = true
            let (_, bits) = d.readBitString()
            if (bits.size > 0) {
                c.keyUsageDigitalSignature = (bits[0] & 0x80) != 0
                c.keyCertSign = (bits[0] & 0x04) != 0
            }
        } else if (oid == "2.5.29.37") {
            c.ekuPresent = true
            let seq = d.enter(0x30)
            while (!seq.eof()) {
                let e = seq.readOid()
                if (e == "1.3.6.1.5.5.7.3.1") {
                    c.ekuServerAuth = true
                }
            }
        } else if (critical || oid == "2.5.29.30") {
            c.unknownCritical = true
        }
    }

    private static func hashFor(alg: String, data: Array<UInt8>): Option<Array<UInt8>> {
        if (alg == "1.2.840.10045.4.3.2" || alg == "1.2.840.113549.1.1.11") {
            return Some(sha256(data))
        }
        if (alg == "1.2.840.10045.4.3.3") {
            return Some(sha384(data))
        }
        if (alg == "1.2.840.113549.1.1.13") {
            return Some(sha512(data))
        }
        return None
    }

    /** Verify that this certificate's signature was produced by `issuer`. */
    public func verifySignedBy(issuer: X509Cert): Bool {
        let h = hashFor(sigAlg, tbs)
        if (h.isNone()) {
            return false
        }
        let digest = h.getOrThrow()
        if (sigAlg == "1.2.840.10045.4.3.2" || sigAlg == "1.2.840.10045.4.3.3") {
            if (issuer.keyType != "EC") {
                return false
            }
            let curve = if (issuer.curveOid == "1.2.840.10045.3.1.7") {
                CURVE_P256
            } else if (issuer.curveOid == "1.3.132.0.34") {
                CURVE_P384
            } else {
                return false
            }
            let rs = parseEcdsaSig(signature)
            if (rs.isNone()) {
                return false
            }
            return curve.verify(issuer.spki, digest, rs.getOrThrow()[0], rs.getOrThrow()[1])
        }
        if (issuer.keyType == "RSA") {
            return rsaVerifyPkcs1(issuer.spki, digest, signature, sigAlg)
        }
        return false
    }

    private static func parseEcdsaSig(sig: Array<UInt8>): Option<(Array<UInt8>, Array<UInt8>)> {
        try {
            let d = Der(sig, 0, sig.size)
            let seq = d.enter(0x30)
            let r = seq.readIntegerBytes()
            let s = seq.readIntegerBytes()
            return Some((r, s))
        } catch (e: Exception) {
            return None
        }
    }

    public func validAt(now: Int64): Bool {
        return now >= notBefore && now <= notAfter
    }

    /** Match a DNS or IP subjectAltName, including single-label DNS wildcards. */
    public func matchesHost(host: String): Bool {
        try {
            let ip = IPAddress.parse(host)
            for (addr in ipSans) {
                if (IPSocketAddress(addr, 0) == IPSocketAddress(ip, 0)) {
                    return true
                }
            }
            return false
        } catch (e: Exception) {
            // A DNS name has no IP address representation.
        }
        let h = toLowerAscii(host)
        var i = 0
        while (i < sanCount) {
            if (matchName(toLowerAscii(sans[i]), h)) {
                return true
            }
            i++
        }
        return false
    }

    private static func matchName(pattern: String, host: String): Bool {
        if (pattern == host) {
            return true
        }
        if (pattern.size > 2 && pattern[0..2] == "*.") {
            // wildcard matches exactly one label
            let suffix = pattern[1..]
            if (host.size > suffix.size && host[host.size - suffix.size..] == suffix) {
                let prefix = host[0..host.size - suffix.size]
                var label = prefix
                if (label.size > 1 && label[label.size - 1] == 46u8) {
                    label = label[0..label.size - 1]
                }
                var hasDot = false
                var k = 0
                while (k < label.size) {
                    if (label[k] == 46u8) {
                        hasDot = true
                    }
                    k++
                }
                return !hasDot && label.size > 0
            }
        }
        return false
    }
}

/** A set of trusted root certificates. */
public class TrustStore {
    public var roots: Array<X509Cert>
    public var count: Int64

    public init() {
        roots = Array<X509Cert>(32, repeat: X509Cert())
        count = 0
    }

    public func addDer(der: Array<UInt8>): Unit {
        try {
            let c = X509Cert.parse(der)
            if (count == roots.size) {
                let expanded = Array<X509Cert>(roots.size * 2, repeat: X509Cert())
                for (i in 0..count) {
                    expanded[i] = roots[i]
                }
                roots = expanded
            }
            roots[count] = c
            count++
        } catch (e: Exception) {
            // skip malformed root
        }
    }

    public static func fromFile(path: String): TrustStore {
        let store = TrustStore()
        store.addPem(String.fromUtf8(File.readFrom(path)))
        if (store.count == 0) {
            throw Exception("no trusted certificates in " + path)
        }
        return store
    }

    /** Load the PEM CA bundle configured by SSL_CERT_FILE or installed by the OS. */
    public static func system(): TrustStore {
        if (let Some(path) <- getVariable("SSL_CERT_FILE")) {
            if (path != "") {
                return fromFile(path)
            }
        }
        for (path in ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem"]) {
            try {
                return fromFile(path)
            } catch (e: Exception) {
                // Try the next platform default.
            }
        }
        throw Exception("no system PEM CA bundle; configure SSL_CERT_FILE or supply a TrustStore")
    }

    public func addPem(text: String): Unit {
        let blocks = pemCertificates(text)
        var i = 0
        while (i < blocks.size) {
            addDer(blocks[i])
            i++
        }
    }

    public func findIssuer(name: X509Name): Option<X509Cert> {
        var i = 0
        while (i < count) {
            if (roots[i].subject.equals(name)) {
                return Some(roots[i])
            }
            i++
        }
        return None
    }
}

/**
 * Verify a server certificate chain (leaf first) against a trust store.
 * Checks signatures, validity, CA constraints, EKU and hostname.
 */
public func verifyCertificateChain(chain: Array<X509Cert>, chainCount: Int64,
    store: TrustStore, host: String, now: Int64,
    backend!: CryptoBackend = PURE_CRYPTO): Bool {
    if (chainCount <= 0 || chainCount > chain.size || chainCount > 8) {
        return false
    }
    let leaf = chain[0]
    if (!leaf.permitsServer(now) || !leaf.matchesHost(host)) {
        return false
    }
    return findChain(leaf, chain, chainCount, store, now, backend, 1, 0)
}

private func findChain(current: X509Cert, chain: Array<X509Cert>, chainCount: Int64,
    store: TrustStore, now: Int64, backend: CryptoBackend, visited: Int64, depth: Int64): Bool {
    for (i in 0..store.count) {
        let anchor = store.roots[i]
        if (ctEqual(current.der, anchor.der) ||
            (anchor.subject.equals(current.issuer) && backend.verifyCertificate(current, anchor))) {
            return true
        }
    }
    for (i in 1..chainCount) {
        let bit = 1 << i
        let candidate = chain[i]
        if ((visited & bit) == 0 && candidate.subject.equals(current.issuer) &&
            candidate.permitsIssuer(depth, now) && backend.verifyCertificate(current, candidate) &&
            findChain(candidate, chain, chainCount, store, now, backend, visited | bit, depth + 1)) {
            return true
        }
    }
    return false
}
