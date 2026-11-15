package quic.crypto

/*
 * X.509 certificate parsing and chain verification (ECDSA P-256/P-384
 * signatures, SAN/EKU/basicConstraints handling).
 */

public class X509Name {
    public var cn: String = ""
    public var org: String = ""
    public var full: String = ""

    public func equals(o: X509Name): Bool {
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

    public func addSan(v: String): Unit {
        if (sanCount < sans.size) {
            sans[sanCount] = v
            sanCount++
        }
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

        let tbsStart = cert.pos
        let tbsTlv = cert.readTLV()
        let tbsEnd = cert.pos
        c.tbs = sliceBytes(derBytes, tbsStart, tbsEnd - tbsStart)

        let sigAlg = cert.enter(0x30)
        c.sigAlg = sigAlg.readOid()
        let sigVal = cert.readBitString()
        c.signature = sigVal[1]

        let tbs = Der(derBytes, tbsTlv[1], tbsTlv[1] + tbsTlv[2])
        if (tbs.peekTag() == 0xA0) {
            let v = tbs.enter(0xA0)
            let _ = v.readInt64()
        }
        c.serial = tbs.readIntegerBytes()
        let innerSig = tbs.enter(0x30)
        let _ = innerSig.readOid()
        c.issuer = parseName(tbs.enter(0x30))
        let validity = tbs.enter(0x30)
        c.notBefore = validity.readTime()
        c.notAfter = validity.readTime()
        c.subject = parseName(tbs.enter(0x30))

        let spki = tbs.enter(0x30)
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
        let key = spki.readBitString()
        c.spki = key[1]

        while (!tbs.eof()) {
            let t = tbs.readTLV()
            if (t[0] == 0xA3) {
                let exts = Der(derBytes, t[1], t[1] + t[2])
                let seq = exts.enter(0x30)
                while (!seq.eof()) {
                    let ext = seq.enter(0x30)
                    let oid = ext.readOid()
                    if (ext.peekTag() == 0x01) {
                        ext.readTLV()
                    }
                    let val = ext.readOctetString()
                    applyExtension(c, oid, val)
                }
            }
        }
        return c
    }

    private static func parseName(nameSeq: Der): X509Name {
        let n = X509Name()
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

    private static func applyExtension(c: X509Cert, oid: String, val: Array<UInt8>): Unit {
        try {
            if (oid == "2.5.29.17") {
                let d = Der(val, 0, val.size)
                let seq = d.enter(0x30)
                while (!seq.eof()) {
                    let t = seq.readTLV()
                    if (t[0] == 0x82) {
                        c.addSan(String.fromUtf8(sliceBytes(val, t[1], t[2])))
                    } else if (t[0] == 0x87) {
                        var ip = ""
                        var i = 0
                        while (i < t[2]) {
                            if (i > 0) {
                                ip = ip + "."
                            }
                            ip = ip + "${val[t[1] + i]}"
                            i++
                        }
                        c.addSan(ip)
                    }
                }
            } else if (oid == "2.5.29.19") {
                c.basicConstraintsPresent = true
                let d = Der(val, 0, val.size)
                let seq = d.enter(0x30)
                if (!seq.eof() && seq.peekTag() == 0x01) {
                    let b = seq.readContent()
                    c.isCA = b[0] != 0
                }
            } else if (oid == "2.5.29.15") {
                c.keyUsagePresent = true
                let d = Der(val, 0, val.size)
                let bs = d.readBitString()
                if (bs[1].size > 0) {
                    c.keyUsageDigitalSignature = (bs[1][0] & 0x80) != 0
                }
            } else if (oid == "2.5.29.37") {
                c.ekuPresent = true
                let d = Der(val, 0, val.size)
                let seq = d.enter(0x30)
                while (!seq.eof()) {
                    let e = seq.readOid()
                    if (e == "1.3.6.1.5.5.7.3.1") {
                        c.ekuServerAuth = true
                    }
                }
            }
        } catch (e: Exception) {
            // ignore malformed optional extensions
        }
    }

    private static func hashFor(alg: String, data: Array<UInt8>): Option<Array<UInt8>> {
        if (alg == "1.2.840.10045.4.3.2" || alg == "1.2.840.113549.1.1.11" ||
            alg == "1.2.840.113549.1.1.10") {
            return Some(sha256(data))
        }
        if (alg == "1.2.840.10045.4.3.3") {
            return Some(sha384(data))
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

    /** RFC 6125-style host match with single-label wildcard support. */
    public func matchesHost(host: String): Bool {
        let h = toLowerAscii(host)
        var i = 0
        while (i < sanCount) {
            if (matchName(toLowerAscii(sans[i]), h)) {
                return true
            }
            i++
        }
        if (sanCount == 0 && subject.cn != "") {
            return matchName(toLowerAscii(subject.cn), h)
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
            if (count < roots.size) {
                roots[count] = c
                count++
            }
        } catch (e: Exception) {
            // skip malformed root
        }
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
    store: TrustStore, host: String, now: Int64): Bool {
    if (chainCount <= 0) {
        return false
    }
    let leaf = chain[0]
    if (!leaf.validAt(now)) {
        return false
    }
    if (leaf.ekuPresent && !leaf.ekuServerAuth) {
        return false
    }
    if (!leaf.matchesHost(host)) {
        return false
    }
    var current = leaf
    var depth = 0
    while (depth < 8) {
        let anchor = store.findIssuer(current.issuer)
        if (anchor.isSome()) {
            let a = anchor.getOrThrow()
            if (current.verifySignedBy(a)) {
                return true
            }
        }
        // find an intermediate that signs `current`
        var next = Option<X509Cert>.None
        var i = 1
        while (i < chainCount) {
            let c = chain[i]
            if (c.subject.equals(current.issuer) && c.isCA && c.validAt(now) &&
                current.verifySignedBy(c)) {
                next = Some(c)
                break
            }
            i++
        }
        if (next.isNone()) {
            return false
        }
        current = next.getOrThrow()
        depth++
    }
    return false
}
