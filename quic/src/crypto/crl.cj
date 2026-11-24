package quic.crypto

import std.collection.HashSet

/** Direct, complete issuer CRLs. Scoped, indirect and delta CRLs require the native path builder. */
private func extensionsSupported(sequence: Der): Bool {
    let seen = HashSet<String>()
    while (!sequence.eof()) {
        let ext = sequence.enter(0x30)
        let oid = ext.readOid()
        if (!seen.add(oid) || oid == "2.5.29.27" || oid == "2.5.29.28" || oid == "2.5.29.29") {
            return false
        }
        // Unknown noncritical extensions do not affect direct, complete CRL processing.
        if (ext.peekTag() == 1) { return false }
        ext.readOctetString()
        if (!ext.eof()) { return false }
    }
    return true
}

private enum CrlStatus { | Inapplicable | Good | Revoked }

private func inspectCrl(der: Array<UInt8>, child: X509Cert, issuer: X509Cert, now: Int64): CrlStatus {
    let outer = Der.parse(der)
    let list = outer.enter(0x30)
    let start = list.pos
    let tbs = list.enter(0x30)
    let proof = X509Cert()
    proof.tbs = der[start..list.pos]
    let algStart = list.pos
    let alg = list.enter(0x30)
    let algorithm = der[algStart..list.pos]
    proof.sigAlg = alg.readOid()
    proof.algorithmParameters = der[alg.pos..alg.end]
    let (unused, signature) = list.readBitString()
    if (!outer.eof() || !list.eof() || unused != 0) { return CrlStatus.Inapplicable }
    proof.signature = signature
    let v2 = tbs.peekTag() == 2
    if (v2 && tbs.readInt64() != 1) { return CrlStatus.Inapplicable }
    let inner = tbs.pos
    tbs.enter(0x30)
    if (!ctEqual(algorithm, der[inner..tbs.pos])) { return CrlStatus.Inapplicable }
    let name = X509Cert.parseName(tbs.enter(0x30))
    if (!issuer.subject.equals(name) || tbs.readTime() > now || tbs.readTime() <= now) {
        return CrlStatus.Inapplicable
    }
    var revoked = false
    if (tbs.peekTag() == 0x30) {
        let entries = tbs.enter(0x30)
        while (!entries.eof()) {
            let entry = entries.enter(0x30)
            let serial = entry.readIntegerBytes()
            entry.readTime()
            if (!entry.eof() && (!v2 || !extensionsSupported(entry.enter(0x30)) || !entry.eof())) {
                return CrlStatus.Inapplicable
            }
            if (ctEqual(child.serial, serial)) { revoked = true }
        }
    }
    if (!tbs.eof()) {
        let extensions = tbs.enter(0xa0)
        if (!v2 || !extensionsSupported(extensions.enter(0x30)) || !extensions.eof() || !tbs.eof()) {
            return CrlStatus.Inapplicable
        }
    }
    if (!proof.verifySignedBy(issuer)) { return CrlStatus.Inapplicable }
    return if (revoked) { CrlStatus.Revoked } else { CrlStatus.Good }
}

func permitsRevocation(child: X509Cert, issuer: X509Cert, store: TrustStore, now: Int64): Bool {
    if (!store.requireCrl) { return true }
    if (issuer.keyUsagePresent && !issuer.crlSign) { return false }
    var covered = false
    try {
        for (crl in store.revocationLists) {
            match (inspectCrl(crl, child, issuer, now)) {
                case Revoked => return false
                case Good => covered = true
                case Inapplicable => ()
            }
        }
    } catch (e: Exception) { return false }
    return covered
}
