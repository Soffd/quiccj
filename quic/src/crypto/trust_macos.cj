package quic.crypto

@When[os == "macOS"]
private func framework(path: String): Ptr {
    unsafe {
        let name = LibC.mallocCString(path)
        try {
            let handle = dlopen(name, 2)
            if (handle.isNull()) { throw Exception("cannot load " + path) }
            return handle
        } finally { LibC.free(name) }
    }
}

@When[os == "macOS"]
func platformChain(chain: Array<X509Cert>, host: String, now: Int64): Array<X509Cert> {
    unsafe {
        let cf = framework("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        try {
            let security = framework("/System/Library/Frameworks/Security.framework/Security")
            try { return appleTrust(cf, security, chain, host, now) } finally { dlclose(security) }
        } finally { dlclose(cf) }
    }
}

@When[os == "macOS"]
private unsafe func appleTrust(cf: Ptr, sec: Ptr, chain: Array<X509Cert>, host: String, now: Int64): Array<X509Cert> {
    let release = CFunc<(Ptr) -> Unit>(find(cf, "CFRelease"))
    let string = CFunc<(Ptr, CString, UInt32) -> Ptr>(find(cf, "CFStringCreateWithCString"))
    let date = CFunc<(Ptr, Float64) -> Ptr>(find(cf, "CFDateCreate"))
    let data = CFunc<(Ptr, Ptr, IntNative) -> Ptr>(find(cf, "CFDataCreate"))
    let array = CFunc<(Ptr, IntNative, Ptr) -> Ptr>(find(cf, "CFArrayCreateMutable"))
    let append = CFunc<(Ptr, Ptr) -> Unit>(find(cf, "CFArrayAppendValue"))
    let at = CFunc<(Ptr, IntNative) -> Ptr>(find(cf, "CFArrayGetValueAtIndex"))
    let count = CFunc<(Ptr) -> IntNative>(find(cf, "CFArrayGetCount"))
    let length = CFunc<(Ptr) -> IntNative>(find(cf, "CFDataGetLength"))
    let bytes = CFunc<(Ptr) -> Ptr>(find(cf, "CFDataGetBytePtr"))
    let certificate = CFunc<(Ptr, Ptr) -> Ptr>(find(sec, "SecCertificateCreateWithData"))
    let der = CFunc<(Ptr) -> Ptr>(find(sec, "SecCertificateCopyData"))
    let ssl = CFunc<(UInt8, Ptr) -> Ptr>(find(sec, "SecPolicyCreateSSL"))
    let create = CFunc<(Ptr, Ptr, PtrRef) -> Int32>(find(sec, "SecTrustCreateWithCertificates"))
    let setDate = CFunc<(Ptr, Ptr) -> Int32>(find(sec, "SecTrustSetVerifyDate"))
    let evaluate = CFunc<(Ptr, PtrRef) -> UInt8>(find(sec, "SecTrustEvaluateWithError"))
    let copyPath = CFunc<(Ptr) -> Ptr>(find(sec, "SecTrustCopyCertificateChain"))
    let name = LibC.mallocCString(host)
    let dns = string(NIL, name, 0x08000100)
    LibC.free(name)
    if (dns.isNull()) { return [] }
    let policy = ssl(1, dns)
    release(dns)
    let certs = array(NIL, 0, find(cf, "kCFTypeArrayCallBacks"))
    let verifyDate = date(NIL, Float64(now) - 978307200.0)
    var trust = NIL
    try {
        if (certs.isNull() || policy.isNull() || verifyDate.isNull()) { return [] }
        for (cert in chain) {
            let raw = acquireArrayRawData(cert.der)
            let encoded = data(NIL, raw.pointer, IntNative(cert.der.size))
            releaseArrayRawData(raw)
            if (encoded.isNull()) { return [] }
            let native = certificate(NIL, encoded)
            release(encoded)
            if (native.isNull()) { return [] }
            append(certs, native)
            release(native)
        }
        if (create(certs, policy, inout trust) != 0 || setDate(trust, verifyDate) != 0 ||
            evaluate(trust, PtrRef()) == 0) { return [] }
        let path = copyPath(trust)
        if (path.isNull()) { return [] }
        try {
            let n = Int64(count(path))
            if (n < 1 || n > 16) { return [] }
            return Array<X509Cert>(n, { i =>
                let encoded = der(at(path, IntNative(i)))
                if (encoded.isNull()) { throw Exception("missing Keychain certificate") }
                try {
                    let content = bytes(encoded)
                    X509Cert.parse(Array<UInt8>(Int64(length(encoded)), { j => content.read(j) }))
                } finally { release(encoded) }
            })
        } finally { release(path) }
    } finally {
        for (ref in [trust, certs, policy, verifyDate]) { if (!ref.isNull()) { release(ref) } }
    }
}
