package quic.crypto

@When[os == "Windows"]
@C
private struct ChainHeader {
    var size: UInt32 = 0
    var error: UInt32 = 0
    var info: UInt32 = 0
    var count: UInt32 = 0
    var entries: CPointer<CPointer<UInt8>> = CPointer<CPointer<UInt8>>()
}

@When[os == "Windows"]
@C
private struct ChainElement {
    var size: UInt32 = 0
    var cert: CPointer<WinCertificate> = CPointer<WinCertificate>()
}

@When[os == "Windows"]
@C
private struct WinCertificate {
    var encoding: UInt32 = 0
    var data: CPointer<UInt8> = CPointer<UInt8>()
    var length: UInt32 = 0
}

@When[os == "Windows"]
@C
private struct EnhancedKeyUsage {
    var count: UInt32 = 0
    var oids: CPointer<CString> = CPointer<CString>()
}

@When[os == "Windows"]
@C
private struct UsageMatch {
    var matchType: UInt32 = 0
    var usage = EnhancedKeyUsage()
}

@When[os == "Windows"]
@C
private struct ChainParameters {
    var size: UInt32 = 0
    var request = UsageMatch()
}

@When[os == "Windows"]
@C
private struct SslPolicy {
    var size: UInt32 = 0
    var authType: UInt32 = 2 // AUTHTYPE_SERVER
    var checks: UInt32 = 0
    var serverName: CPointer<UInt16> = CPointer<UInt16>()
}

@When[os == "Windows"]
@C
private struct PolicyParameters {
    var size: UInt32 = 0
    var flags: UInt32 = 0
    var ssl: CPointer<SslPolicy> = CPointer<SslPolicy>()
}

@When[os == "Windows"]
@C
private struct PolicyResult {
    var size: UInt32 = 0
    var error: UInt32 = 0
    var chain: Int32 = 0
    var element: Int32 = 0
    var extra: CPointer<UInt8> = CPointer<UInt8>()
}

@When[os == "Windows"]
private unsafe func approvedWindowsPath(result: CPointer<UInt8>): Array<X509Cert> {
    let header = CPointer<ChainHeader>(result).read()
    if (header.error != 0 || header.count != 1) { return [] }
    let simple = CPointer<ChainHeader>(header.entries.read()).read()
    if (simple.count == 0 || simple.count > 16 || simple.error != 0) { return [] }
    let entries = simple.entries
    return Array<X509Cert>(Int64(simple.count), { i =>
        let context = CPointer<ChainElement>(entries.read(i)).read().cert.read()
        let data = context.data
        let der = Array<UInt8>(Int64(context.length), { n => data.read(n) })
        X509Cert.parse(der)
    })
}

@When[os == "Windows"]
func platformChain(chain: Array<X509Cert>, host: String, now: Int64): Array<X509Cert> {
    unsafe {
        let library = LibC.mallocCString("crypt32.dll")
        let api = dlopen(library, 2)
        LibC.free(library)
        if (api.isNull()) { throw Exception("Windows certificate services unavailable") }
        try {
            let open = CFunc<(UIntNative, UInt32, Ptr, UInt32, Ptr) -> Ptr>(find(api, "CertOpenStore"))
            let close = CFunc<(Ptr, UInt32) -> Int32>(find(api, "CertCloseStore"))
            let add = CFunc<(Ptr, UInt32, Ptr, UInt32, UInt32, PtrRef) -> Int32>(find(api, "CertAddEncodedCertificateToStore"))
            let freeCert = CFunc<(Ptr) -> Int32>(find(api, "CertFreeCertificateContext"))
            let build = CFunc<(Ptr, Ptr, CPointer<Int64>, Ptr, CPointer<ChainParameters>, UInt32, Ptr, PtrRef) -> Int32>(
                find(api, "CertGetCertificateChain"))
            let freeChain = CFunc<(Ptr) -> Unit>(find(api, "CertFreeCertificateChain"))
            let verify = CFunc<(UIntNative, Ptr, CPointer<PolicyParameters>, CPointer<PolicyResult>) -> Int32>(
                find(api, "CertVerifyCertificateChainPolicy"))
            let store = open(2, 0, NIL, 0, NIL) // CERT_STORE_PROV_MEMORY
            if (store.isNull()) { return [] }
            var leaf = NIL
            var path = NIL
            var oid = LibC.mallocCString("1.3.6.1.5.5.7.3.1")
            let oids = LibC.malloc<CString>()
            let sslPtr = LibC.malloc<SslPolicy>()
            try {
                if (oids.isNull() || sslPtr.isNull()) { return [] }
                for (i in 0..chain.size) {
                    let raw = acquireArrayRawData(chain[i].der)
                    var cert = NIL
                    let ok = add(store, 1, raw.pointer, UInt32(chain[i].der.size), 4, inout cert)
                    releaseArrayRawData(raw)
                    if (ok == 0) { return [] }
                    if (i == 0) { leaf = cert } else { freeCert(cert) }
                }
                var params = ChainParameters()
                params.size = UInt32(sizeOf<ChainParameters>())
                params.request.usage.count = 1
                oids.write(oid)
                params.request.usage.oids = oids
                var fileTime = (now + 11644473600) * 10000000
                if (build(NIL, leaf, inout fileTime, store, inout params, 0, NIL, inout path) == 0) { return [] }
                let bytes = host.toArray()
                let wide = Array<UInt16>(bytes.size + 1, repeat: 0)
                for (i in 0..bytes.size) { wide[i] = UInt16(bytes[i]) }
                let data = acquireArrayRawData(wide)
                var ssl = SslPolicy()
                ssl.size = UInt32(sizeOf<SslPolicy>())
                ssl.serverName = data.pointer
                var policy = PolicyParameters()
                policy.size = UInt32(sizeOf<PolicyParameters>())
                sslPtr.write(ssl)
                policy.ssl = sslPtr
                var status = PolicyResult()
                status.size = UInt32(sizeOf<PolicyResult>())
                let ok = verify(4, path, inout policy, inout status) // CERT_CHAIN_POLICY_SSL
                releaseArrayRawData(data)
                if (ok == 0 || status.error != 0) { return [] }
                return approvedWindowsPath(path)
            } finally {
                LibC.free(sslPtr)
                LibC.free(oids)
                LibC.free(oid)
                if (!path.isNull()) { freeChain(path) }
                if (!leaf.isNull()) { freeCert(leaf) }
                close(store, 0)
            }
        } finally { dlclose(api) }
    }
}
