package quic_openssl

import quic.crypto.*

private type Ptr = CPointer<UInt8>
private type PtrRef = CPointer<Ptr>
private type IntRef = CPointer<Int32>

foreign func dlopen(filename: CString, flags: Int32): Ptr
foreign func dlsym(handle: Ptr, name: CString): Ptr
foreign func dlclose(handle: Ptr): Int32

private let NIL = Ptr()
private const RTLD_NOW: Int32 = 2
private const RSA_PKCS1_PSS_PADDING: Int32 = 6
private const RSA_PSS_SALTLEN_DIGEST: Int32 = -1
private const AEAD_GET_TAG: Int32 = 0x10
private const AEAD_SET_TAG: Int32 = 0x11

private func find(handle: Ptr, name: String): Ptr {
    unsafe {
        let cName = LibC.mallocCString(name)
        try {
            let result = dlsym(handle, cName)
            if (result.isNull()) {
                throw Exception("missing OpenSSL symbol " + name)
            }
            return result
        } finally {
            LibC.free(cName)
        }
    }
}

private class OpenSslApi {
    let d2i_AutoPrivateKey: CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>
    let EVP_PKEY_get_octet_string_param: CFunc<(Ptr, CString, Ptr, UIntNative, CPointer<UIntNative>) -> Int32>
    let d2i_X509: CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>
    let X509_free: CFunc<(Ptr) -> Unit>
    let X509_STORE_new: CFunc<() -> Ptr>
    let X509_STORE_free: CFunc<(Ptr) -> Unit>
    let X509_STORE_add_cert: CFunc<(Ptr, Ptr) -> Int32>
    let X509_STORE_CTX_new: CFunc<() -> Ptr>
    let X509_STORE_CTX_free: CFunc<(Ptr) -> Unit>
    let X509_STORE_CTX_init: CFunc<(Ptr, Ptr, Ptr, Ptr) -> Int32>
    let X509_STORE_CTX_get0_param: CFunc<(Ptr) -> Ptr>
    let X509_STORE_CTX_set_purpose: CFunc<(Ptr, Int32) -> Int32>
    let X509_VERIFY_PARAM_set1_host: CFunc<(Ptr, CString, UIntNative) -> Int32>
    let X509_VERIFY_PARAM_set1_ip_asc: CFunc<(Ptr, CString) -> Int32>
    let X509_VERIFY_PARAM_set_hostflags: CFunc<(Ptr, UInt32) -> Unit>
    let X509_VERIFY_PARAM_set_time: CFunc<(Ptr, IntNative) -> Unit>
    let X509_VERIFY_PARAM_set_flags: CFunc<(Ptr, UIntNative) -> Int32>
    let X509_verify_cert: CFunc<(Ptr) -> Int32>
    let OPENSSL_sk_new_null: CFunc<() -> Ptr>
    let OPENSSL_sk_free: CFunc<(Ptr) -> Unit>
    let OPENSSL_sk_push: CFunc<(Ptr, Ptr) -> Int32>
    let EVP_sha256: CFunc<() -> Ptr>
    let EVP_sha384: CFunc<() -> Ptr>
    let EVP_sha512: CFunc<() -> Ptr>
    let EVP_Digest: CFunc<(Ptr, UIntNative, Ptr, IntRef, Ptr, Ptr) -> Int32>
    let EVP_MD_CTX_new: CFunc<() -> Ptr>
    let EVP_MD_CTX_free: CFunc<(Ptr) -> Unit>
    let EVP_DigestVerifyInit: CFunc<(Ptr, PtrRef, Ptr, Ptr, Ptr) -> Int32>
    let EVP_DigestVerify: CFunc<(Ptr, Ptr, UIntNative, Ptr, UIntNative) -> Int32>
    let EVP_PKEY_CTX_set_rsa_padding: CFunc<(Ptr, Int32) -> Int32>
    let EVP_PKEY_CTX_set_rsa_pss_saltlen: CFunc<(Ptr, Int32) -> Int32>
    let d2i_PUBKEY: CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>
    let EVP_PKEY_new_raw_private_key_ex: CFunc<(Ptr, CString, Ptr, Ptr, UIntNative) -> Ptr>
    let EVP_PKEY_new_raw_public_key_ex: CFunc<(Ptr, CString, Ptr, Ptr, UIntNative) -> Ptr>
    let EVP_PKEY_CTX_new: CFunc<(Ptr, Ptr) -> Ptr>
    let EVP_PKEY_CTX_free: CFunc<(Ptr) -> Unit>
    let EVP_PKEY_free: CFunc<(Ptr) -> Unit>
    let EVP_PKEY_derive_init: CFunc<(Ptr) -> Int32>
    let EVP_PKEY_derive_set_peer: CFunc<(Ptr, Ptr) -> Int32>
    let EVP_PKEY_derive: CFunc<(Ptr, Ptr, CPointer<UIntNative>) -> Int32>
    let EVP_aes_128_gcm: CFunc<() -> Ptr>
    let EVP_aes_256_gcm: CFunc<() -> Ptr>
    let EVP_aes_128_ecb: CFunc<() -> Ptr>
    let EVP_aes_256_ecb: CFunc<() -> Ptr>
    let EVP_chacha20_poly1305: CFunc<() -> Ptr>
    let EVP_chacha20: CFunc<() -> Ptr>
    let EVP_CIPHER_CTX_new: CFunc<() -> Ptr>
    let EVP_CIPHER_CTX_free: CFunc<(Ptr) -> Unit>
    let EVP_CIPHER_CTX_set_padding: CFunc<(Ptr, Int32) -> Int32>
    let EVP_CIPHER_CTX_ctrl: CFunc<(Ptr, Int32, Int32, Ptr) -> Int32>
    let EVP_CipherInit_ex: CFunc<(Ptr, Ptr, Ptr, Ptr, Ptr, Int32) -> Int32>
    let EVP_CipherUpdate: CFunc<(Ptr, Ptr, IntRef, Ptr, Int32) -> Int32>
    let EVP_CipherFinal_ex: CFunc<(Ptr, Ptr, IntRef) -> Int32>
    let ERR_clear_error: CFunc<() -> Unit>

    init(path: String) {
        let handle = unsafe {
            let name = LibC.mallocCString(path)
            try {
                dlopen(name, RTLD_NOW)
            } finally {
                LibC.free(name)
            }
        }
        if (handle.isNull()) {
            throw Exception("could not load OpenSSL 3: " + path)
        }
        // Keep a successful dlopen handle for the lifetime of the process.
        try {
            d2i_AutoPrivateKey = CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>(find(handle, "d2i_AutoPrivateKey"))
            EVP_PKEY_get_octet_string_param = CFunc<(Ptr, CString, Ptr, UIntNative, CPointer<UIntNative>) -> Int32>(find(handle, "EVP_PKEY_get_octet_string_param"))
            d2i_X509 = CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>(find(handle, "d2i_X509"))
            X509_free = CFunc<(Ptr) -> Unit>(find(handle, "X509_free"))
            X509_STORE_new = CFunc<() -> Ptr>(find(handle, "X509_STORE_new"))
            X509_STORE_free = CFunc<(Ptr) -> Unit>(find(handle, "X509_STORE_free"))
            X509_STORE_add_cert = CFunc<(Ptr, Ptr) -> Int32>(find(handle, "X509_STORE_add_cert"))
            X509_STORE_CTX_new = CFunc<() -> Ptr>(find(handle, "X509_STORE_CTX_new"))
            X509_STORE_CTX_free = CFunc<(Ptr) -> Unit>(find(handle, "X509_STORE_CTX_free"))
            X509_STORE_CTX_init = CFunc<(Ptr, Ptr, Ptr, Ptr) -> Int32>(find(handle, "X509_STORE_CTX_init"))
            X509_STORE_CTX_get0_param = CFunc<(Ptr) -> Ptr>(find(handle, "X509_STORE_CTX_get0_param"))
            X509_STORE_CTX_set_purpose = CFunc<(Ptr, Int32) -> Int32>(find(handle, "X509_STORE_CTX_set_purpose"))
            X509_VERIFY_PARAM_set1_host = CFunc<(Ptr, CString, UIntNative) -> Int32>(find(handle, "X509_VERIFY_PARAM_set1_host"))
            X509_VERIFY_PARAM_set1_ip_asc = CFunc<(Ptr, CString) -> Int32>(find(handle, "X509_VERIFY_PARAM_set1_ip_asc"))
            X509_VERIFY_PARAM_set_hostflags = CFunc<(Ptr, UInt32) -> Unit>(find(handle, "X509_VERIFY_PARAM_set_hostflags"))
            X509_VERIFY_PARAM_set_time = CFunc<(Ptr, IntNative) -> Unit>(find(handle, "X509_VERIFY_PARAM_set_time"))
            X509_VERIFY_PARAM_set_flags = CFunc<(Ptr, UIntNative) -> Int32>(find(handle, "X509_VERIFY_PARAM_set_flags"))
            X509_verify_cert = CFunc<(Ptr) -> Int32>(find(handle, "X509_verify_cert"))
            OPENSSL_sk_new_null = CFunc<() -> Ptr>(find(handle, "OPENSSL_sk_new_null"))
            OPENSSL_sk_free = CFunc<(Ptr) -> Unit>(find(handle, "OPENSSL_sk_free"))
            OPENSSL_sk_push = CFunc<(Ptr, Ptr) -> Int32>(find(handle, "OPENSSL_sk_push"))
            EVP_sha256 = CFunc<() -> Ptr>(find(handle, "EVP_sha256"))
            EVP_sha384 = CFunc<() -> Ptr>(find(handle, "EVP_sha384"))
            EVP_sha512 = CFunc<() -> Ptr>(find(handle, "EVP_sha512"))
            EVP_Digest = CFunc<(Ptr, UIntNative, Ptr, IntRef, Ptr, Ptr) -> Int32>(find(handle, "EVP_Digest"))
            EVP_MD_CTX_new = CFunc<() -> Ptr>(find(handle, "EVP_MD_CTX_new"))
            EVP_MD_CTX_free = CFunc<(Ptr) -> Unit>(find(handle, "EVP_MD_CTX_free"))
            EVP_DigestVerifyInit = CFunc<(Ptr, PtrRef, Ptr, Ptr, Ptr) -> Int32>(find(handle, "EVP_DigestVerifyInit"))
            EVP_DigestVerify = CFunc<(Ptr, Ptr, UIntNative, Ptr, UIntNative) -> Int32>(find(handle, "EVP_DigestVerify"))
            EVP_PKEY_CTX_set_rsa_padding = CFunc<(Ptr, Int32) -> Int32>(find(handle, "EVP_PKEY_CTX_set_rsa_padding"))
            EVP_PKEY_CTX_set_rsa_pss_saltlen = CFunc<(Ptr, Int32) -> Int32>(find(handle, "EVP_PKEY_CTX_set_rsa_pss_saltlen"))
            d2i_PUBKEY = CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>(find(handle, "d2i_PUBKEY"))
            EVP_PKEY_new_raw_private_key_ex = CFunc<(Ptr, CString, Ptr, Ptr, UIntNative) -> Ptr>(find(handle, "EVP_PKEY_new_raw_private_key_ex"))
            EVP_PKEY_new_raw_public_key_ex = CFunc<(Ptr, CString, Ptr, Ptr, UIntNative) -> Ptr>(find(handle, "EVP_PKEY_new_raw_public_key_ex"))
            EVP_PKEY_CTX_new = CFunc<(Ptr, Ptr) -> Ptr>(find(handle, "EVP_PKEY_CTX_new"))
            EVP_PKEY_CTX_free = CFunc<(Ptr) -> Unit>(find(handle, "EVP_PKEY_CTX_free"))
            EVP_PKEY_free = CFunc<(Ptr) -> Unit>(find(handle, "EVP_PKEY_free"))
            EVP_PKEY_derive_init = CFunc<(Ptr) -> Int32>(find(handle, "EVP_PKEY_derive_init"))
            EVP_PKEY_derive_set_peer = CFunc<(Ptr, Ptr) -> Int32>(find(handle, "EVP_PKEY_derive_set_peer"))
            EVP_PKEY_derive = CFunc<(Ptr, Ptr, CPointer<UIntNative>) -> Int32>(find(handle, "EVP_PKEY_derive"))
            EVP_aes_128_gcm = CFunc<() -> Ptr>(find(handle, "EVP_aes_128_gcm"))
            EVP_aes_256_gcm = CFunc<() -> Ptr>(find(handle, "EVP_aes_256_gcm"))
            EVP_aes_128_ecb = CFunc<() -> Ptr>(find(handle, "EVP_aes_128_ecb"))
            EVP_aes_256_ecb = CFunc<() -> Ptr>(find(handle, "EVP_aes_256_ecb"))
            EVP_chacha20_poly1305 = CFunc<() -> Ptr>(find(handle, "EVP_chacha20_poly1305"))
            EVP_chacha20 = CFunc<() -> Ptr>(find(handle, "EVP_chacha20"))
            EVP_CIPHER_CTX_new = CFunc<() -> Ptr>(find(handle, "EVP_CIPHER_CTX_new"))
            EVP_CIPHER_CTX_free = CFunc<(Ptr) -> Unit>(find(handle, "EVP_CIPHER_CTX_free"))
            EVP_CIPHER_CTX_set_padding = CFunc<(Ptr, Int32) -> Int32>(find(handle, "EVP_CIPHER_CTX_set_padding"))
            EVP_CIPHER_CTX_ctrl = CFunc<(Ptr, Int32, Int32, Ptr) -> Int32>(find(handle, "EVP_CIPHER_CTX_ctrl"))
            EVP_CipherInit_ex = CFunc<(Ptr, Ptr, Ptr, Ptr, Ptr, Int32) -> Int32>(find(handle, "EVP_CipherInit_ex"))
            EVP_CipherUpdate = CFunc<(Ptr, Ptr, IntRef, Ptr, Int32) -> Int32>(find(handle, "EVP_CipherUpdate"))
            EVP_CipherFinal_ex = CFunc<(Ptr, Ptr, IntRef) -> Int32>(find(handle, "EVP_CipherFinal_ex"))
            ERR_clear_error = CFunc<() -> Unit>(find(handle, "ERR_clear_error"))
        } catch (e: Exception) {
            unsafe { dlclose(handle) }
            throw e
        }
    }
}

private let defaultApi = OpenSslApi("libcrypto.so.3")

/** Optional EVP backend for Linux. Constructing it requires the OpenSSL 3 runtime. */
public class OpenSslBackend <: CryptoBackend {
    private let api: OpenSslApi

    public init() {
        api = defaultApi
    }

    private func digestType(alg: HashAlg): Ptr {
        unsafe {
            return match (alg) {
                case Sha256 => api.EVP_sha256()
                case Sha384 => api.EVP_sha384()
                case Sha512 => api.EVP_sha512()
            }
        }
    }

    public override func digest(alg: HashAlg, message: Array<UInt8>): Array<UInt8> {
        let out = Array<UInt8>(hashSize(alg), repeat: 0)
        unsafe {
            let input = acquireArrayRawData(message)
            let output = acquireArrayRawData(out)
            var size: Int32 = 0
            let ok = api.EVP_Digest(input.pointer, UIntNative(message.size), output.pointer,
                inout size, digestType(alg), NIL)
            releaseArrayRawData(output)
            releaseArrayRawData(input)
            if (ok != 1 || Int64(size) != out.size) {
                api.ERR_clear_error()
                throw Exception("OpenSSL digest failed")
            }
        }
        return out
    }

    public override func x25519(privateKey: Array<UInt8>, peerPublic: Array<UInt8>): Array<UInt8> {
        unsafe {
            let name = LibC.mallocCString("X25519")
            let priv = acquireArrayRawData(privateKey)
            let peer = acquireArrayRawData(peerPublic)
            let localKey = api.EVP_PKEY_new_raw_private_key_ex(NIL, name, NIL, priv.pointer,
                UIntNative(privateKey.size))
            let peerKey = api.EVP_PKEY_new_raw_public_key_ex(NIL, name, NIL, peer.pointer,
                UIntNative(peerPublic.size))
            releaseArrayRawData(peer)
            releaseArrayRawData(priv)
            LibC.free(name)
            try {
                if (localKey.isNull() || peerKey.isNull()) {
                    throw Exception("invalid OpenSSL X25519 key")
                }
                return deriveKey(localKey, peerKey)
            } finally {
                api.EVP_PKEY_free(peerKey)
                api.EVP_PKEY_free(localKey)
                api.ERR_clear_error()
            }
        }
    }

    private func deriveKey(localKey: Ptr, peerKey: Ptr): Array<UInt8> {
        unsafe {
            let ctx = api.EVP_PKEY_CTX_new(localKey, NIL)
            if (ctx.isNull()) {
                throw Exception("OpenSSL key context allocation failed")
            }
            try {
                let key = Array<UInt8>(32, repeat: 0)
                let out = acquireArrayRawData(key)
                var size: UIntNative = 32
                let ok = api.EVP_PKEY_derive_init(ctx) == 1 &&
                    api.EVP_PKEY_derive_set_peer(ctx, peerKey) == 1 &&
                    api.EVP_PKEY_derive(ctx, out.pointer, inout size) == 1
                releaseArrayRawData(out)
                if (!ok || size != 32) {
                    throw Exception("OpenSSL ECDH derivation failed")
                }
                return key
            } finally {
                api.EVP_PKEY_CTX_free(ctx)
            }
        }
    }

    private func ecPrivate(privateKey: Array<UInt8>): Ptr {
        if (privateKey.size != 32) {
            throw Exception("invalid P-256 private key length")
        }
        // RFC 5915 ECPrivateKey, named curve prime256v1.
        let encoded = concat3(hexDecode("30310201010420"), privateKey, hexDecode("a00a06082a8648ce3d030107"))
        unsafe {
            let data = acquireArrayRawData(encoded)
            var cursor = data.pointer
            let key = api.d2i_AutoPrivateKey(PtrRef(), inout cursor, IntNative(encoded.size))
            releaseArrayRawData(data)
            fillBytes(encoded, 0)
            if (key.isNull()) {
                api.ERR_clear_error()
                throw Exception("invalid OpenSSL P-256 private key")
            }
            return key
        }
    }

    private func publicKey(der: Array<UInt8>): Ptr {
        unsafe {
            let input = acquireArrayRawData(der)
            var cursor = input.pointer
            let key = api.d2i_PUBKEY(PtrRef(), inout cursor, IntNative(der.size))
            releaseArrayRawData(input)
            return key
        }
    }

    public override func p256Public(privateKey: Array<UInt8>): Array<UInt8> {
        unsafe {
            let key = ecPrivate(privateKey)
            let name = LibC.mallocCString("pub")
            let encoded = Array<UInt8>(65, repeat: 0)
            let data = acquireArrayRawData(encoded)
            var size: UIntNative = 0
            let ok = api.EVP_PKEY_get_octet_string_param(key, name, data.pointer, 65, inout size)
            releaseArrayRawData(data)
            LibC.free(name)
            api.EVP_PKEY_free(key)
            if (ok != 1 || size != 65) {
                api.ERR_clear_error()
                throw Exception("OpenSSL P-256 public key export failed")
            }
            return encoded
        }
    }

    public override func p256(privateKey: Array<UInt8>, peerPublic: Array<UInt8>): Array<UInt8> {
        if (peerPublic.size != 65 || peerPublic[0] != 4) {
            throw Exception("invalid OpenSSL P-256 public key length")
        }
        unsafe {
            let local = ecPrivate(privateKey)
            let peer = publicKey(concat(hexDecode("3059301306072a8648ce3d020106082a8648ce3d030107034200"),
                peerPublic))
            try {
                if (peer.isNull()) {
                    throw Exception("invalid OpenSSL P-256 public key")
                }
                return deriveKey(local, peer)
            } finally {
                api.EVP_PKEY_free(peer)
                api.EVP_PKEY_free(local)
                api.ERR_clear_error()
            }
        }
    }

    private func certificate(der: Array<UInt8>): Ptr {
        unsafe {
            let input = acquireArrayRawData(der)
            var cursor = input.pointer
            let cert = api.d2i_X509(PtrRef(), inout cursor, IntNative(der.size))
            releaseArrayRawData(input)
            return cert
        }
    }

    public override func verifyChain(chain: Array<X509Cert>, count: Int64, anchors: TrustStore, host: String,
        now: Int64): Bool {
        if (count < 1 || count > chain.size || host == "" || host.toArray().contains(0u8)) {
            return false
        }
        unsafe {
            let store = api.X509_STORE_new()
            let ctx = api.X509_STORE_CTX_new()
            let intermediates = api.OPENSSL_sk_new_null()
            let untrusted = Array<Ptr>(count, repeat: NIL)
            try {
                if (store.isNull() || ctx.isNull() || intermediates.isNull()) {
                    throw Exception("OpenSSL certificate context allocation failed")
                }
                for (i in 0..anchors.count) {
                    let anchor = certificate(anchors.roots[i].der)
                    if (!anchor.isNull()) {
                        api.X509_STORE_add_cert(store, anchor)
                        api.X509_free(anchor)
                    }
                }
                for (i in 0..count) {
                    untrusted[i] = certificate(chain[i].der)
                    if (untrusted[i].isNull() ||
                        (i > 0 && api.OPENSSL_sk_push(intermediates, untrusted[i]) <= 0)) {
                        return false
                    }
                }
                if (api.X509_STORE_CTX_init(ctx, store, untrusted[0], intermediates) != 1 ||
                    api.X509_STORE_CTX_set_purpose(ctx, 2) != 1) { // X509_PURPOSE_SSL_SERVER
                    return false
                }
                let params = api.X509_STORE_CTX_get0_param(ctx)
                api.X509_VERIFY_PARAM_set_time(params, IntNative(now))
                // NO_PARTIAL_WILDCARDS | NEVER_CHECK_SUBJECT; name or IP must match SAN.
                api.X509_VERIFY_PARAM_set_hostflags(params, 0x24)
                if (api.X509_VERIFY_PARAM_set_flags(params, 0x80000) != 1) { // PARTIAL_CHAIN
                    return false
                }
                let name = LibC.mallocCString(host)
                let ok = api.X509_VERIFY_PARAM_set1_ip_asc(params, name) == 1 ||
                    api.X509_VERIFY_PARAM_set1_host(params, name, UIntNative(host.toArray().size)) == 1
                LibC.free(name)
                return ok && api.X509_verify_cert(ctx) == 1
            } finally {
                api.X509_STORE_CTX_free(ctx)
                api.OPENSSL_sk_free(intermediates)
                for (cert in untrusted) {
                    api.X509_free(cert)
                }
                api.X509_STORE_free(store)
                api.ERR_clear_error()
            }
        }
    }

    public override func verifyCertificate(cert: X509Cert, issuer: X509Cert): Bool {
        let alg = match (cert.sigAlg) {
            case "1.2.840.10045.4.3.2" | "1.2.840.113549.1.1.11" => HashAlg.Sha256
            case "1.2.840.10045.4.3.3" | "1.2.840.113549.1.1.12" => HashAlg.Sha384
            case "1.2.840.10045.4.3.4" | "1.2.840.113549.1.1.13" => HashAlg.Sha512
            case _ => return false
        }
        let rsaSignature = cert.sigAlg.startsWith("1.2.840.113549.")
        if ((rsaSignature && issuer.keyType != "RSA") || (!rsaSignature && issuer.keyType != "EC")) {
            return false
        }
        return verify(issuer.publicKeyDer, alg, cert.tbs, cert.signature, false)
    }

    public override func verifyHandshake(cert: X509Cert, scheme: Int64, message: Array<UInt8>,
        signature: Array<UInt8>): Bool {
        let pss = scheme >= 0x0804 && scheme <= 0x0806
        if (!((pss && cert.keyType == "RSA") ||
            (scheme == 0x0403 && cert.curveOid == "1.2.840.10045.3.1.7") ||
            (scheme == 0x0503 && cert.curveOid == "1.3.132.0.34"))) {
            return false
        }
        let alg = if (scheme == 0x0806) { HashAlg.Sha512 } else if (scheme == 0x0805 || scheme == 0x0503) {
            HashAlg.Sha384
        } else {
            HashAlg.Sha256
        }
        return verify(cert.publicKeyDer, alg, message, signature, pss)
    }

    private func verify(publicDer: Array<UInt8>, alg: HashAlg, message: Array<UInt8>,
        signature: Array<UInt8>, pss: Bool): Bool {
        unsafe {
            let key = publicKey(publicDer)
            if (key.isNull()) {
                api.ERR_clear_error()
                return false
            }
            let ctx = api.EVP_MD_CTX_new()
            try {
                if (ctx.isNull()) {
                    throw Exception("OpenSSL verification context allocation failed")
                }
                var pctx = NIL
                if (api.EVP_DigestVerifyInit(ctx, inout pctx, digestType(alg), NIL, key) != 1) {
                    return false
                }
                if (pss && (api.EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
                    api.EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1)) {
                    return false
                }
                let sig = acquireArrayRawData(signature)
                let msg = acquireArrayRawData(message)
                let ok = api.EVP_DigestVerify(ctx, sig.pointer, UIntNative(signature.size),
                    msg.pointer, UIntNative(message.size))
                releaseArrayRawData(msg)
                releaseArrayRawData(sig)
                return ok == 1
            } finally {
                api.EVP_MD_CTX_free(ctx)
                api.EVP_PKEY_free(key)
                api.ERR_clear_error()
            }
        }
    }

    public override func headerMask(chacha: Bool, key: Array<UInt8>, sample: Array<UInt8>): Array<UInt8> {
        if (sample.size != 16 || (chacha && key.size != 32) ||
            (!chacha && key.size != 16 && key.size != 32)) {
            throw Exception("invalid OpenSSL header protection input")
        }
        unsafe {
            let cipher = if (chacha) { api.EVP_chacha20() } else if (key.size == 32) {
                api.EVP_aes_256_ecb()
            } else {
                api.EVP_aes_128_ecb()
            }
            let iv = if (chacha) { sample } else { Array<UInt8>() }
            let input = if (chacha) { Array<UInt8>(16, repeat: 0) } else { sample }
            let out = Array<UInt8>(32, repeat: 0)
            let ctx = api.EVP_CIPHER_CTX_new()
            let k = acquireArrayRawData(key)
            let n = acquireArrayRawData(iv)
            let src = acquireArrayRawData(input)
            let dst = acquireArrayRawData(out)
            var size: Int32 = 0
            let ok = !ctx.isNull() &&
                api.EVP_CipherInit_ex(ctx, cipher, NIL, k.pointer,
                    if (chacha) { n.pointer } else { NIL }, 1) == 1 &&
                api.EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
                api.EVP_CipherUpdate(ctx, dst.pointer, inout size, src.pointer, 16) == 1
            releaseArrayRawData(dst)
            releaseArrayRawData(src)
            releaseArrayRawData(n)
            releaseArrayRawData(k)
            api.EVP_CIPHER_CTX_free(ctx)
            if (!ok || size != 16) {
                api.ERR_clear_error()
                throw Exception("OpenSSL header protection failed")
            }
            return out
        }
    }

    public override func seal(chacha: Bool, key: Array<UInt8>, nonce: Array<UInt8>, aad: Array<UInt8>,
        packet: Array<UInt8>, offset: Int64, length: Int64): Unit {
        if (!crypt(true, chacha, key, nonce, aad, packet, offset, length, offset + length)) {
            throw Exception("OpenSSL packet encryption failed")
        }
    }

    public override func openPacket(chacha: Bool, key: Array<UInt8>, nonce: Array<UInt8>, aad: Array<UInt8>,
        packet: Array<UInt8>, offset: Int64, length: Int64, tagOffset: Int64): Bool {
        return crypt(false, chacha, key, nonce, aad, packet, offset, length, tagOffset)
    }

    private func crypt(encrypt: Bool, chacha: Bool, key: Array<UInt8>, nonce: Array<UInt8>,
        aad: Array<UInt8>, packet: Array<UInt8>, offset: Int64, length: Int64, tagOffset: Int64): Bool {
        let keySize = if (chacha || key.size == 32) { 32 } else { 16 }
        if (key.size != keySize || nonce.size != 12 || offset < 0 || length < 0 ||
            offset > packet.size || length > packet.size - offset ||
            tagOffset < 0 || tagOffset > packet.size - 16 || aad.size > Int64(Int32.Max) ||
            length > Int64(Int32.Max)) {
            throw Exception("invalid OpenSSL AEAD input")
        }
        let out = Array<UInt8>(length + 16, repeat: 0)
        unsafe {
            let cipher = if (chacha) { api.EVP_chacha20_poly1305() } else if (key.size == 32) {
                api.EVP_aes_256_gcm()
            } else {
                api.EVP_aes_128_gcm()
            }
            let ctx = api.EVP_CIPHER_CTX_new()
            let k = acquireArrayRawData(key)
            let n = acquireArrayRawData(nonce)
            let a = acquireArrayRawData(aad)
            let wire = acquireArrayRawData(packet)
            let dst = acquireArrayRawData(out)
            var size: Int32 = 0
            var finalSize: Int32 = 0
            let direction: Int32 = if (encrypt) { 1 } else { 0 }
            let ok = !ctx.isNull() &&
                api.EVP_CipherInit_ex(ctx, cipher, NIL, k.pointer, n.pointer, direction) == 1 &&
                api.EVP_CipherUpdate(ctx, NIL, inout size, a.pointer, Int32(aad.size)) == 1 &&
                (encrypt || api.EVP_CIPHER_CTX_ctrl(ctx, AEAD_SET_TAG, 16, wire.pointer + tagOffset) == 1) &&
                api.EVP_CipherUpdate(ctx, dst.pointer, inout size, wire.pointer + offset, Int32(length)) == 1 &&
                Int64(size) == length &&
                api.EVP_CipherFinal_ex(ctx, dst.pointer + length, inout finalSize) == 1 &&
                finalSize == 0 &&
                (!encrypt || api.EVP_CIPHER_CTX_ctrl(ctx, AEAD_GET_TAG, 16, wire.pointer + tagOffset) == 1)
            releaseArrayRawData(dst)
            releaseArrayRawData(wire)
            releaseArrayRawData(a)
            releaseArrayRawData(n)
            releaseArrayRawData(k)
            api.EVP_CIPHER_CTX_free(ctx)
            api.ERR_clear_error()
            if (ok) {
                copyBytes(packet, offset, out, 0, length)
            }
            return ok
        }
    }
}
