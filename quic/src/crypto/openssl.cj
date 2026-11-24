package quic.crypto

import std.env.getVariable
import std.sync.Mutex
import std.collection.HashMap

type Ptr = CPointer<UInt8>
type PtrRef = CPointer<Ptr>
private type IntRef = CPointer<Int32>

@When[os != "Windows"]
foreign func dlopen(filename: CString, flags: Int32): Ptr
@When[os != "Windows"]
foreign func dlsym(handle: Ptr, name: CString): Ptr
@When[os != "Windows"]
foreign func dlclose(handle: Ptr): Int32

@When[os == "Windows"]
foreign func LoadLibraryExW(name: CPointer<UInt16>, file: Ptr, flags: UInt32): Ptr
@When[os == "Windows"]
foreign func MultiByteToWideChar(page: UInt32, flags: UInt32, input: CString, size: Int32,
    output: CPointer<UInt16>, capacity: Int32): Int32
@When[os == "Windows"]
foreign func GetProcAddress(handle: Ptr, name: CString): Ptr
@When[os == "Windows"]
foreign func FreeLibrary(handle: Ptr): Int32
@When[os == "Windows"]
unsafe func dlopen(name: CString, flags: Int32): Ptr {
    let wideSize = MultiByteToWideChar(65001, 8, name, -1, CPointer<UInt16>(), 0)
    if (wideSize <= 0) { return Ptr() }
    let wide = Array<UInt16>(Int64(wideSize), repeat: 0)
    let raw = acquireArrayRawData(wide)
    try {
        if (MultiByteToWideChar(65001, 8, name, -1, raw.pointer, wideSize) != wideSize) { return Ptr() }
        // Include the DLL's own directory for dependencies of an explicitly named file.
        let path = name.toString()
        let search: UInt32 = if (path.contains("\\") || path.contains("/")) { 0x1100 } else { 0x1000 }
        return LoadLibraryExW(raw.pointer, Ptr(), search)
    } finally { releaseArrayRawData(raw) }
}
@When[os == "Windows"]
unsafe func dlsym(handle: Ptr, name: CString): Ptr { GetProcAddress(handle, name) }
@When[os == "Windows"]
unsafe func dlclose(handle: Ptr): Int32 { FreeLibrary(handle) }

let NIL = Ptr()
private const RTLD_NOW: Int32 = 2
private const RSA_PKCS1_PSS_PADDING: Int32 = 6
private const RSA_PSS_SALTLEN_DIGEST: Int32 = -1
private const AEAD_GET_TAG: Int32 = 0x10
private const AEAD_SET_TAG: Int32 = 0x11

func find(handle: Ptr, name: String): Ptr {
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

/** Convert Unicode DNS names to the IDNA A-label used for SNI, DNS, SAN and HTTP authority. */
public func asciiHost(host: String): String {
    let bytes = host.toArray()
    if (bytes.isEmpty() || bytes.contains(0u8)) { throw Exception("invalid host") }
    var unicode = false
    for (b in bytes) { if (b >= 128) { unicode = true } }
    if (!unicode) { return host }
    unsafe {
        for (library in idnLibraries()) {
            let name = LibC.mallocCString(library)
            let handle = dlopen(name, RTLD_NOW)
            LibC.free(name)
            if (handle.isNull()) { continue }
            try {
                let lookup = CFunc<(CString, CPointer<CString>, Int32) -> Int32>(find(handle, "idn2_lookup_u8"))
                let free = CFunc<(CString) -> Unit>(find(handle, "idn2_free"))
                let input = LibC.mallocCString(host)
                var output = CString(NIL)
                try {
                    // IDN2_NONTRANSITIONAL | IDN2_USE_STD3_ASCII_RULES.
                    if (lookup(input, inout output, 40) != 0) { throw Exception("invalid IDNA hostname") }
                    return output.toString()
                } finally {
                    free(output)
                    LibC.free(input)
                }
            } finally { dlclose(handle) }
        }
        throw Exception("Unicode DNS names require libidn2")
    }
}

@When[os == "Windows"]
private func idnLibraries(): Array<String> { ["libidn2-0.dll"] }
@When[os == "macOS"]
private func idnLibraries(): Array<String> { ["libidn2.0.dylib"] }
@When[os != "Windows" && os != "macOS"]
private func idnLibraries(): Array<String> { ["libidn2.so.0", "libidn2.so"] }

private class OpenSslApi {
    let d2i_AutoPrivateKey: CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>
    let EVP_PKEY_get_octet_string_param: CFunc<(Ptr, CString, Ptr, UIntNative, CPointer<UIntNative>) -> Int32>
    let X509_VERIFY_PARAM_set_auth_level: CFunc<(Ptr, Int32) -> Unit>
    let X509_check_ca: CFunc<(Ptr) -> Int32>
    let X509_get_pubkey: CFunc<(Ptr) -> Ptr>
    let X509_verify: CFunc<(Ptr, Ptr) -> Int32>
    let EVP_PKEY_get_bits: CFunc<(Ptr) -> Int32>
    let d2i_X509_CRL: CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>
    let X509_CRL_free: CFunc<(Ptr) -> Unit>
    let X509_STORE_add_crl: CFunc<(Ptr, Ptr) -> Int32>
    let EVP_CIPHER_CTX_reset: CFunc<(Ptr) -> Int32>
    let EVP_PKEY_CTX_new_from_name: CFunc<(Ptr, CString, Ptr) -> Ptr>
    let EVP_PKEY_keygen_init: CFunc<(Ptr) -> Int32>
    let EVP_PKEY_generate: CFunc<(Ptr, PtrRef) -> Int32>
    let EVP_PKEY_get_raw_public_key: CFunc<(Ptr, Ptr, CPointer<UIntNative>) -> Int32>
    let EVP_PKEY_get_raw_private_key: CFunc<(Ptr, Ptr, CPointer<UIntNative>) -> Int32>
    let EVP_PKEY_decapsulate_init: CFunc<(Ptr, Ptr) -> Int32>
    let EVP_PKEY_decapsulate: CFunc<(Ptr, Ptr, CPointer<UIntNative>, Ptr, UIntNative) -> Int32>
    let EVP_DigestSignInit: CFunc<(Ptr, PtrRef, Ptr, Ptr, Ptr) -> Int32>
    let EVP_DigestSign: CFunc<(Ptr, Ptr, CPointer<UIntNative>, Ptr, UIntNative) -> Int32>
    let EVP_PKEY_is_a: CFunc<(Ptr, CString) -> Int32>
    let EVP_PKEY_CTX_set_group_name: CFunc<(Ptr, CString) -> Int32>
    let EVP_PKEY_get_bn_param: CFunc<(Ptr, CString, PtrRef) -> Int32>
    let BN_bn2binpad: CFunc<(Ptr, Ptr, Int32) -> Int32>
    let BN_clear_free: CFunc<(Ptr) -> Unit>
    let d2i_OCSP_RESPONSE: CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>
    let OCSP_RESPONSE_free: CFunc<(Ptr) -> Unit>
    let OCSP_response_status: CFunc<(Ptr) -> Int32>
    let OCSP_response_get1_basic: CFunc<(Ptr) -> Ptr>
    let OCSP_BASICRESP_free: CFunc<(Ptr) -> Unit>
    let OCSP_basic_verify: CFunc<(Ptr, Ptr, Ptr, UIntNative) -> Int32>
    let OCSP_cert_to_id: CFunc<(Ptr, Ptr, Ptr) -> Ptr>
    let OCSP_CERTID_free: CFunc<(Ptr) -> Unit>
    let OCSP_resp_find_status: CFunc<(Ptr, Ptr, IntRef, IntRef, PtrRef, PtrRef, PtrRef) -> Int32>
    let ASN1_TIME_set: CFunc<(Ptr, IntNative) -> Ptr>
    let ASN1_TIME_free: CFunc<(Ptr) -> Unit>
    let ASN1_TIME_compare: CFunc<(Ptr, Ptr) -> Int32>
    let OCSP_resp_get0_produced_at: CFunc<(Ptr) -> Ptr>
    let X509_STORE_CTX_get0_chain: CFunc<(Ptr) -> Ptr>
    let X509_STORE_get0_param: CFunc<(Ptr) -> Ptr>
    let OPENSSL_sk_value: CFunc<(Ptr, Int32) -> Ptr>
    let EVP_sha1: CFunc<() -> Ptr>
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

    // At most one idle, reset context per loaded library. Concurrent callers own separate contexts.
    private let cipherLock = Mutex()
    private var idleCipher = NIL

    func acquireCipher(): Ptr {
        synchronized (cipherLock) {
            if (!idleCipher.isNull()) {
                let ctx = idleCipher
                idleCipher = NIL
                return ctx
            }
        }
        return unsafe { EVP_CIPHER_CTX_new() }
    }

    func releaseCipher(ctx: Ptr): Unit {
        unsafe {
            if (ctx.isNull()) { return }
            if (EVP_CIPHER_CTX_reset(ctx) == 1) {
                synchronized (cipherLock) {
                    if (idleCipher.isNull()) { idleCipher = ctx; return }
                }
            }
            EVP_CIPHER_CTX_free(ctx)
        }
    }

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
            let major = CFunc<() -> UInt32>(find(handle, "OPENSSL_version_major"))
            if (unsafe { major() } != 3) { throw Exception("OpenSSL 3 required") }
            d2i_AutoPrivateKey = CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>(find(handle, "d2i_AutoPrivateKey"))
            EVP_PKEY_get_octet_string_param = CFunc<(Ptr, CString, Ptr, UIntNative, CPointer<UIntNative>) -> Int32>(find(handle, "EVP_PKEY_get_octet_string_param"))
            X509_VERIFY_PARAM_set_auth_level = CFunc<(Ptr, Int32) -> Unit>(find(handle, "X509_VERIFY_PARAM_set_auth_level"))
            X509_check_ca = CFunc<(Ptr) -> Int32>(find(handle, "X509_check_ca"))
            X509_get_pubkey = CFunc<(Ptr) -> Ptr>(find(handle, "X509_get_pubkey"))
            X509_verify = CFunc<(Ptr, Ptr) -> Int32>(find(handle, "X509_verify"))
            EVP_PKEY_get_bits = CFunc<(Ptr) -> Int32>(find(handle, "EVP_PKEY_get_bits"))
            d2i_X509_CRL = CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>(find(handle, "d2i_X509_CRL"))
            X509_CRL_free = CFunc<(Ptr) -> Unit>(find(handle, "X509_CRL_free"))
            X509_STORE_add_crl = CFunc<(Ptr, Ptr) -> Int32>(find(handle, "X509_STORE_add_crl"))
            EVP_CIPHER_CTX_reset = CFunc<(Ptr) -> Int32>(find(handle, "EVP_CIPHER_CTX_reset"))
            EVP_PKEY_CTX_new_from_name = CFunc<(Ptr, CString, Ptr) -> Ptr>(find(handle, "EVP_PKEY_CTX_new_from_name"))
            EVP_PKEY_keygen_init = CFunc<(Ptr) -> Int32>(find(handle, "EVP_PKEY_keygen_init"))
            EVP_PKEY_generate = CFunc<(Ptr, PtrRef) -> Int32>(find(handle, "EVP_PKEY_generate"))
            EVP_PKEY_get_raw_public_key = CFunc<(Ptr, Ptr, CPointer<UIntNative>) -> Int32>(find(handle, "EVP_PKEY_get_raw_public_key"))
            EVP_PKEY_get_raw_private_key = CFunc<(Ptr, Ptr, CPointer<UIntNative>) -> Int32>(find(handle, "EVP_PKEY_get_raw_private_key"))
            EVP_PKEY_decapsulate_init = CFunc<(Ptr, Ptr) -> Int32>(find(handle, "EVP_PKEY_decapsulate_init"))
            EVP_PKEY_decapsulate = CFunc<(Ptr, Ptr, CPointer<UIntNative>, Ptr, UIntNative) -> Int32>(find(handle, "EVP_PKEY_decapsulate"))
            EVP_DigestSignInit = CFunc<(Ptr, PtrRef, Ptr, Ptr, Ptr) -> Int32>(find(handle, "EVP_DigestSignInit"))
            EVP_DigestSign = CFunc<(Ptr, Ptr, CPointer<UIntNative>, Ptr, UIntNative) -> Int32>(find(handle, "EVP_DigestSign"))
            EVP_PKEY_is_a = CFunc<(Ptr, CString) -> Int32>(find(handle, "EVP_PKEY_is_a"))
            EVP_PKEY_CTX_set_group_name = CFunc<(Ptr, CString) -> Int32>(find(handle, "EVP_PKEY_CTX_set_group_name"))
            EVP_PKEY_get_bn_param = CFunc<(Ptr, CString, PtrRef) -> Int32>(find(handle, "EVP_PKEY_get_bn_param"))
            BN_bn2binpad = CFunc<(Ptr, Ptr, Int32) -> Int32>(find(handle, "BN_bn2binpad"))
            BN_clear_free = CFunc<(Ptr) -> Unit>(find(handle, "BN_clear_free"))
            d2i_OCSP_RESPONSE = CFunc<(PtrRef, PtrRef, IntNative) -> Ptr>(find(handle, "d2i_OCSP_RESPONSE"))
            OCSP_RESPONSE_free = CFunc<(Ptr) -> Unit>(find(handle, "OCSP_RESPONSE_free"))
            OCSP_response_status = CFunc<(Ptr) -> Int32>(find(handle, "OCSP_response_status"))
            OCSP_response_get1_basic = CFunc<(Ptr) -> Ptr>(find(handle, "OCSP_response_get1_basic"))
            OCSP_BASICRESP_free = CFunc<(Ptr) -> Unit>(find(handle, "OCSP_BASICRESP_free"))
            OCSP_basic_verify = CFunc<(Ptr, Ptr, Ptr, UIntNative) -> Int32>(find(handle, "OCSP_basic_verify"))
            OCSP_cert_to_id = CFunc<(Ptr, Ptr, Ptr) -> Ptr>(find(handle, "OCSP_cert_to_id"))
            OCSP_CERTID_free = CFunc<(Ptr) -> Unit>(find(handle, "OCSP_CERTID_free"))
            OCSP_resp_find_status = CFunc<(Ptr, Ptr, IntRef, IntRef, PtrRef, PtrRef, PtrRef) -> Int32>(find(handle, "OCSP_resp_find_status"))
            ASN1_TIME_set = CFunc<(Ptr, IntNative) -> Ptr>(find(handle, "ASN1_TIME_set"))
            ASN1_TIME_free = CFunc<(Ptr) -> Unit>(find(handle, "ASN1_TIME_free"))
            ASN1_TIME_compare = CFunc<(Ptr, Ptr) -> Int32>(find(handle, "ASN1_TIME_compare"))
            OCSP_resp_get0_produced_at = CFunc<(Ptr) -> Ptr>(find(handle, "OCSP_resp_get0_produced_at"))
            X509_STORE_CTX_get0_chain = CFunc<(Ptr) -> Ptr>(find(handle, "X509_STORE_CTX_get0_chain"))
            X509_STORE_get0_param = CFunc<(Ptr) -> Ptr>(find(handle, "X509_STORE_get0_param"))
            OPENSSL_sk_value = CFunc<(Ptr, Int32) -> Ptr>(find(handle, "OPENSSL_sk_value"))
            EVP_sha1 = CFunc<() -> Ptr>(find(handle, "EVP_sha1"))
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

private let apiLock = Mutex()
private let loadedApis = HashMap<String, OpenSslApi>()

private func loadApi(path: String): OpenSslApi {
    synchronized (apiLock) {
        if (let Some(api) <- loadedApis.get(path)) { return api }
        let candidates = if (path != "") { [path] } else { libraryNames() }
        var detail = ""
        for (name in candidates) {
            try {
                let api = OpenSslApi(name)
                loadedApis.add(path, api)
                return api
            } catch (e: Exception) {
                detail += " " + e.message
            }
        }
        throw Exception("OpenSSL 3 unavailable:" + detail)
    }
}

@When[os == "macOS"]
private func libraryNames(): Array<String> { ["libcrypto.3.dylib", "libcrypto.dylib"] }

@When[os == "Windows"]
private func libraryNames(): Array<String> { ["libcrypto-3-x64.dll", "libcrypto-3.dll"] }

@When[os != "macOS" && os != "Windows"]
private func libraryNames(): Array<String> { ["libcrypto.so.3", "libcrypto.so"] }

/** EVP implementation. Library discovery occurs only on explicit construction or first connection. */
public class NativeCryptoBackend <: CryptoBackend {
    private let api: OpenSslApi

    public init(path!: String = getVariable("QUICCJ_LIBCRYPTO").getOrDefault({ => "" })) {
        if (path.toArray().contains(0u8)) { throw Exception("invalid OpenSSL library path") }
        api = loadApi(path)
    }

    public override func mlkem768Keys(): Option<(Array<UInt8>, Array<UInt8>)> {
        unsafe {
            let name = LibC.mallocCString("ML-KEM-768")
            let ctx = api.EVP_PKEY_CTX_new_from_name(NIL, name, NIL)
            LibC.free(name)
            if (ctx.isNull()) { api.ERR_clear_error(); return None }
            var key = NIL
            try {
                if (api.EVP_PKEY_keygen_init(ctx) != 1 || api.EVP_PKEY_generate(ctx, inout key) != 1) {
                    throw Exception("ML-KEM-768 key generation failed")
                }
                let priv = Array<UInt8>(2400, repeat: 0)
                let pub = Array<UInt8>(1184, repeat: 0)
                let dk = acquireArrayRawData(priv)
                let ek = acquireArrayRawData(pub)
                var d: UIntNative = 2400
                var e: UIntNative = 1184
                let ok = api.EVP_PKEY_get_raw_private_key(key, dk.pointer, inout d) == 1 &&
                    api.EVP_PKEY_get_raw_public_key(key, ek.pointer, inout e) == 1
                releaseArrayRawData(ek)
                releaseArrayRawData(dk)
                if (!ok || d != 2400 || e != 1184) {
                    fillBytes(priv, 0)
                    throw Exception("ML-KEM-768 key export failed")
                }
                return Some((priv, pub))
            } finally {
                api.EVP_PKEY_free(key)
                api.EVP_PKEY_CTX_free(ctx)
                api.ERR_clear_error()
            }
        }
    }

    public override func mlkem768Open(priv: Array<UInt8>, ciphertext: Array<UInt8>): Array<UInt8> {
        if (priv.size != 2400 || ciphertext.size != 1088) { throw Exception("invalid ML-KEM-768 input") }
        unsafe {
            let name = LibC.mallocCString("ML-KEM-768")
            let dk = acquireArrayRawData(priv)
            let key = api.EVP_PKEY_new_raw_private_key_ex(NIL, name, NIL, dk.pointer, UIntNative(priv.size))
            releaseArrayRawData(dk)
            LibC.free(name)
            if (key.isNull()) { throw Exception("invalid ML-KEM-768 key") }
            let ctx = api.EVP_PKEY_CTX_new(key, NIL)
            try {
                let secret = Array<UInt8>(32, repeat: 0)
                let ct = acquireArrayRawData(ciphertext)
                let out = acquireArrayRawData(secret)
                var size: UIntNative = 32
                let ok = !ctx.isNull() && api.EVP_PKEY_decapsulate_init(ctx, NIL) == 1 &&
                    api.EVP_PKEY_decapsulate(ctx, out.pointer, inout size, ct.pointer, 1088) == 1
                releaseArrayRawData(out)
                releaseArrayRawData(ct)
                if (!ok || size != 32) {
                    fillBytes(secret, 0)
                    throw Exception("ML-KEM-768 decapsulation failed")
                }
                return secret
            } finally {
                api.EVP_PKEY_CTX_free(ctx)
                api.EVP_PKEY_free(key)
                api.ERR_clear_error()
            }
        }
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

    public override func p256Private(): Array<UInt8> {
        unsafe {
            let ec = LibC.mallocCString("EC")
            let ctx = api.EVP_PKEY_CTX_new_from_name(NIL, ec, NIL)
            LibC.free(ec)
            let group = LibC.mallocCString("prime256v1")
            let parameter = LibC.mallocCString("priv")
            var key = NIL
            var scalar = NIL
            try {
                if (ctx.isNull() || api.EVP_PKEY_keygen_init(ctx) != 1 ||
                    api.EVP_PKEY_CTX_set_group_name(ctx, group) != 1 || api.EVP_PKEY_generate(ctx, inout key) != 1 ||
                    api.EVP_PKEY_get_bn_param(key, parameter, inout scalar) != 1) {
                    throw Exception("OpenSSL P-256 key generation failed")
                }
                let out = Array<UInt8>(32, repeat: 0)
                let raw = acquireArrayRawData(out)
                let size = api.BN_bn2binpad(scalar, raw.pointer, 32)
                releaseArrayRawData(raw)
                if (size != 32) { fillBytes(out, 0); throw Exception("OpenSSL P-256 scalar export failed") }
                return out
            } finally {
                api.BN_clear_free(scalar)
                api.EVP_PKEY_free(key)
                api.EVP_PKEY_CTX_free(ctx)
                LibC.free(parameter)
                LibC.free(group)
                api.ERR_clear_error()
            }
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
        return verifyPeerChain(chain, count, anchors, host, now, [])
    }

    public override func verifyPeerChain(chain: Array<X509Cert>, count: Int64, anchors: TrustStore, host: String,
        now: Int64, staple: Array<UInt8>): Bool {
        if (count < 1 || count > chain.size || host == "" || host.toArray().contains(0u8)) {
            return false
        }
        if (anchors.requireStapledOcsp && staple.isEmpty()) { return false }
        if (anchors.nativeSystem) { return verifySystemChain(chain, count, anchors, host, now, this, staple: staple) }
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
                    if (anchor.isNull()) { return false }
                    let added = api.X509_STORE_add_cert(store, anchor)
                    api.X509_free(anchor)
                    if (added != 1) { return false }
                }
                for (der in anchors.revocationLists) {
                    let input = acquireArrayRawData(der)
                    var cursor = input.pointer
                    let crl = api.d2i_X509_CRL(PtrRef(), inout cursor, IntNative(der.size))
                    releaseArrayRawData(input)
                    if (crl.isNull()) { return false }
                    let added = api.X509_STORE_add_crl(store, crl) == 1
                    api.X509_CRL_free(crl)
                    if (!added) { return false }
                }
                for (i in 0..count) {
                    untrusted[i] = certificate(chain[i].der)
                    if (untrusted[i].isNull() ||
                        (i > 0 && api.OPENSSL_sk_push(intermediates, untrusted[i]) <= 0)) {
                        return false
                    }
                }
                if (api.X509_check_ca(untrusted[0]) != 0 || api.X509_STORE_CTX_init(ctx, store, untrusted[0], intermediates) != 1 ||
                    api.X509_STORE_CTX_set_purpose(ctx, 2) != 1) { // X509_PURPOSE_SSL_SERVER
                    return false
                }
                let params = api.X509_STORE_CTX_get0_param(ctx)
                api.X509_VERIFY_PARAM_set_auth_level(params, 2)
                api.X509_VERIFY_PARAM_set_time(params, IntNative(now))
                // NO_PARTIAL_WILDCARDS | NEVER_CHECK_SUBJECT; name or IP must match SAN.
                api.X509_VERIFY_PARAM_set_hostflags(params, 0x24)
                let flags: UIntNative = if (anchors.requireCrl) { 0x8000c } else { 0x80000 }
                if (api.X509_VERIFY_PARAM_set_flags(params, flags) != 1) {
                    return false
                }
                let normalized = asciiHost(host)
                let name = LibC.mallocCString(normalized)
                let ok = api.X509_VERIFY_PARAM_set1_ip_asc(params, name) == 1 ||
                    api.X509_VERIFY_PARAM_set1_host(params, name, UIntNative(normalized.toArray().size)) == 1
                LibC.free(name)
                if (!ok || api.X509_verify_cert(ctx) != 1) { return false }
                if (!anchors.requireStapledOcsp) { return true }
                // Only time and auth level apply to delegated OCSP responders; hostname and server EKU do not.
                let responderParams = api.X509_STORE_get0_param(store)
                api.X509_VERIFY_PARAM_set_auth_level(responderParams, 2)
                api.X509_VERIFY_PARAM_set_time(responderParams, IntNative(now))
                return validStaple(staple, store, ctx, now)
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

    private unsafe func validStaple(der: Array<UInt8>, store: Ptr, ctx: Ptr, now: Int64): Bool {
        let object = Der.parse(der)
        object.enter(0x30)
        if (!object.eof()) { return false }
        let raw = acquireArrayRawData(der)
        var cursor = raw.pointer
        let response = api.d2i_OCSP_RESPONSE(PtrRef(), inout cursor, IntNative(der.size))
        releaseArrayRawData(raw)
        if (response.isNull()) { return false }
        try {
            if (api.OCSP_response_status(response) != 0) { return false }
            let basic = api.OCSP_response_get1_basic(response)
            if (basic.isNull()) { return false }
            let verified = api.X509_STORE_CTX_get0_chain(ctx)
            let clock = api.ASN1_TIME_set(NIL, IntNative(now))
            try {
                let produced = api.OCSP_resp_get0_produced_at(basic)
                if (clock.isNull() || produced.isNull() || !atOrBefore(produced, clock) ||
                    api.OCSP_basic_verify(basic, verified, store, 0) != 1) { return false }
                let leaf = api.OPENSSL_sk_value(verified, 0)
                let issuer = api.OPENSSL_sk_value(verified, 1)
                if (issuer.isNull()) { return false }
                for (digest in [api.EVP_sha1(), api.EVP_sha256(), api.EVP_sha384(), api.EVP_sha512()]) {
                    let id = api.OCSP_cert_to_id(digest, leaf, issuer)
                    if (id.isNull()) { return false }
                    var status: Int32 = -1
                    var reason: Int32 = 0
                    var revoked = NIL
                    var updated = NIL
                    var expires = NIL
                    let found = api.OCSP_resp_find_status(basic, id, inout status, inout reason, inout revoked,
                        inout updated, inout expires)
                    api.OCSP_CERTID_free(id)
                    if (found == 1) {
                        return status == 0 && !updated.isNull() && !expires.isNull() &&
                            atOrBefore(updated, produced) && api.ASN1_TIME_compare(clock, expires) == -1
                    }
                }
                return false
            } finally { api.ASN1_TIME_free(clock); api.OCSP_BASICRESP_free(basic) }
        } finally { api.OCSP_RESPONSE_free(response) }
    }

    private unsafe func atOrBefore(a: Ptr, b: Ptr): Bool {
        let order = api.ASN1_TIME_compare(a, b)
        return order == -1 || order == 0
    }

    public override func verifyCertificate(cert: X509Cert, issuer: X509Cert): Bool {
        unsafe {
            let child = certificate(cert.der)
            let parent = certificate(issuer.der)
            try {
                if (child.isNull() || parent.isNull()) { return false }
                let key = api.X509_get_pubkey(parent)
                if (key.isNull()) { return false }
                try {
                    return api.X509_verify(child, key) == 1
                } finally { api.EVP_PKEY_free(key) }
            } finally {
                api.X509_free(child)
                api.X509_free(parent)
                api.ERR_clear_error()
            }
        }
    }

    public override prop supportsEd25519: Bool { get() { true } }

    /** TLS 1.3 signer for a DER private key. The caller retains ownership of keyDer. */
    public func signClient(keyDer: Array<UInt8>, scheme: UInt16, message: Array<UInt8>): Array<UInt8> {
        let pss = scheme >= 0x0804 && scheme <= 0x0806
        let kind = if (pss) { "RSA" } else if (scheme == 0x0807) { "ED25519" } else if (
            scheme == 0x0403 || scheme == 0x0503) { "EC" } else { throw Exception("unsupported client signature") }
        unsafe {
            let data = acquireArrayRawData(keyDer)
            var cursor = data.pointer
            let key = api.d2i_AutoPrivateKey(PtrRef(), inout cursor, IntNative(keyDer.size))
            releaseArrayRawData(data)
            if (key.isNull()) { throw Exception("invalid client private key DER") }
            let ctx = api.EVP_MD_CTX_new()
            try {
                let name = LibC.mallocCString(kind)
                let compatible = api.EVP_PKEY_is_a(key, name) == 1
                LibC.free(name)
                let md = match (scheme) {
                    case 0x0807 => NIL
                    case 0x0806 => api.EVP_sha512()
                    case 0x0805 | 0x0503 => api.EVP_sha384()
                    case _ => api.EVP_sha256()
                }
                var pctx = NIL
                if (!compatible || ctx.isNull() || (pss && api.EVP_PKEY_get_bits(key) < 2048) ||
                    api.EVP_DigestSignInit(ctx, inout pctx, md, NIL, key) != 1 ||
                    (pss && (api.EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1 ||
                    api.EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1))) {
                    throw Exception("client signing key or signature scheme rejected")
                }
                let msg = acquireArrayRawData(message)
                try {
                    var size: UIntNative = 0
                    if (api.EVP_DigestSign(ctx, NIL, inout size, msg.pointer, UIntNative(message.size)) != 1 ||
                        size == 0 || size > 65535) { throw Exception("invalid client signature length") }
                    let sig = Array<UInt8>(Int64(size), repeat: 0)
                    let out = acquireArrayRawData(sig)
                    let ok = api.EVP_DigestSign(ctx, out.pointer, inout size, msg.pointer, UIntNative(message.size))
                    releaseArrayRawData(out)
                    if (ok != 1) { throw Exception("client signing failed") }
                    return sig[0..Int64(size)]
                } finally { releaseArrayRawData(msg) }
            } finally {
                api.EVP_PKEY_free(key)
                api.EVP_MD_CTX_free(ctx)
                api.ERR_clear_error()
            }
        }
    }

    public override func verifyHandshake(cert: X509Cert, scheme: Int64, message: Array<UInt8>,
        signature: Array<UInt8>): Bool {
        if (scheme == 0x0807 && cert.keyType == "ED25519") {
            return verify(cert.publicKeyDer, NIL, message, signature, false)
        }
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
        return verify(cert.publicKeyDer, digestType(alg), message, signature, pss)
    }

    private func verify(publicDer: Array<UInt8>, digest: Ptr, message: Array<UInt8>,
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
                if ((pss && api.EVP_PKEY_get_bits(key) < 2048) || api.EVP_DigestVerifyInit(ctx, inout pctx, digest, NIL, key) != 1) {
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
            let ctx = api.acquireCipher()
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
            api.releaseCipher(ctx)
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
            let ctx = api.acquireCipher()
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
            api.releaseCipher(ctx)
            api.ERR_clear_error()
            if (ok) {
                copyBytes(packet, offset, out, 0, length)
            }
            fillBytes(out, 0)
            return ok
        }
    }
}
