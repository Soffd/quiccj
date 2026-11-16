package consumer_native

import quic.crypto.{CryptoBackend, PURE_CRYPTO, TrustStore}
import quic.http3.Http3Client
import quic_openssl.OpenSslBackend

private const OK: Int32 = 0
private const INVALID_ARGUMENT: Int32 = 1
private const HANDSHAKE_FAILED: Int32 = 2
private const BUFFER_TOO_SMALL: Int32 = 3
private const FAILED: Int32 = 4

// Layout matches struct quiccj_smoke_request in smoke.h.
@C
public struct SmokeRequest {
    public var host: CString = CString(CPointer<UInt8>())
    public var caFile: CString = CString(CPointer<UInt8>())
    public var body: CPointer<UInt8> = CPointer<UInt8>()
    public var bodyCapacity: UIntNative = 0
    public var bodySize: UIntNative = 0
    public var status: Int32 = 0
    public var result: Int32 = 0
    public var port: UInt16 = 0
    public var backend: UInt8 = 0
}

/** Runtime task entry. The caller retains the request and buffers until the task returns. */
@C
public func quiccj_consumer_get(arg: CPointer<Unit>): CPointer<Unit> {
    if (arg.isNull()) {
        return CPointer<Unit>()
    }
    unsafe {
        let ptr = CPointer<SmokeRequest>(arg)
        var request = ptr.read()
        request.status = 0
        request.bodySize = 0
        try {
            request = get(request)
        } catch (e: Exception) {
            request.result = FAILED
        }
        ptr.write(request)
    }
    return arg
}

private func get(input: SmokeRequest): SmokeRequest {
    var request = input
    if (request.host.isNull() || request.caFile.isNull() || request.body.isNull() ||
        request.port == 0 || request.backend > 1) {
        request.result = INVALID_ARGUMENT
        return request
    }
    let host = unsafe { request.host.toString() }
    let caFile = unsafe { request.caFile.toString() }
    let trust = TrustStore.fromFile(caFile)
    let backend: CryptoBackend = if (request.backend == 1) { OpenSslBackend() } else { PURE_CRYPTO }
    if (let Some(client) <- Http3Client.connect(host, request.port, trust, true, 8000, backend: backend)) {
        try {
            let response = client.get("/")
            if (!response.complete) {
                request.result = FAILED
                return request
            }
            request.status = Int32(response.status)
            request.bodySize = UIntNative(response.body.size)
            if (request.bodySize > request.bodyCapacity) {
                request.result = BUFFER_TOO_SMALL
                return request
            }
            unsafe {
                for (i in 0..response.body.size) {
                    request.body.write(i, response.body[i])
                }
            }
            request.result = OK
        } finally {
            client.conn.closeConnection("C consumer smoke test")
        }
    } else {
        request.result = HANDSHAKE_FAILED
    }
    return request
}
