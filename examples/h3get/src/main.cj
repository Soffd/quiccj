package h3get

import quic.crypto.*
import std.convert.Parsable
import std.net.IPSocketAddress
import quic.transport.*
import quic.tls.*
import std.env.getVariable
import std.fs.File
import quic.http3.*
import quic_openssl.OpenSslBackend
private class BodyCounter {
    var size: Int64 = 0
    func accept(bytes: Array<UInt8>): Unit { size += bytes.size }
}

main(args: Array<String>): Int64 {
    var host = "cloudflare-quic.com"
    var path = "/"
    var port: UInt16 = 443
    var verify = true
    if (args.size > 0) {
        host = args[0]
    }
    if (args.size > 1) {
        path = args[1]
    }
    if (args.size > 2) {
        port = UInt16.parse(args[2])
    }
    if (args.size > 3) {
        verify = args[3] != "insecure"
    }
    let store = if (!verify) {
        TrustStore()
    } else if (args.size > 3 && args[3] != "system") {
        TrustStore.fromFile(args[3])
    } else {
        TrustStore.system()
    }
    println("HTTP/3 GET https://${host}:${port}${path} (roots=${store.count}, verify=${verify})")
    let backend: CryptoBackend = if (args.size <= 4 || args[4] == "openssl") {
        OpenSslBackend()
    } else if (args[4] == "pure") {
        PURE_CRYPTO
    } else {
        throw Exception("unknown crypto backend")
    }
    store.requireStapledOcsp = getVariable("QUICCJ_REQUIRE_OCSP").getOrDefault({ => "" }) == "1"
    if (let Some(crl) <- getVariable("QUICCJ_CRL_FILE")) {
        store.addCrlPem(String.fromUtf8(File.readFrom(crl)))
    }
    let identity: Option<ClientIdentity> = if (let Some(chainPath) <- getVariable("QUICCJ_CLIENT_CHAIN")) {
        let keyPath = getVariable("QUICCJ_CLIENT_KEY_DER").getOrThrow()
        let chain = pemCertificates(String.fromUtf8(File.readFrom(chainPath)))
        let leaf = X509Cert.parse(chain[0])
        let scheme: UInt16 = match (leaf.keyType) {
            case "EC" => if (leaf.curveOid == "1.3.132.0.34") { 0x0503 } else { 0x0403 }
            case "RSA" => 0x0804
            case "ED25519" => 0x0807
            case _ => throw Exception("unsupported client certificate")
        }
        let signer = OpenSslBackend()
        Some(ClientIdentity(chain, scheme, { msg =>
            let key = File.readFrom(keyPath)
            try { signer.signClient(key, scheme, msg) } finally { fillBytes(key, 0) }
        }))
    } else { None }
    let mode = if (args.size > 6) { args[6] } else { "" }
    let tlsOptions = TlsOptions(identity: identity)
    let mtu = Int64.parse(getVariable("QUICCJ_SEND_MTU").getOrDefault({ => "1200" }))
    let received = BodyCounter()
    let params = TransportParams()
    if (mode == "transport") { params.initialMaxDatagramFrameSize = 1200 }
    let config = if (mode == "transport") {
        QuicConfig(parameters: params, keepaliveMs: 100, ackEvery: 2, sendMtu: mtu,
            onDatagram: Some(received.accept))
    } else { QuicConfig(sendMtu: mtu) }
    if (mode == "pool") {
        let pool = Http3Pool(store, backend: backend, tlsOptions: tlsOptions, config: config)
        try {
            pool.observeAltSvc(host, 443, "h3=\":" + port.toString() + "\"")
            for (i in 1..3) {
                let response = pool.get(host, 443, "/authority")
                if (!response.complete || response.status != 200 ||
                    String.fromUtf8(response.body) != host + " " + i.toString()) { return 6 }
            }
            println("pool reused alternative with original authority")
            return 0
        } finally { pool.close() }
    }
    let start = nowMillis()
    let conn0 = QuicConnection.dial(host, port, store, verify, tlsOptions: tlsOptions, config: config, backend: backend)
    let ok = conn0.handshake(8000)
    println("handshake=${ok} elapsed_ms=${nowMillis() - start} version=${conn0.version} rx=${conn0.rxCount} closed=${conn0.closed} reason=${conn0.closeReason} err=${conn0.lastError}")
    if (!ok) {
        return 1
    }
    let c = Http3Client(conn0)
    c.openControlStreams()
    if (c.conn.lastError != "") {
        println("note: ${c.conn.lastError}")
    }
    let repeat = if (args.size > 5) { Int64.parse(args[5]) } else { 1 }
    let push = mode == "push"
    if (mode == "migrate") {
        let deadline = nowMillis() + 2000
        while (!conn0.handshakeDone && !conn0.closed && nowMillis() < deadline) {
            c.pollOnce()
        }
        let migrated = conn0.migrate(IPSocketAddress("0.0.0.0", 0))
        println("migrated=" + "${migrated}")
        if (!migrated) {
            conn0.closeConnection("migration failed")
            return 3
        }
    }
    if (push) {
        c.allowPush(1)
    }
    let streamed = BodyCounter()
    var resp = if (mode == "stream") {
        c.getStreaming(path, streamed.accept)
    } else if (mode == "upload") {
        c.post(path, Array<UInt8>(1048576, { i => UInt8(i % 251) }))
    } else { c.get(path) }
    if (mode == "stream") { println("streamed bytes: " + streamed.size.toString()) }
    var completed = if (resp.complete && resp.status == 200) { 1 } else { 0 }
    for (_ in 1..repeat) {
        resp = c.get(path)
        if (resp.complete && resp.status == 200) { completed++ }
        if (!resp.complete || resp.rejected) {
            break
        }
    }
    if (push) {
        let deadline = nowMillis() + 3000
        while (!c.conn.closed && nowMillis() < deadline) {
            if (let Some(promised) <- c.getPush(0)) {
                if (promised.response.complete) {
                    println("push bytes: ${promised.response.body.size}")
                    break
                }
            }
            c.pollOnce()
        }
    }
    if (mode == "transport") {
        let deadline = nowMillis() + 4000
        var sent = false
        while (!conn0.closed && nowMillis() < deadline && (received.size == 0 || (mtu > 1200 && conn0.validatedMtu == 1200))) {
            if (!sent) { sent = conn0.sendDatagram([1, 2, 3]) }
            c.pollOnce()
        }
        println("datagram_echo_bytes=" + received.size.toString())
    }
    if (mode == "key-update") {
        let deadline = nowMillis() + 2000
        var updated = conn0.updateKeys()
        while (!updated && !conn0.closed && nowMillis() < deadline) {
            c.pollOnce()
            updated = conn0.updateKeys()
        }
        println("key_updated=" + updated.toString())
        if (!updated) {
            conn0.closeConnection("key update failed")
            return 5
        }
        resp = c.get(path)
    }
    if (repeat > 1) {
        println("completed_requests=" + completed.toString())
        println("qpack_known_received=" + c.qpackKnownReceivedCount.toString())
    }
    if (mode == "resume") {
        let deadline = nowMillis() + 2000
        var session = conn0.session()
        while (session.isNone() && !conn0.closed && nowMillis() < deadline) {
            c.pollOnce()
            session = conn0.session()
        }
        if (let Some(saved) <- session) {
            conn0.closeConnection("resuming")
            let next = QuicConnection.dial(host, port, store, verify, tlsOptions: tlsOptions, config: config, backend: backend, session: Some(saved),
                allowEarlyData: true, version: saved.version)
            saved.destroy()
            let resumed = Http3Client(next)
            resp = resumed.getEarly(path)
            println("resumed=${next.resumed} early_accepted=${next.earlyDataAccepted} complete=${resp.complete} status=${resp.status} err=${next.lastError}")
            next.closeConnection("done")
        } else {
            println("no resumption ticket received")
            conn0.closeConnection("done")
            return 4
        }
    }
    println("status: ${resp.status} complete=${resp.complete} rejected=${resp.rejected} rx=${c.conn.rxCount} err=${c.conn.lastError}")
    var i = 0
    while (i < resp.headerCount) {
        println("${resp.headers[i].name}: ${resp.headers[i].value}")
        i++
    }
    println("validated_mtu=" + conn0.validatedMtu.toString())
    println("pacing_deferrals=" + c.conn.pacedSendDeferrals.toString() +
        " persistent_congestion=" + c.conn.persistentCongestionEvents.toString())
    println("body bytes: ${resp.body.size}")
    if (resp.body.size > 0) {
        let n = if (resp.body.size > 400) { 400 } else { resp.body.size }
        try {
            println(String.fromUtf8(sliceBytes(resp.body, 0, n)))
        } catch (e: IllegalArgumentException) {
            println("(binary response body)")
        }
    }
    c.conn.closeConnection("done")
    return if (resp.complete && resp.status == 200) { 0 } else { 2 }
}
