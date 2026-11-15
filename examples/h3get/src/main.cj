package h3get

import quic.crypto.*
import quic.transport.*
import quic.http3.*
import std.fs.*
import std.env.*

func readText(path: String): String {
    let f = File(path, OpenMode.Read)
    let buf = Array<UInt8>(1048576, repeat: 0)
    let n = f.read(buf)
    f.close()
    return String.fromUtf8(sliceBytes(buf, 0, n))
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
        var pv: Int64 = 0
        let pb = args[2].toArray()
        var pi = 0
        while (pi < pb.size) {
            if (pb[pi] >= 48 && pb[pi] <= 57) {
                pv = pv * 10 + Int64(pb[pi] - 48)
            }
            pi++
        }
        port = UInt16(pv)
    }
    if (args.size > 3) {
        verify = args[3] != "insecure"
    }
    let store = TrustStore()
    try {
        store.addPem(readText("/workspace/quic/testdata/roots.pem"))
    } catch (e: Exception) {
        println("root load error: ${e}")
    }
    println("HTTP/3 GET https://${host}:${port}${path} (roots=${store.count}, verify=${verify})")
    let conn0 = QuicConnection.dial(host, port, store, verify)
    conn0.debug = true
    let ok = conn0.handshake(8000)
    println("handshake=${ok} rx=${conn0.rxCount} closed=${conn0.closed} reason=${conn0.closeReason} err=${conn0.lastError}")
    if (!ok) {
        return 1
    }
    let c = Http3Client(conn0)
    c.openControlStreams()
    if (c.conn.lastError != "") {
        println("note: ${c.conn.lastError}")
    }
    let resp = c.get(path)
    println("status: ${resp.status} rx=${c.conn.rxCount} err=${c.conn.lastError}")
    var i = 0
    while (i < resp.headerCount) {
        println("${resp.headers[i].name}: ${resp.headers[i].value}")
        i++
    }
    println("body bytes: ${resp.body.size}")
    if (resp.body.size > 0) {
        let n = if (resp.body.size > 400) { 400 } else { resp.body.size }
        println(String.fromUtf8(sliceBytes(resp.body, 0, n)))
    }
    c.conn.closeConnection("done")
    return if (resp.status == 200) { 0 } else { 2 }
}
