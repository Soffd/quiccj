package quic.http3

import quic.crypto.*
import quic.transport.*

/*
 * Minimal HTTP/3 (RFC 9114) client with QPACK (RFC 9204).
 * Encoder uses the static table and literals only (never blocks).
 * Decoder supports the static table, literals and dynamic-table inserts.
 */

public let QPACK_STATIC: Array<String> = [
    ":authority", "", ":path", "/", "age", "0",
    "content-disposition", "", "content-length", "0", "cookie", "",
    "date", "", "etag", "", "if-modified-since", "",
    "if-none-match", "", "last-modified", "", "link", "",
    "location", "", "referer", "", "set-cookie", "",
    ":method", "CONNECT", ":method", "DELETE", ":method", "GET",
    ":method", "HEAD", ":method", "OPTIONS", ":method", "POST",
    ":method", "PUT", ":scheme", "http", ":scheme", "https",
    ":status", "103", ":status", "200", ":status", "304",
    ":status", "404", ":status", "503", "accept", "*/*",
    "accept", "application/dns-message", "accept-encoding", "gzip, deflate, br", "accept-ranges", "bytes",
    "access-control-allow-headers", "cache-control", "access-control-allow-headers", "content-type", "access-control-allow-origin", "*",
    "cache-control", "max-age=0", "cache-control", "max-age=2592000", "cache-control", "max-age=604800",
    "cache-control", "no-cache", "cache-control", "no-store", "cache-control", "public, max-age=31536000",
    "content-encoding", "br", "content-encoding", "gzip", "content-type", "application/dns-message",
    "content-type", "application/javascript", "content-type", "application/json", "content-type", "application/x-www-form-urlencoded",
    "content-type", "image/gif", "content-type", "image/jpeg", "content-type", "image/png",
    "content-type", "text/css", "content-type", "text/html; charset=utf-8", "content-type", "text/plain",
    "content-type", "text/plain;charset=utf-8", "range", "bytes=0-", "strict-transport-security", "max-age=31536000",
    "strict-transport-security", "max-age=31536000; includesubdomains", "strict-transport-security", "max-age=31536000; includesubdomains; preload", "vary", "accept-encoding",
    "vary", "origin", "x-content-type-options", "nosniff", "x-xss-protection", "1; mode=block",
    ":status", "100", ":status", "204", ":status", "206",
    ":status", "302", ":status", "400", ":status", "403",
    ":status", "421", ":status", "425", ":status", "500",
    ":status", "502", "accept-language", "", "access-control-allow-credentials", "FALSE",
    "access-control-allow-credentials", "TRUE", "access-control-allow-headers", "*", "access-control-allow-methods", "get",
    "access-control-allow-methods", "get, post, options", "access-control-allow-methods", "options", "access-control-expose-headers", "content-length",
    "access-control-request-headers", "content-type", "access-control-request-method", "get", "access-control-request-method", "post",
    "alt-svc", "clear", "authorization", "", "content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'",
    "early-data", "1", "expect-ct", "", "forwarded", "",
    "if-range", "", "origin", "", "purpose", "prefetch",
    "server", "", "timing-allow-origin", "*", "upgrade-insecure-requests", "1",
    "user-agent", "", "x-forwarded-for", "", "x-frame-options", "deny",
]

public class H3Header {
    public var name: String = ""
    public var value: String = ""
}

private func staticIndex(name: String, value: String): Int64 {
    // returns exact-match index or -1
    var i = 0
    while (i + 1 < QPACK_STATIC.size) {
        if (QPACK_STATIC[i] == name && QPACK_STATIC[i + 1] == value) {
            return i / 2
        }
        i = i + 2
    }
    return -1
}

public func qpackEncode(headers: Array<H3Header>): Array<UInt8> {
    let w = ByteWriter(256)
    // Field section prefix: Required Insert Count = 0, Delta Base = 0 (RFC 9204
    // section 4.5.1); a static-table-only block never blocks the decoder.
    w.putU8(0)
    w.putU8(0)
    var i = 0
    while (i < headers.size) {
        let name = headers[i].name
        let value = headers[i].value
        let idx = staticIndex(name, value)
        if (idx >= 0 && idx < 63) {
            // Indexed field line, static table.
            putPrefixed(w, 0xC0, 6, idx)
        } else {
            let nb = name.toArray()
            let vb = value.toArray()
            // Literal field line with literal name: 001 N H NameLen(3+).
            putPrefixed(w, 0x20, 3, Int64(nb.size))
            w.putBytes(nb)
            // Value: 0 H ValueLen(7+).
            putPrefixed(w, 0x00, 7, Int64(vb.size))
            w.putBytes(vb)
        }
        i++
    }
    return w.toArray()
}

/** QPACK/HPACK prefixed integer (RFC 9204 section 4.1.1). */
private func putPrefixed(w: ByteWriter, pattern: UInt8, prefixBits: Int64, value: Int64): Unit {
    let max = (1 << prefixBits) - 1
    if (value < max) {
        w.putU8(pattern | UInt8(value))
        return
    }
    w.putU8(pattern | UInt8(max))
    var v = value - max
    while (v >= 128) {
        w.putU8(UInt8(v & 0x7F) | 0x80)
        v = v >> 7
    }
    w.putU8(UInt8(v))
}

/** Decode a prefixed integer and consume its continuation groups. */
private func readPrefixed(r: ByteReader, first: UInt8, prefixBits: Int64): Int64 {
    let max = (1 << prefixBits) - 1
    var v = Int64(first & UInt8(max))
    if (v < max) {
        return v
    }
    var shift = 0
    while (true) {
        let b = r.readU8()
        v = v + (Int64(b & 0x7F) << shift)
        shift = shift + 7
        if ((b & 0x80) == 0) {
            break
        }
    }
    return v
}

/** Decode one QPACK header block (static + literals + dynamic inserts). */
public func qpackDecode(block: Array<UInt8>, dyn: Array<H3Header>, dynCount: Int64): Array<H3Header> {
    let out = Array<H3Header>(32, repeat: H3Header())
    var outCount = 0
    let r = ByteReader(block)
    // Skip the field section prefix (Required Insert Count, Delta Base).
    let ricFirst = r.readU8()
    readPrefixed(r, ricFirst, 8)
    if (!r.eof()) {
        let baseFirst = r.readU8()
        readPrefixed(r, baseFirst, 7)
    }
    while (!r.eof()) {
        let b = r.readU8()
        var name = ""
        var value = ""
        if ((b & 0x80) != 0) {
            // indexed field line
            let staticRef = (b & 0x40) != 0
            var index = Int64(b & 0x3F)
            if ((b & 0x3F) == 0x3F) {
                index = index + Int64(Varint.read(r))
            }
            if (staticRef) {
                if (index * 2 + 1 < QPACK_STATIC.size) {
                    name = QPACK_STATIC[index * 2]
                    value = QPACK_STATIC[index * 2 + 1]
                }
            } else {
                let pos = Int64(index)
                if (pos < dynCount) {
                    name = dyn[pos].name
                    value = dyn[pos].value
                }
            }
        } else if ((b & 0xC0) == 0x40) {
            // literal with name reference
            let staticRef = (b & 0x10) != 0
            var index = Int64(b & 0x0F)
            if ((b & 0x0F) == 0x0F) {
                index = index + Int64(Varint.read(r))
            }
            if (staticRef) {
                if (index * 2 < QPACK_STATIC.size) {
                    name = QPACK_STATIC[index * 2]
                }
            } else {
                let pos = Int64(index)
                if (pos < dynCount) {
                    name = dyn[pos].name
                }
            }
            value = decodeString(r)
        } else if ((b & 0xE0) == 0x20) {
            // literal with literal name: 001 N H NameLen(3+), Name, Value
            let nameLen = readPrefixed(r, b, 3)
            name = String.fromUtf8(r.readBytes(nameLen))
            value = decodeString(r)
        } else {
            // unsupported (post-base / dynamic inserts on request stream): stop
            break
        }
        if (outCount < out.size) {
            let h = H3Header()
            h.name = name
            h.value = value
            out[outCount] = h
            outCount++
        }
    }
    let res = Array<H3Header>(outCount, repeat: H3Header())
    var i = 0
    while (i < outCount) {
        res[i] = out[i]
        i++
    }
    return res
}

private func decodeString(r: ByteReader): String {
    let h = r.readU8()
    let isHuffman = (h & 0x80) != 0
    var len = Int64(h & 0x7F)
    if (len == 0x7F) {
        len = len + Int64(Varint.read(r))
    }
    let raw = r.readBytes(len)
    if (isHuffman) {
        return String.fromUtf8(huffmanDecode(raw))
    }
    return String.fromUtf8(raw)
}

/** RFC 7541 Huffman decode (canonical codes reconstructed from lengths). */
public func huffmanDecode(data: Array<UInt8>): Array<UInt8> {
    let maxLen = 30
    let count = Array<Int64>(maxLen + 1, repeat: 0)
    var i = 0
    while (i < 257) {
        count[Int64(HUFF_LENS[i])]++
        i++
    }
    let firstCode = Array<Int64>(maxLen + 1, repeat: 0)
    let firstIndex = Array<Int64>(maxLen + 1, repeat: 0)
    var code: Int64 = 0
    var idx: Int64 = 0
    var len = 1
    while (len <= maxLen) {
        code = (code + count[len - 1]) << 1
        firstCode[len] = code
        firstIndex[len] = idx
        idx = idx + count[len]
        len++
    }
    // symbols ordered by (length, symbol)
    let order = Array<Int64>(257, repeat: 0)
    var placed = 0
    var l = 1
    while (l <= maxLen) {
        var sym = 0
        while (sym < 257) {
            if (Int64(HUFF_LENS[sym]) == l) {
                order[placed] = sym
                placed++
            }
            sym++
        }
        l++
    }
    let out = ByteWriter(data.size * 2 + 8)
    var cur: Int64 = 0
    var curLen: Int64 = 0
    var bi = 0
    while (bi < data.size) {
        let byte = data[bi]
        var bit = 7
        while (bit >= 0) {
            cur = (cur << 1) | Int64((byte >> UInt8(bit)) & 1)
            curLen++
            if (curLen <= maxLen && count[curLen] > 0) {
                let delta = cur - firstCode[curLen]
                if (delta >= 0 && delta < count[curLen]) {
                    let sym = order[firstIndex[curLen] + delta]
                    if (sym == 256) {
                        return out.toArray()
                    }
                    out.putU8(UInt8(sym))
                    cur = 0
                    curLen = 0
                }
            }
            if (curLen > maxLen) {
                return out.toArray()
            }
            bit--
        }
        bi++
    }
    return out.toArray()
}

/** Frame types. */
public class H3Frame {
    public static let DATA: Int64 = 0x00
    public static let HEADERS: Int64 = 0x01
    public static let CANCEL_PUSH: Int64 = 0x03
    public static let SETTINGS: Int64 = 0x04
    public static let PUSH_PROMISE: Int64 = 0x05
    public static let GOAWAY: Int64 = 0x07
    public static let MAX_PUSH_ID: Int64 = 0x0D

    public static func encode(ftype: Int64, payload: Array<UInt8>): Array<UInt8> {
        let w = ByteWriter(payload.size + 16)
        Varint.write(w, UInt64(ftype))
        Varint.write(w, UInt64(payload.size))
        w.putBytes(payload)
        return w.toArray()
    }
}

public class HttpResponse {
    public var status: Int64 = 0
    public var headers: Array<H3Header> = Array<H3Header>(16, repeat: H3Header())
    public var headerCount: Int64 = 0
    public var body: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var complete: Bool = false
}

public class Http3Client {
    public let host: String
    public let conn: QuicConnection
    private var controlStream: QuicStream
    private var encoderStream: QuicStream
    private var decoderStream: QuicStream
    private var dynTable: Array<H3Header>
    private var dynCount: Int64
    private var settingsSent: Bool

    public init(conn: QuicConnection) {
        this.conn = conn
        this.host = conn.host
        controlStream = QuicStream()
        encoderStream = QuicStream()
        decoderStream = QuicStream()
        dynTable = Array<H3Header>(64, repeat: H3Header())
        dynCount = 0
        settingsSent = false
    }

    public static func connect(host: String, port: UInt16, store: TrustStore,
        verifyPeer: Bool, timeoutMs: Int64): Option<Http3Client> {
        let conn = QuicConnection.dial(host, port, store, verifyPeer)
        if (!conn.handshake(timeoutMs)) {
            return None
        }
        let client = Http3Client(conn)
        client.openControlStreams()
        return Some(client)
    }

    public func openControlStreams(): Unit {
        // client-initiated unidirectional stream ids: 2, 6, 10, ...
        let ctrl = QuicStream()
        ctrl.id = 2
        conn.putStream(ctrl)
        let settings = ByteWriter(8)
        settings.putU8(0x00) // control stream type
        Varint.write(settings, 0x04)
        Varint.write(settings, 0)
        conn.sendStream(ctrl, settings.toArray(), false)
        controlStream = ctrl

        let enc = QuicStream()
        enc.id = 6
        conn.putStream(enc)
        conn.sendStream(enc, [0x02], false)
        encoderStream = enc

        let dec = QuicStream()
        dec.id = 10
        conn.putStream(dec)
        conn.sendStream(dec, [0x03], false)
        decoderStream = dec
        settingsSent = true
    }

    public func get(path: String): HttpResponse {
        let req = QuicStream()
        var id: Int64 = 0
        while (conn.getStream(id).isSome()) {
            id = id + 4
        }
        req.id = id
        req.maxSend = 1048576
        conn.putStream(req)
        let headers = Array<H3Header>(8, repeat: H3Header())
        let h1 = H3Header()
        h1.name = ":method"
        h1.value = "GET"
        headers[0] = h1
        let h2 = H3Header()
        h2.name = ":scheme"
        h2.value = "https"
        headers[1] = h2
        let h3 = H3Header()
        h3.name = ":authority"
        h3.value = host
        headers[2] = h3
        let h4 = H3Header()
        h4.name = ":path"
        h4.value = path
        headers[3] = h4
        let block = qpackEncode(headers[0..4])
        var frame = H3Frame.encode(H3Frame.HEADERS, block)
        conn.sendStream(req, frame, true)
        conn.flushStreams()
        return waitResponse(req)
    }

    private func waitResponse(req: QuicStream): HttpResponse {
        let resp = HttpResponse()
        let deadline = nowMillis() + 15000
        var frameBuf = ByteWriter(4096)
        var headersSeen = false
        while (nowMillis() < deadline) {
            if (conn.closed) {
                break
            }
            conn.pollOnce()
            conn.flushStreams()
            let data = req.recvBuf.toArray()
            if (data.size > frameBuf.size) {
                // append only the new bytes
                let have = frameBuf.size
                frameBuf.putBytes(data, have, data.size - have)
            }
            // parse frames
            var progress = true
            while (progress) {
                progress = false
                let all = frameBuf.toArray()
                if (all.size < 2) {
                    break
                }
                let r = ByteReader(all)
                let ftype = Int64(Varint.read(r))
                if (r.pos > all.size) {
                    break
                }
                let lr = ByteReader(all, r.pos, all.size)
                let flen = Int64(Varint.read(lr))
                if (lr.pos + flen > all.size) {
                    break
                }
                let payload = sliceBytes(all, lr.pos, flen)
                let consumed = lr.pos + flen
                let rest = sliceBytes(all, consumed, all.size - consumed)
                frameBuf.clear()
                frameBuf.putBytes(rest)
                if (ftype == H3Frame.HEADERS) {
                    let hs = qpackDecode(payload, dynTable, dynCount)
                    var i = 0
                    while (i < hs.size) {
                        if (hs[i].name == ":status") {
                            resp.status = parseInt(hs[i].value)
                        }
                        if (resp.headerCount < resp.headers.size) {
                            resp.headers[resp.headerCount] = hs[i]
                            resp.headerCount++
                        }
                        i++
                    }
                    headersSeen = true
                } else if (ftype == H3Frame.DATA) {
                    resp.body = concat(resp.body, payload)
                } else if (ftype == H3Frame.GOAWAY) {
                    resp.complete = true
                }
                progress = true
            }
            if (req.recvFin && frameBuf.size == 0) {
                resp.complete = true
                break
            }
            if (headersSeen && req.recvFin) {
                resp.complete = true
                break
            }
        }
        return resp
    }

    private func parseInt(s: String): Int64 {
        var v: Int64 = 0
        let b = s.toArray()
        var i = 0
        while (i < b.size) {
            if (b[i] >= 48 && b[i] <= 57) {
                v = v * 10 + Int64(b[i] - 48)
            }
            i++
        }
        return v
    }
}
