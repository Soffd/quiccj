package quic.http3

import quic.tls.TlsOptions
import quic.crypto.*
import quic.transport.*
import std.collection.*

/*
 * HTTP/3 (RFC 9114) client with QPACK (RFC 9204).
 * The encoder uses the peer's SETTINGS to bound potentially blocked sections.
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
    "accept-language", "", "access-control-allow-credentials", "FALSE",
    "access-control-allow-credentials", "TRUE", "access-control-allow-headers", "*", "access-control-allow-methods", "get",
    "access-control-allow-methods", "get, post, options", "access-control-allow-methods", "options", "access-control-expose-headers", "content-length",
    "access-control-request-headers", "content-type", "access-control-request-method", "get", "access-control-request-method", "post",
    "alt-svc", "clear", "authorization", "", "content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'",
    "early-data", "1", "expect-ct", "", "forwarded", "",
    "if-range", "", "origin", "", "purpose", "prefetch",
    "server", "", "timing-allow-origin", "*", "upgrade-insecure-requests", "1",
    "user-agent", "", "x-forwarded-for", "", "x-frame-options", "deny",
    "x-frame-options", "sameorigin",
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
    return encodeFields(headers, 0, "")
}

func encodeFields(headers: Array<H3Header>, encodedInsertCount: Int64, authority: String): Array<UInt8> {
    let w = ByteWriter(256)
    putPrefixed(w, 0, 8, encodedInsertCount)
    w.putU8(0)
    var i = 0
    while (i < headers.size) {
        let name = headers[i].name
        let value = headers[i].value
        let idx = staticIndex(name, value)
        if (encodedInsertCount != 0 && name == ":authority" && value == authority) {
            putPrefixed(w, 0x80, 6, 0)
        } else if (idx >= 0) {
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
func putPrefixed(w: ByteWriter, pattern: UInt8, prefixBits: Int64, value: Int64): Unit {
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
func readPrefixed(r: ByteReader, first: UInt8, prefixBits: Int64): Int64 {
    let max = (1 << prefixBits) - 1
    var v = Int64(first & UInt8(max))
    if (v < max) {
        return v
    }
    var shift = 0
    while (true) {
        let b = r.readU8()
        let chunk = Int64(b & 0x7f)
        if (shift >= 63 || chunk > ((0x3fff_ffff_ffff_ffff - v) >> shift)) {
            throw Exception("QPACK integer overflow")
        }
        v += chunk << shift
        shift += 7
        if ((b & 0x80) == 0) {
            break
        }
    }
    return v
}

/** Decode one QPACK field section with externally supplied entries in insertion order. */
public func qpackDecode(block: Array<UInt8>, dyn: Array<H3Header>, dynCount: Int64): Array<H3Header> {
    return decodeFields(block, dyn.size, dynCount, { index =>
        if (index < 0 || index >= dynCount || index >= dyn.size) {
            throw Exception("QPACK dynamic entry unavailable")
        }
        dyn[index]
    })[0]
}

func staticHeader(index: Int64): H3Header {
    if (index < 0 || index >= QPACK_STATIC.size / 2) {
        throw Exception("QPACK static index out of range")
    }
    let field = H3Header()
    field.name = QPACK_STATIC[2 * index]
    field.value = QPACK_STATIC[2 * index + 1]
    return field
}

func decodeFields(block: Array<UInt8>, maxEntries: Int64, inserts: Int64,
    lookup: (Int64) -> H3Header): (Array<H3Header>, Int64) {
    let r = ByteReader(block)
    let encoded = readPrefixed(r, r.readU8(), 8)
    var required = 0
    if (encoded != 0) {
        let range = 2 * maxEntries
        if (encoded > range) {
            throw Exception("invalid QPACK required insert count")
        }
        let maxValue = inserts + maxEntries
        required = (maxValue / range) * range + encoded - 1
        if (required > maxValue) {
            required -= range
        }
        if (required <= 0 || required > inserts) {
            throw Exception("unavailable QPACK insert count")
        }
    }
    let deltaField = r.readU8()
    let delta = readPrefixed(r, deltaField, 7)
    let base = if ((deltaField & 0x80) != 0) { required - delta - 1 } else { required + delta }
    if (base < 0) {
        throw Exception("invalid QPACK base")
    }
    let requiredCount = required
    let dynamic = { index: Int64 =>
        if (index < 0 || index >= requiredCount) {
            throw Exception("QPACK index exceeds required insert count")
        }
        lookup(index)
    }
    let out = ArrayList<H3Header>()
    while (!r.eof()) {
        let first = r.readU8()
        let field = H3Header()
        if ((first & 0x80) != 0) {
            let index = readPrefixed(r, first, 6)
            let entry = if ((first & 0x40) != 0) { staticHeader(index) } else {
                dynamic(base - index - 1)
            }
            field.name = entry.name
            field.value = entry.value
        } else if ((first & 0x40) != 0) {
            let index = readPrefixed(r, first, 4)
            let entry = if ((first & 0x10) != 0) { staticHeader(index) } else {
                dynamic(base - index - 1)
            }
            field.name = entry.name
            field.value = decodeString(r)
        } else if ((first & 0x20) != 0) {
            let length = readPrefixed(r, first, 3)
            field.name = decodeText(r.readBytes(length), (first & 0x08) != 0)
            field.value = decodeString(r)
        } else if ((first & 0x10) != 0) {
            let entry = dynamic(base + readPrefixed(r, first, 4))
            field.name = entry.name
            field.value = entry.value
        } else {
            field.name = dynamic(base + readPrefixed(r, first, 3)).name
            field.value = decodeString(r)
        }
        if (field.name == "") {
            throw Exception("empty QPACK field name")
        }
        out.add(field)
    }
    return (out.toArray(), required)
}

func decodeString(r: ByteReader): String {
    let h = r.readU8()
    let length = readPrefixed(r, h, 7)
    return decodeText(r.readBytes(length), (h & 0x80) != 0)
}

func decodeText(raw: Array<UInt8>, huffman: Bool): String {
    return String.fromUtf8(if (huffman) { huffmanDecode(raw) } else { raw })
}

private class HuffmanNode {
    var symbol: Int64 = -1
    let child = Array<Int64>(2, repeat: -1)
}

private func huffmanTree(): Array<HuffmanNode> {
    let nodes = ArrayList<HuffmanNode>()
    nodes.add(HuffmanNode())
    for (symbol in 0..HUFF_LENS.size) {
        let code = HUFF_CODES[symbol]
        var bit = Int64(HUFF_LENS[symbol]) - 1
        var node = 0
        while (bit >= 0) {
            let branch = (code >> bit) & 1
            if (nodes[node].child[branch] < 0) {
                nodes[node].child[branch] = nodes.size
                nodes.add(HuffmanNode())
            }
            node = nodes[node].child[branch]
            bit--
        }
        nodes[node].symbol = symbol
    }
    return nodes.toArray()
}

private let HUFFMAN = huffmanTree()

/** RFC 7541 Appendix B, including EOS and padding validation. */
public func huffmanDecode(data: Array<UInt8>): Array<UInt8> {
    let out = ByteWriter(data.size + 8)
    var node = 0
    var pending = 0
    var ones = true
    for (byte in data) {
        var shift = 7
        while (shift >= 0) {
            let bit = Int64((byte >> shift) & 1)
            node = HUFFMAN[node].child[bit]
            pending++
            ones = ones && bit == 1
            if (node < 0 || HUFFMAN[node].symbol == 256) {
                throw Exception("invalid QPACK Huffman code")
            }
            if (HUFFMAN[node].symbol >= 0) {
                out.putU8(UInt8(HUFFMAN[node].symbol))
                node = 0
                pending = 0
                ones = true
            }
            shift--
        }
    }
    if (pending > 7 || !ones) {
        throw Exception("invalid QPACK Huffman padding")
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

    public let ftype: Int64
    public let payload: Array<UInt8>

    public init(ftype: Int64, payload: Array<UInt8>) {
        this.ftype = ftype
        this.payload = payload
    }

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
    /** The peer's GOAWAY excludes this request. It can be retried on a new connection. */
    public var rejected: Bool = false
}

public class Http3Push {
    public let id: Int64
    public var promisedHeaders: Array<H3Header> = []
    let reader = ResponseReader()

    init(id: Int64) {
        this.id = id
    }

    public prop response: HttpResponse {
        get() { reader.response }
    }
}

class ResponseReader {
    let response = HttpResponse()
    let body = ByteWriter(4096)
    var offset: Int64 = 0
    var lastSize: Int64 = -1
    var trailersSeen = false
    var sink: Option<(Array<UInt8>) -> Unit> = None
    var dataRemaining: Int64 = 0
    var metadataBytes: Int64 = 0
}

private class PeerStream {
    var typeId: Int64 = -1
    var offset: Int64 = 0
    var lastSize: Int64 = -1
    var pushId: Int64 = -1
}

public class Http3Client {
    public let host: String
    public let conn: QuicConnection
    private var controlStream: QuicStream
    private var encoderStream: QuicStream
    private var decoderStream: QuicStream
    private let qpack = QpackDecoder()
    private let peerStreams = HashMap<Int64, PeerStream>()
    private let pushes = HashMap<Int64, Http3Push>()
    private let outstandingSections = HashMap<Int64, Bool>()
    private var controlId: Int64 = -1
    private var encoderId: Int64 = -1
    private var decoderId: Int64 = -1
    private var settingsSent = false
    private var settingsRead = false
    private var maxPushId: Int64 = -1
    private var authorityInserted = false
    private var authorityAcknowledged = false
    private var peerBlockedStreams: Int64 = 0

    public prop qpackKnownReceivedCount: Int64 {
        get() { if (authorityAcknowledged) { 1 } else { 0 } }
    }
    private let originPort: UInt16
    private let responseTimeoutMs: Int64
    private let maxResponseBytes: Int64
    public var goawayId: Option<Int64> = None

    public init(conn: QuicConnection, maxResponseBytes!: Int64 = 16777216, responseTimeoutMs!: Int64 = 15000,
        originPort!: UInt16 = conn.port) {
        this.originPort = originPort
        if (responseTimeoutMs <= 0) { throw Exception("HTTP/3 response timeout must be positive") }
        this.responseTimeoutMs = responseTimeoutMs
        if (maxResponseBytes < 1) {
            throw Exception("HTTP/3 response limit must be positive")
        }
        this.maxResponseBytes = maxResponseBytes
        this.conn = conn
        this.host = conn.host
        controlStream = QuicStream()
        encoderStream = QuicStream()
        decoderStream = QuicStream()
    }

    public static func connect(host: String, port: UInt16, store: TrustStore,
        verifyPeer: Bool, timeoutMs: Int64, backend!: CryptoBackend = NativeCryptoBackend(),
        tlsOptions!: TlsOptions = TlsOptions(), config!: QuicConfig = QuicConfig(),
        responseTimeoutMs!: Int64 = 15000): Option<Http3Client> {
        let connected = QuicConnection.connect(host, port, store, verifyPeer, timeoutMs: timeoutMs,
            backend: backend, config: config, tlsOptions: tlsOptions)
        if (connected.isNone()) { return None }
        let conn = connected.getOrThrow()
        let client = Http3Client(conn, responseTimeoutMs: responseTimeoutMs)
        client.openControlStreams()
        return Some(client)
    }

    public func openControlStreams(): Unit {
        if (settingsSent) {
            return
        }
        controlStream = conn.openUniStream()
        encoderStream = conn.openUniStream()
        decoderStream = conn.openUniStream()
        let settings = ByteWriter(16)
        Varint.write(settings, 1) // QPACK_MAX_TABLE_CAPACITY
        Varint.write(settings, UInt64(DECODER_CAPACITY))
        writeStream(controlStream, concat([0], H3Frame.encode(H3Frame.SETTINGS, settings.toArray())), false)
        writeStream(encoderStream, [2], false)
        writeStream(decoderStream, [3], false)
        settingsSent = true
    }

    private func writeStream(stream: QuicStream, data: Array<UInt8>, fin: Bool): Unit {
        if (conn.established) {
            conn.sendStream(stream, data, fin)
        } else {
            conn.sendEarlyStream(stream, data, fin)
        }
    }

    /** Send an explicitly replay-safe GET, using 0-RTT when the session allows it. */
    public func getEarly(path: String, handshakeTimeoutMs!: Int64 = 8000): HttpResponse {
        if (!conn.canSendEarlyData && !conn.handshake(handshakeTimeoutMs)) {
            return HttpResponse()
        }
        let request = sendRequest(path, None)
        if (!conn.handshake(handshakeTimeoutMs)) {
            return HttpResponse()
        }
        return waitResponse(request)
    }

    /** Deliver DATA incrementally. The returned response contains the status and headers. */
    public func getStreaming(path: String, onData: (Array<UInt8>) -> Unit): HttpResponse {
        return request(path, Some(onData))
    }

    public func get(path: String): HttpResponse { return request(path, None) }

    /** Send a request body after the authenticated handshake. */
    public func post(path: String, body: Array<UInt8>): HttpResponse {
        if (!conn.established) { throw Exception("POST requires an established connection") }
        return request(path, None, body: Some(body))
    }

    private func request(path: String, sink: Option<(Array<UInt8>) -> Unit>,
        body!: Option<Array<UInt8>> = None): HttpResponse {
        openControlStreams()
        if (goawayId.isSome()) {
            let rejected = HttpResponse()
            rejected.rejected = true
            return rejected
        }
        return waitResponse(sendRequest(path, body), sink: sink)
    }

    private func sendRequest(path: String, body: Option<Array<UInt8>>): QuicStream {
        openControlStreams()
        let req = conn.openBidiStream()
        let headers = Array<H3Header>(8, repeat: H3Header())
        let h1 = H3Header()
        h1.name = ":method"
        h1.value = if (body.isSome()) { "POST" } else { "GET" }
        headers[0] = h1
        let h2 = H3Header()
        h2.name = ":scheme"
        h2.value = "https"
        headers[1] = h2
        let h3 = H3Header()
        h3.name = ":authority"
        h3.value = authority()
        headers[2] = h3
        let h4 = H3Header()
        h4.name = ":path"
        h4.value = path
        headers[3] = h4
        let block = if (authorityInserted &&
            (authorityAcknowledged || outstandingSections.size < peerBlockedStreams)) {
            outstandingSections.add(req.id, true)
            // One insertion at absolute index 0: encoded count 2, base 1.
            encodeFields(headers[0..4], 2, authority())
        } else {
            qpackEncode(headers[0..4])
        }
        let frame = H3Frame.encode(H3Frame.HEADERS, block)
        writeStream(req, frame, body.isNone())
        if (let Some(payload) <- body) {
            let header = ByteWriter(9)
            Varint.write(header, UInt64(H3Frame.DATA))
            Varint.write(header, UInt64(payload.size))
            writeStream(req, header.toArray(), false)
            writeStream(req, payload, true)
        }
        return req
    }

    private func authority(): String {
        let name = if (host.contains(":")) { "[" + host + "]" } else { host }
        return if (originPort == 443) { name } else { "${name}:${originPort}" }
    }

    /** RFC 9218 request priority update on the client control stream. */
    public func updatePriority(requestId: Int64, urgency: UInt8, incremental!: Bool = false): Unit {
        if (requestId < 0 || (requestId & 3) != 0 || urgency > 7) { throw Exception("invalid HTTP priority") }
        openControlStreams()
        let value = ByteWriter()
        Varint.write(value, UInt64(requestId))
        value.putBytes(("u=" + urgency.toString() + if (incremental) { ", i" } else { "" }).toArray())
        writeStream(controlStream, H3Frame.encode(0xf0700, value.toArray()), false)
    }

    /** Permit push IDs up to and including the given ID. Push is opt-in. */
    public func allowPush(maxId: Int64): Unit {
        if (maxId < 0 || maxId > 15 || maxId < maxPushId) {
            throw Exception("push ID must be nondecreasing and in 0..15")
        }
        openControlStreams()
        maxPushId = maxId
        let id = ByteWriter(8)
        Varint.write(id, UInt64(maxId))
        conn.sendStream(controlStream, H3Frame.encode(H3Frame.MAX_PUSH_ID, id.toArray()), false)
    }

    public func getPush(id: Int64): Option<Http3Push> {
        let push = pushes.get(id)
        if (let Some(value) <- push) {
            if (value.promisedHeaders.size > 0) {
                return push
            }
        }
        return None
    }

    public func pollOnce(): Bool {
        let received = conn.pollOnce()
        if (conn.closed) {
            return received
        }
        try {
            for (stream in conn.peerUniStreams()) {
                processPeerStream(stream)
            }
        } catch (e: Exception) {
            fail(0x101, e.message)
        }
        return received
    }

    private func processPeerStream(stream: QuicStream): Unit {
        let state = if (let Some(existing) <- peerStreams.get(stream.id)) { existing } else {
            let created = PeerStream()
            peerStreams.add(stream.id, created)
            created
        }
        if (state.pushId >= 0 && pushFor(state.pushId).response.complete) {
            return
        }
        if (stream.receiveReset.isSome() && (state.typeId == 0 || state.typeId == 2 || state.typeId == 3)) {
            fail(0x104, "HTTP/3 critical stream reset")
            return
        }
        if (state.lastSize == stream.recvBuf.size && !stream.recvFin) {
            return
        }
        if (stream.recvBuf.size > maxResponseBytes) {
            throw Exception("HTTP/3 unidirectional stream limit exceeded")
        }
        state.lastSize = stream.recvBuf.size
        let r = stream.recvBuf.reader(offset: state.offset)
        if (state.typeId < 0) {
            if (!hasVarint(r)) {
                return
            }
            state.typeId = Int64(Varint.read(r))
            state.offset = r.pos
            match (state.typeId) {
                case 0 =>
                    if (controlId >= 0) { throw Exception("duplicate control stream") }
                    controlId = stream.id
                case 2 =>
                    if (encoderId >= 0) { throw Exception("duplicate QPACK encoder stream") }
                    encoderId = stream.id
                case 3 =>
                    if (decoderId >= 0) { throw Exception("duplicate QPACK decoder stream") }
                    decoderId = stream.id
                case _ => ()
            }
        }
        match (state.typeId) {
            case 0 =>
                while (!r.eof()) {
                    if (let Some(frame) <- readFrame(r)) {
                        onControl(frame)
                        state.offset = r.pos
                    } else {
                        break
                    }
                }
            case 1 =>
                if (state.pushId < 0) {
                    if (!hasVarint(r)) { return }
                    state.pushId = Int64(Varint.read(r))
                    let push = pushFor(state.pushId)
                    if (push.reader.offset != 0) { throw Exception("duplicate push stream") }
                    push.reader.offset = r.pos
                }
                readResponse(stream, pushFor(state.pushId).reader, false)
            case 2 =>
                let previous = qpack.inserts
                while (!r.eof()) {
                    try {
                        qpack.instruction(r)
                        state.offset = r.pos
                    } catch (e: Exception) {
                        if (e.message != "buffer underflow") { throw e }
                        break
                    }
                }
                if (qpack.inserts > previous) {
                    let increment = ByteWriter(8)
                    putPrefixed(increment, 0, 6, qpack.inserts - previous)
                    conn.sendStream(decoderStream, increment.toArray(), false)
                }
            case 3 =>
                while (!r.eof()) {
                    try {
                        onDecoderInstruction(r)
                        state.offset = r.pos
                    } catch (e: Exception) {
                        if (e.message != "buffer underflow") { throw e }
                        break
                    }
                }
            case _ => state.offset = r.end
        }
        if (stream.recvFin && (state.typeId == 0 || state.typeId == 2 || state.typeId == 3)) {
            fail(0x104, "HTTP/3 critical stream closed")
        } else if (!conn.closed) {
            conn.extendReceiveWindow(stream, stream.recvOff)
        }
    }

    private func onControl(frame: H3Frame): Unit {
        if (!settingsRead && frame.ftype != H3Frame.SETTINGS) {
            throw Exception("first HTTP/3 control frame must be SETTINGS")
        }
        let r = ByteReader(frame.payload)
        match (frame.ftype) {
            case 0x04 => // SETTINGS
                if (settingsRead) { throw Exception("duplicate HTTP/3 SETTINGS") }
                let seen = HashMap<UInt64, Bool>()
                var remoteCapacity: Int64 = 0
                while (!r.eof()) {
                    let id = Varint.read(r)
                    let value = Varint.read(r)
                    if (seen.contains(id) || (id >= 2 && id <= 5)) {
                        throw Exception("invalid HTTP/3 setting")
                    }
                    seen.add(id, true)
                    if (id == 1) { remoteCapacity = Int64(value) }
                    if (id == 7) { peerBlockedStreams = Int64(value) }
                }
                settingsRead = true
                insertAuthority(remoteCapacity)
            case 0x07 => // GOAWAY
                let id = Int64(Varint.read(r))
                if (!r.eof() || id % 4 != 0 || id > goawayId.getOrDefault({ => Int64.Max })) {
                    fail(0x108, "invalid HTTP/3 GOAWAY stream ID")
                } else {
                    goawayId = Some(id)
                }
            case 0x03 => // CANCEL_PUSH
                let id = Int64(Varint.read(r))
                if (!r.eof() || id > maxPushId) {
                    fail(0x108, "invalid CANCEL_PUSH ID")
                } else {
                    pushes.remove(id)
                }
            case 0x00 | 0x01 | 0x05 | 0x0d =>
                fail(0x105, "frame forbidden on server control stream")
            case _ => ()
        }
    }

    private func insertAuthority(remoteCapacity: Int64): Unit {
        let value = authority().toArray()
        let capacity = 42 + value.size
        if (remoteCapacity < capacity) { return }
        let w = ByteWriter(value.size + 16)
        putPrefixed(w, 0x20, 5, capacity)
        putPrefixed(w, 0xc0, 6, 0) // Insert With Name Reference, static :authority.
        putPrefixed(w, 0, 7, value.size)
        w.putBytes(value)
        authorityInserted = true
        conn.sendStream(encoderStream, w.toArray(), false)
    }

    private func onDecoderInstruction(r: ByteReader): Unit {
        let first = r.readU8()
        if ((first & 0x80) != 0) {
            let id = readPrefixed(r, first, 7)
            if (!outstandingSections.contains(id)) {
                throw Exception("unexpected QPACK section acknowledgment")
            }
            outstandingSections.remove(id)
            authorityAcknowledged = true
        } else if ((first & 0x40) != 0) {
            outstandingSections.remove(readPrefixed(r, first, 6))
        } else {
            let increment = readPrefixed(r, first, 6)
            if (increment != 1 || !authorityInserted || authorityAcknowledged) {
                throw Exception("invalid QPACK insert count increment")
            }
            authorityAcknowledged = true
        }
    }

    private func pushFor(id: Int64): Http3Push {
        if (id < 0 || id > maxPushId) {
            throw Exception("push ID exceeds the advertised maximum")
        }
        if (let Some(push) <- pushes.get(id)) {
            return push
        }
        let push = Http3Push(id)
        pushes.add(id, push)
        return push
    }

    private func fail(code: UInt64, message: String): Unit {
        conn.lastError = message
        conn.closeApplication(code, message)
    }

    private func waitResponse(req: QuicStream, sink!: Option<(Array<UInt8>) -> Unit> = None): HttpResponse {
        let reader = ResponseReader()
        reader.sink = sink
        let deadline = nowMillis() + responseTimeoutMs
        while (!conn.closed && nowMillis() < deadline) {
            pollOnce()
            if (let Some(code) <- req.receiveReset) {
                reader.response.rejected = code == 0x10b // H3_REQUEST_REJECTED
                conn.lastError = "HTTP/3 request stream reset"
                break
            }
            if (req.id >= goawayId.getOrDefault({ => Int64.Max })) {
                reader.response.rejected = true
                break
            }
            try {
                readResponse(req, reader, true)
            } catch (e: Exception) {
                fail(0x10e, e.message)
            }
            if (reader.response.complete) {
                conn.releaseStream(req.id)
                break
            }
        }
        if (!reader.response.complete && !conn.closed && nowMillis() >= deadline) {
            conn.lastError = "HTTP/3 response timeout"
        }
        if (!reader.response.complete) {
            reader.response.body = reader.body.toArray()
        }
        return reader.response
    }

    private func readResponse(stream: QuicStream, reader: ResponseReader, allowPromise: Bool): Unit {
        if (reader.response.complete || stream.receiveReset.isSome() ||
            (reader.lastSize == stream.recvBuf.size && !stream.recvFin)) {
            return
        }
        if (let Some(sink) <- reader.sink) {
            readStreamingResponse(stream, reader, sink)
            return
        }
        if (stream.recvBuf.size > maxResponseBytes) {
            throw Exception("HTTP/3 response limit exceeded")
        }
        reader.lastSize = stream.recvBuf.size
        let input = stream.recvBuf.reader(offset: reader.offset)
        while (!input.eof()) {
            if (let Some(frame) <- readFrame(input)) {
                handleResponseFrame(reader, stream.id, frame, allowPromise)
                reader.offset = input.pos
            } else {
                break
            }
        }
        conn.extendReceiveWindow(stream, stream.recvOff)
        if (stream.recvFin) {
            if (reader.offset != input.end || reader.response.status < 200) {
                throw Exception("incomplete HTTP/3 response")
            }
            reader.response.body = reader.body.toArray()
            reader.response.complete = true
            stream.recvBuf = ByteWriter(1)
        }
    }

    private func readStreamingResponse(stream: QuicStream, reader: ResponseReader,
        sink: (Array<UInt8>) -> Unit): Unit {
        let input = stream.recvBuf.reader()
        while (!input.eof()) {
            if (reader.dataRemaining > 0) {
                let size = if (input.remaining() < reader.dataRemaining) { input.remaining() } else { reader.dataRemaining }
                sink(input.readBytes(size))
                reader.dataRemaining -= size
                continue
            }
            let start = input.pos
            if (!hasVarint(input)) { break }
            let kind = Int64(Varint.read(input))
            if (!hasVarint(input)) { input.pos = start; break }
            let size = Int64(Varint.read(input))
            if (kind == H3Frame.DATA) {
                if (reader.response.status < 200 || reader.trailersSeen) { throw Exception("unexpected HTTP/3 DATA") }
                reader.dataRemaining = size
            } else {
                if (size > maxResponseBytes - reader.metadataBytes) { throw Exception("HTTP/3 metadata limit exceeded") }
                if (size > input.remaining()) { input.pos = start; break }
                handleResponseFrame(reader, stream.id, H3Frame(kind, input.readBytes(size)), true)
                reader.metadataBytes += input.pos - start
            }
        }
        if (input.pos > 0) {
            let remaining = input.readBytes(input.remaining())
            stream.recvBuf.clear()
            stream.recvBuf.putBytes(remaining)
        }
        reader.lastSize = stream.recvBuf.size
        conn.extendReceiveWindow(stream, stream.recvOff)
        if (stream.recvFin) {
            if (reader.dataRemaining != 0 || stream.recvBuf.size != 0 || reader.response.status < 200) {
                throw Exception("incomplete HTTP/3 response")
            }
            reader.response.complete = true
        }
    }

    private func decodeSection(payload: Array<UInt8>, sid: Int64): Array<H3Header> {
        let (headers, required) = qpack.fields(payload)
        if (required != 0 && !conn.closed) {
            let ack = ByteWriter(8)
            putPrefixed(ack, 0x80, 7, sid)
            conn.sendStream(decoderStream, ack.toArray(), false)
        }
        return headers
    }

    private func handleResponseFrame(reader: ResponseReader, sid: Int64, frame: H3Frame,
        allowPromise: Bool): Unit {
        let resp = reader.response
        if (frame.ftype == H3Frame.HEADERS) {
            let headers = decodeSection(frame.payload, sid)
            var status: Int64 = 0
            for (header in headers) {
                if (header.name == ":status") {
                    if (status != 0 || header.value.toArray().size != 3) {
                        throw Exception("invalid HTTP/3 status")
                    }
                    status = parseInt(header.value)
                }
            }
            if (reader.trailersSeen || (resp.status >= 200 && status != 0) ||
                (resp.status < 200 && status < 100)) {
                throw Exception("unexpected HTTP/3 HEADERS")
            }
            reader.trailersSeen = resp.status >= 200
            if (status != 0) {
                resp.status = status
            }
            if (resp.status >= 200) {
                let combined = Array<H3Header>(resp.headerCount + headers.size, repeat: H3Header())
                for (i in 0..resp.headerCount) {
                    combined[i] = resp.headers[i]
                }
                for (i in 0..headers.size) {
                    combined[resp.headerCount + i] = headers[i]
                }
                resp.headers = combined
                resp.headerCount = combined.size
            }
        } else if (frame.ftype == H3Frame.DATA && resp.status >= 200 && !reader.trailersSeen) {
            reader.body.putBytes(frame.payload)
        } else if (frame.ftype == H3Frame.PUSH_PROMISE && allowPromise) {
            let input = ByteReader(frame.payload)
            let push = pushFor(Int64(Varint.read(input)))
            let fields = decodeSection(input.readBytes(input.remaining()), sid)
            if (push.promisedHeaders.size > 0) {
                if (push.promisedHeaders.size != fields.size) {
                    throw Exception("inconsistent push promise")
                }
                for (i in 0..fields.size) {
                    if (push.promisedHeaders[i].name != fields[i].name ||
                        push.promisedHeaders[i].value != fields[i].value) {
                        throw Exception("inconsistent push promise")
                    }
                }
            } else {
                push.promisedHeaders = fields
            }
        } else if (frame.ftype == H3Frame.DATA || frame.ftype == H3Frame.GOAWAY ||
            frame.ftype == H3Frame.SETTINGS || frame.ftype == H3Frame.PUSH_PROMISE ||
            frame.ftype == H3Frame.CANCEL_PUSH || frame.ftype == H3Frame.MAX_PUSH_ID) {
            throw Exception("unexpected HTTP/3 response frame")
        }
    }

    private func parseInt(s: String): Int64 {
        var v: Int64 = 0
        let b = s.toArray()
        var i = 0
        while (i < b.size) {
            if (b[i] < 48 || b[i] > 57) {
                throw Exception("invalid HTTP/3 status")
            }
            v = v * 10 + Int64(b[i] - 48)
            i++
        }
        return v
    }
}

func readFrame(reader: ByteReader): Option<H3Frame> {
    let start = reader.pos
    if (!hasVarint(reader)) {
        return None
    }
    let kind = Int64(Varint.read(reader))
    if (!hasVarint(reader)) {
        reader.pos = start
        return None
    }
    let length = Int64(Varint.read(reader))
    if (length > reader.remaining()) {
        reader.pos = start
        return None
    }
    return Some(H3Frame(kind, reader.readBytes(length)))
}

func hasVarint(reader: ByteReader): Bool {
    return !reader.eof() && reader.remaining() >= (1 << (reader.data[reader.pos] >> 6))
}
