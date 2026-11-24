package quic.http3

import quic.crypto.*
import quic.transport.*
import quic.tls.*
import std.collection.HashMap
import std.convert.Parsable

private class PoolEntry {
    var client: Option<Http3Client> = None
    var alternative = ""
    var port: UInt16 = 0
    var expires: Int64 = 0
    var lastUsed: Int64 = 0
}

/** A synchronous origin-keyed pool scoped to one trust policy and client identity. */
public class Http3Pool {
    private let entries = HashMap<String, PoolEntry>()
    private let trust: TrustStore
    private let backend: CryptoBackend
    private let tlsOptions: TlsOptions
    private let config: QuicConfig
    private let capacity: Int64
    private let timeoutMs: Int64

    public init(trust: TrustStore, backend!: CryptoBackend = NativeCryptoBackend(),
        tlsOptions!: TlsOptions = TlsOptions(), config!: QuicConfig = QuicConfig(),
        capacity!: Int64 = 16, handshakeTimeoutMs!: Int64 = 8000) {
        if (capacity < 1 || handshakeTimeoutMs < 1) { throw Exception("invalid HTTP/3 pool settings") }
        this.trust = trust
        this.backend = backend
        this.tlsOptions = tlsOptions
        this.config = config
        this.capacity = capacity
        timeoutMs = handshakeTimeoutMs
    }

    private func entry(host: String, port: UInt16): PoolEntry {
        let key = "[${host}]:${port}"
        if (let Some(found) <- entries.get(key)) { found.lastUsed = nowMillis(); return found }
        if (entries.size >= capacity) {
            var oldest = Int64.Max
            var remove = ""
            for ((name, item) in entries) {
                if (item.lastUsed <= oldest) { oldest = item.lastUsed; remove = name }
            }
            closeEntry(entries.get(remove).getOrThrow())
            entries.remove(remove)
        }
        let item = PoolEntry()
        item.lastUsed = nowMillis()
        entries.add(key, item)
        return item
    }

    private func closeEntry(item: PoolEntry): Unit {
        if (let Some(client) <- item.client) { client.conn.closeConnection("pool released connection") }
        item.client = None
    }

    /** Record an Alt-Svc field obtained from a verified HTTPS response for this origin. */
    public func observeAltSvc(host: String, port: UInt16, field: String): Unit {
        let item = entry(toLowerAscii(asciiHost(host)), port)
        if (field.trimAscii() == "clear") { item.expires = 0; return }
        for (value in field.split(",")) {
            let parts = value.trimAscii().split(";")
            let service = parts[0].trimAscii()
            if (!service.startsWith("h3=\"") || !service.endsWith("\"") || service.size < 7) { continue }
            let address = service[4..service.size - 1]
            var split = address.size - 1
            while (split >= 0 && address[split] != 58u8) { split-- }
            if (split < 0 || split + 1 == address.size) { continue }
            var target = address[0..split]
            if (target.startsWith("[") && target.endsWith("]")) { target = target[1..target.size - 1] }
            var age: Int64 = 86400
            try {
                let destinationPort = UInt16.parse(address[split + 1..])
                for (part in parts[1..]) {
                    let parameter = part.trimAscii()
                    if (parameter.startsWith("ma=")) { age = Int64.parse(parameter[3..]) }
                }
                if (age < 0 || destinationPort == 0) { continue }
                if (age > 604800) { age = 604800 }
                item.alternative = if (target == "") { host } else { asciiHost(target) }
                item.port = destinationPort
                item.expires = nowMillis() + age * 1000
                return
            } catch (e: Exception) { continue }
        }
    }

    private func acquire(host: String, port: UInt16, item: PoolEntry): Option<Http3Client> {
        if (let Some(client) <- item.client) {
            if (!client.conn.closed && client.goawayId.isNone()) { return Some(client) }
            closeEntry(item)
        }
        var connected: Option<QuicConnection> = None
        if (nowMillis() < item.expires) {
            try {
                connected = QuicConnection.connect(host, item.port, trust, true, connectHost: item.alternative,
                    tlsOptions: tlsOptions, config: config, backend: backend, timeoutMs: timeoutMs)
            } catch (e: Exception) { connected = None }
            if (connected.isNone()) { item.expires = 0 }
        }
        if (connected.isNone()) {
            connected = QuicConnection.connect(host, port, trust, true, tlsOptions: tlsOptions,
                config: config, backend: backend, timeoutMs: timeoutMs)
        }
        if (let Some(conn) <- connected) {
            item.client = Some(Http3Client(conn, originPort: port))
        }
        return item.client
    }

    public func get(host: String, port: UInt16, path: String): HttpResponse {
        let name = toLowerAscii(asciiHost(host))
        let item = entry(name, port)
        for (_ in 0..2) {
            if (let Some(client) <- acquire(name, port, item)) {
                let response = client.get(path)
                if (response.complete) {
                    for (header in response.headers[0..response.headerCount]) {
                        if (header.name == "alt-svc") { observeAltSvc(name, port, header.value) }
                    }
                    return response
                }
                closeEntry(item)
                if (!response.rejected) { return response }
            } else { break }
        }
        return HttpResponse()
    }

    public func close(): Unit {
        for ((_, item) in entries) { closeEntry(item) }
        entries.clear()
    }
}
