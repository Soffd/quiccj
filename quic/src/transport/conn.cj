package quic.transport

import quic.crypto.*
import quic.tls.*
import std.net.*
import std.collection.*
import std.time.*

/*
 * QUIC v1 client connection: handshake, ACK, streams, flow control and a
 * timer-based PTO retransmission. Synchronous design: the caller polls.
 */

public class QuicStream {
    public var id: Int64 = 0
    var scheduled = false
    var earlyRegistered = false
    let outgoing = ByteWriter(1)
    public mut prop sendBuf: Array<UInt8> {
        get() { return outgoing.reader().data[0..outgoing.size] }
        set(bytes) { outgoing.clear(); outgoing.putBytes(bytes) }
    }
    public var sendOff: Int64 = 0
    public var ackedOff: Int64 = 0
    public var finSent: Bool = false
    public var finQueued: Bool = false
    public var recvBuf: ByteWriter = ByteWriter(1024)
    public var recvOff: Int64 = 0
    public var recvFin: Bool = false
    public var receiveReset: Option<UInt64> = None
    public var sendReset: Option<UInt64> = None
    public var recvFinOffset: Int64 = -1
    let receive = ReceiveRanges()
    var highestReceived: Int64 = 0
    var maxReceive: Int64 = 0
    var creditedReceive: Int64 = 0
    public var maxSend: Int64 = 262144
}

/** QUIC resumption state for a verified peer and port. */
public class QuicSession {
    public let port: UInt16
    public let version: UInt32
    let tlsTicket: TlsTicket
    let transportParams: Array<UInt8>

    public func destroy(): Unit { tlsTicket.destroy() }

    init(port: UInt16, version: UInt32, tlsTicket: TlsTicket, transportParams: Array<UInt8>) {
        this.port = port
        this.version = version
        this.tlsTicket = tlsTicket
        this.transportParams = transportParams
    }
}

private class ConnectionId {
    let id: Array<UInt8>
    let resetToken: Array<UInt8>

    init(id: Array<UInt8>, resetToken: Array<UInt8>) {
        this.id = id
        this.resetToken = resetToken
    }
}

private class PathProbe {
    let socket: QuicSocket
    let sequence: UInt64
    let connectionId: Array<UInt8>
    let challenge: Array<UInt8>
    var validated = false

    init(socket: QuicSocket, sequence: UInt64, connectionId: Array<UInt8>) {
        this.socket = socket
        this.sequence = sequence
        this.connectionId = connectionId
        challenge = randomBytes(8)
    }
}

public enum QuicCloseCause {
    | Transport(UInt64)
    | Application(UInt64)
    | IdleTimeout
    | HandshakeTimeout
    | StatelessReset
}

public class QuicConfig {
    public let parameters: TransportParams
    public let ecn: Bool
    public let ackEvery: Int64
    public let onDatagram: Option<(Array<UInt8>) -> Unit>
    public let qlog: Option<(String) -> Unit>
    public let ackRangeLimit: Int64
    public let receiveBatch: Int64
    public let keepaliveMs: Int64
    public let sendMtu: Int64
    public let log: Option<(String) -> Unit>

    public init(parameters!: TransportParams = TransportParams(), ackRangeLimit!: Int64 = 512,
        receiveBatch!: Int64 = 16, keepaliveMs!: Int64 = 0, sendMtu!: Int64 = 1200,
        log!: Option<(String) -> Unit> = None, qlog!: Option<(String) -> Unit> = None,
        ackEvery!: Int64 = 1, ecn!: Bool = true, onDatagram!: Option<(Array<UInt8>) -> Unit> = None) {
        if (ackRangeLimit < 1 || ackRangeLimit > 8192 || receiveBatch < 1 || receiveBatch > 128 ||
            keepaliveMs < 0 || sendMtu < 1200 || sendMtu > 65527) { throw Exception("invalid QUIC settings") }
        if (ackEvery < 1 || ackEvery > 2) { throw Exception("ACK interval must be one or two packets") }
        this.ecn = ecn
        this.qlog = qlog
        this.ackEvery = ackEvery
        this.onDatagram = onDatagram
        this.parameters = parameters
        this.ackRangeLimit = ackRangeLimit
        this.receiveBatch = receiveBatch
        this.keepaliveMs = keepaliveMs
        this.sendMtu = sendMtu
        this.log = log
    }
}

public class QuicConnection {
    private var cause: Option<QuicCloseCause> = None
    public prop closeCause: Option<QuicCloseCause> { get() { cause } }
    private let config: QuicConfig
    private let receiveBuffer = Array<UInt8>(65535, repeat: 0)
    private var pathMtu = 1200
    private var probeSize = 1200
    private var mtuProbe: Option<RecoveryFrame> = None
    private var nextMtuProbe: Int64 = 0
    public prop validatedMtu: Int64 { get() { pathMtu } }
    private let ecnReceived = Array<Array<UInt64>>(3, { _ => Array<UInt64>(3, repeat: 0) })
    private var inputEcn = 0
    private var ecnFailed = false
    private var ecnValidated = false
    private var ecnTrialSent = 0
    private var ecnTrialStart = 0
    private var markedSent: UInt64 = 0
    private var peerEct0: UInt64 = 0
    private var peerCe: UInt64 = 0
    public prop ecnActive: Bool { get() { socket.supportsEcn && ecnValidated && !ecnFailed } }
    public prop congestionExperienced: UInt64 { get() { peerCe } }
    private var lastKeepalive = 0
    private var pendingAck = 0
    private var ackDeadline = Int64.Max
    private var largestAppTime: Int64 = 0
    private var txCount: Int64 = 0
    public prop packetsSent: Int64 { get() { txCount } }
    private let traceStart = nowMillis()

    public prop smoothedRttMs: Int64 { get() { recovery.srtt } }
    public prop congestionWindow: Int64 { get() { recovery.window } }
    public prop bytesInFlight: Int64 { get() { recovery.bytesInFlight } }
    public prop packetsLost: Int64 { get() { recovery.packetsLost } }
    public prop streamCount: Int64 { get() { streams.size } }
    public prop streamBytesSent: Int64 { get() { sentData } }
    public prop streamBytesReceived: Int64 { get() { receivedData } }

    public let host: String
    public let port: UInt16
    var socket: QuicSocket
    let peer: IPSocketAddress

    var dcid: Array<UInt8>
    var scid: Array<UInt8>
    var peerCid: Array<UInt8>
    var originalDcid: Array<UInt8>
    var retryCid: Array<UInt8> = []
    var retryToken: Array<UInt8> = []
    var authenticatedInitial = false
    private let peerConnectionIds = HashMap<UInt64, ConnectionId>()
    private let localConnectionIds = HashMap<UInt64, Array<UInt8>>()
    private var nextLocalCid: UInt64 = 1
    private var retiredBefore: UInt64 = 0
    private var pathProbe: Option<PathProbe> = None
    private var fromProbe = false
    private var inputCid: Array<UInt8> = []
    public var version: UInt32 = QUIC_V1
    private var switchedVersion = false
    public var offeredVersions: Array<UInt32> = []

    var tls: TlsClient
    var tp: TransportParams
    var peerTp: TransportParams

    var initialClient: PacketKeys
    var initialServer: PacketKeys
    var handshakeClient: PacketKeys
    var handshakeServer: PacketKeys
    var appClient: PacketKeys
    var appServer: PacketKeys
    private var nextAppServer: Option<PacketKeys> = None
    private var previousAppServer: Option<PacketKeys> = None
    private var readPhase = false
    private var writePhase = false
    private var readPhaseStart: Int64 = -1
    private var largestInReadPhase: Int64 = -1
    private var writePhaseStart: Int64 = 0
    private var earliestWriteRotation: Int64 = 0
    private var previousKeyExpires: Int64 = 0
    private var failedAppAuthentications: Int64 = 0

    var largestRecvInitial: Int64 = -1
    var largestRecvHandshake: Int64 = -1
    var largestRecvApp: Int64 = -1
    private let received: Array<ReceivedPackets>

    let cryptoReceive = [ReceiveRanges(), ReceiveRanges(), ReceiveRanges()]
    var clientHello: Array<UInt8>
    private var initialCryptoSent: Int64 = 0
    private var started = false
    private var earlyClient: Option<PacketKeys> = None
    private let earlyStreams = ArrayList<QuicStream>()

    public prop canSendEarlyData: Bool {
        get() { !established && !closed && earlyClient.isSome() }
    }

    public prop earlyDataAccepted: Bool {
        get() { established && tls.earlyAccepted }
    }

    public prop resumed: Bool {
        get() { established && tls.resumed }
    }

    public func session(): Option<QuicSession> {
        if (let Some(ticket) <- tls.newTicket) {
            return Some(QuicSession(port, version, ticket.duplicate(), peerAppParams))
        }
        return None
    }
    private var lastActivity: Int64 = 0
    private var localBidiCount: Int64 = 0
    private var localUniCount: Int64 = 0
    private var receivedData: Int64 = 0
    private var sentData: Int64 = 0
    private let streams = HashMap<Int64, QuicStream>()
    // Retain recent final sizes for delayed duplicates without pinning application buffers.
    private let retiredIds = Array<Int64>(256, repeat: -1)
    private let retiredSizes = Array<Int64>(256, repeat: 0)
    private let sendStreams = LinkedList<QuicStream>()
    private let recovery = LossRecovery()
    private let nextPn = Array<Int64>(3, repeat: 0)

    public var established: Bool = false
    public var handshakeDone: Bool = false
    public var closed: Bool = false
    public var closeReason: String = ""
    public var lastError: String = ""
    public var rxCount: Int64 = 0
    public var peerAppParams: Array<UInt8> = Array<UInt8>(0, repeat: 0)

    private init(host: String, port: UInt16, socket: QuicSocket, peer: IPSocketAddress,
        dcid: Array<UInt8>, store: TrustStore, verifyPeer: Bool, backend: CryptoBackend,
        session: Option<QuicSession>, allowEarlyData: Bool, version: UInt32, tlsOptions: TlsOptions, config: QuicConfig) {
        this.host = host
        this.port = port
        this.socket = socket
        this.peer = peer
        this.dcid = dcid
        originalDcid = dcid
        this.version = version
        scid = randomBytes(8)
        localConnectionIds.add(0, scid)
        peerCid = Array<UInt8>(0, repeat: 0)
        this.config = config
        tp = TransportParams.decode(config.parameters.encode())
        tp.initialSourceConnectionId = scid
        tp.disableActiveMigration = true
        tp.chosenVersion = version
        tp.availableVersions = [version]
        peerTp = TransportParams()
        initialClient = PacketKeys([], [], [])
        initialServer = PacketKeys([], [], [])
        handshakeClient = PacketKeys([], [], [])
        handshakeServer = PacketKeys([], [], [])
        appClient = PacketKeys([], [], [])
        appServer = PacketKeys([], [], [])
        received = Array<ReceivedPackets>(3, { _ => ReceivedPackets(config.ackRangeLimit) })
        clientHello = []
        let ticket: Option<TlsTicket> = if (let Some(value) <- session) {
            if (value.port == port && value.version == version) { Some(value.tlsTicket) } else { Option<TlsTicket>.None }
        } else {
            None
        }
        if (let Some(write) <- config.qlog) {
            write(String.fromUtf8([30]) + #"{"qlog_version":"0.3","qlog_format":"JSON-SEQ","trace":{"vantage_point":{"type":"client"}}}"# + "\n")
        }
        tls = TlsClient(host, "h3", tp.encode(), store, verifyPeer, backend: backend, ticket: ticket,
            allowEarlyData: allowEarlyData, options: tlsOptions, labelPrefix: keyLabelPrefix(version))
    }

    public static func dial(host: String, port: UInt16, store: TrustStore,
        verifyPeer: Bool, backend!: CryptoBackend = NativeCryptoBackend(), session!: Option<QuicSession> = None,
        allowEarlyData!: Bool = false, version!: UInt32 = QUIC_V1, tlsOptions!: TlsOptions = TlsOptions(),
        config!: QuicConfig = QuicConfig()): QuicConnection {
        let normalized = asciiHost(host)
        let addresses = resolvePeers(normalized)
        return dialAddress(normalized, addresses[0], port, store, verifyPeer, backend, session,
            allowEarlyData, version, tlsOptions, config)
    }

    private static func dialAddress(host: String, ip: IPAddress, port: UInt16, store: TrustStore,
        verifyPeer: Bool, backend: CryptoBackend, session: Option<QuicSession>, allowEarlyData: Bool,
        version: UInt32, tlsOptions: TlsOptions, config: QuicConfig): QuicConnection {
        if (version != QUIC_V1 && version != QUIC_V2) { throw Exception("unsupported QUIC version") }
        let dcid = randomBytes(8)
        let peer = IPSocketAddress(ip, port)
        let bindHost = if (ip is IPv6Address) { "::" } else { "0.0.0.0" }
        let socket = QuicSocket(IPSocketAddress(bindHost, 0), peer, config)
        try {
            socket.receiveTimeout = Some(Duration.millisecond * 10)
            let conn = QuicConnection(host, port, socket, peer, dcid, store, verifyPeer, backend,
                session, allowEarlyData, version, tlsOptions, config)
            let (c, s) = PacketCrypto.initialSecrets(dcid, backend: backend, version: version)
            conn.initialClient = c
            conn.initialServer = s
            conn.clientHello = conn.tls.start()
            if (let Some(keys) <- conn.tls.earlyKeys) {
                let saved = session.getOrThrow()
                conn.peerTp = TransportParams.decode(saved.transportParams)
                conn.earlyClient = Some(conn.trafficKeys(keys, saved.tlsTicket.cipherSuite))
            }
            return conn
        } catch (e: Exception) {
            socket.close()
            throw e
        }
    }

    private static func resolvePeers(host: String): Array<IPAddress> {
        try { return [IPAddress.parse(host)] } catch (e: Exception) {
            let addresses = IPAddress.resolve(host)
            if (addresses.isEmpty()) { throw Exception("cannot resolve " + host) }
            // Preserve the resolver's first choice and try the other family second.
            for (i in 1..addresses.size) {
                if ((addresses[i] is IPv6Address) != (addresses[0] is IPv6Address)) {
                    let next = addresses[i]
                    for (j in 1..i) { addresses[i - j + 1] = addresses[i - j] }
                    addresses[1] = next
                    break
                }
            }
            return addresses
        }
    }

    /** Race complete, verified handshakes with staggered address attempts (RFC 8305). */
    public static func connect(host: String, port: UInt16, store: TrustStore, verifyPeer: Bool,
        timeoutMs!: Int64 = 8000, backend!: CryptoBackend = NativeCryptoBackend(),
        tlsOptions!: TlsOptions = TlsOptions(), config!: QuicConfig = QuicConfig(),
        connectHost!: String = ""): Option<QuicConnection> {
        let origin = asciiHost(host)
        let addresses = resolvePeers(if (connectHost == "") { origin } else { asciiHost(connectHost) })
        let active = ArrayList<QuicConnection>()
        let deadline = nowMillis() + timeoutMs
        var index = 0
        var nextStart = nowMillis()
        try {
            while (nowMillis() < deadline && (index < addresses.size || !active.isEmpty())) {
                if (index < addresses.size && (active.isEmpty() || nowMillis() >= nextStart)) {
                    let address = addresses[index]
                    index++
                    try {
                        let attempt = dialAddress(origin, address, port, store, verifyPeer, backend, None,
                            false, QUIC_V1, tlsOptions, config)
                        active.add(attempt)
                        attempt.sendClientHello()
                    } catch (e: Exception) { continue }
                    nextStart = nowMillis() + 250
                }
                var i = 0
                while (i < active.size && nowMillis() < deadline) {
                    let attempt = active[i]
                    attempt.pollOnce()
                    if (attempt.closed) { active.remove(at: i); continue }
                    if (attempt.established) { return Some(active.remove(at: i)) }
                    i++
                }
            }
            return None
        } finally {
            for (attempt in active) { attempt.terminate("address attempt abandoned") }
        }
    }

    // ------------------------------------------------------------------

    private func protectApplication(cid: Array<UInt8>, payload: Array<UInt8>): Array<UInt8> {
        let pn = nextPn[2]
        if (!appClient.chacha && pn - writePhaseStart >= 4194304) {
            if (!updateKeys() && pn - writePhaseStart >= 8388607) {
                lastError = "AEAD usage limit reached"
                terminate(lastError)
                throw Exception(lastError)
            }
        }
        nextPn[2]++
        return PacketBuilder.shortHeader(cid, pn, 4, appClient, payload, phase: writePhase)
    }

    private var wireNumbers = [SentNumbers(), SentNumbers(), SentNumbers()]
    private var nextPacedSend = Int64.Max
    private var deferredByPacer = 0

    /** Number of send attempts deferred by the pacing budget. */
    public prop pacedSendDeferrals: Int64 {
        get() { deferredByPacer }
    }

    /** Number of times the current connection detected persistent congestion. */
    public prop persistentCongestionEvents: Int64 {
        get() { recovery.persistentCongestionEvents }
    }

    private func tracePacket(direction: String, space: Int64, pn: Int64): Unit {
        if (let Some(write) <- config.qlog) {
            let kind = if (space == 0) { "initial" } else if (space == 1) { "handshake" } else if (!established) {
                "0RTT"
            } else { "1RTT" }
            let time = nowMillis() - traceStart
            write(String.fromUtf8([30]) + "{\"time\":${time},\"name\":\"transport:packet_${direction}\"," +
                "\"data\":{\"header\":{\"packet_type\":\"${kind}\",\"packet_number\":${pn}}}}\n")
        }
    }

    private func sendPacket(space: Int64, payload: Array<UInt8>, frame: Option<RecoveryFrame>,
        probe!: Bool = false): Bool {
        if (frame.isSome() && !probe) {
            let size = PacketBuilder.connectionPacketSize(space, dcid.size, scid.size, retryToken.size,
                payload.size, space == 2 && established)
            let reserve = if (space == 2 && !established) { MAX_DATAGRAM } else { 0 }
            if (recovery.bytesInFlight + size + reserve > recovery.window) {
                return false
            }
            let now = nowMicros()
            let delay = recovery.pacingDelay(now, size)
            if (delay > 0) {
                deferredByPacer++
                let deadline = now + delay
                if (deadline < nextPacedSend) {
                    nextPacedSend = deadline
                }
                return false
            }
        }
        let pn = nextPn[space]
        let packet = if (space == 2 && established) {
            protectApplication(dcid, payload)
        } else {
            nextPn[space]++
            let keys = if (space == 0) {
                initialClient
            } else if (space == 1) {
                handshakeClient
            } else {
                earlyClient.getOrThrow()
            }
            let padding = if (space == 0) { 1200 } else { 0 }
            PacketBuilder.longHeader(space, dcid, scid, retryToken, pn, 4, keys, payload, padding)
        }
        let ect = space == 2 && handshakeDone && frame.isSome() && socket.supportsEcn &&
            !ecnFailed && (ecnValidated || ecnTrialSent < 10)
        try {
            socket.sendTo(peer, packet, ect: ect)
        } catch (e: Exception) {
            if (space == 2 && packet.size > 1200) {
                pathMtu = 1200
                nextMtuProbe = nowMillis() + 60000
                return false
            }
            lastError = "send failed: ${e}"
            return false
        }
        if (ect) {
            markedSent++
            if (!ecnValidated) {
                if (ecnTrialSent == 0) { ecnTrialStart = nowMillis() }
                ecnTrialSent++
            }
        }
        txCount++
        tracePacket("sent", space, pn)
        wireNumbers[space].sent(pn)
        let time = nowMicros()
        if (let Some(sent) <- frame) {
            if (recovery.bytesInFlight == 0) {
                lastActivity = time / 1000
            }
            recovery.sent(space, pn, time / 1000, packet.size, sent, timeMicros: time, ect: ect)
        } else {
            recovery.sentNonEliciting(space, pn, time / 1000)
        }
        if (space == 1 && initialClient.key.size > 0) {
            recovery.discard(0)
            initialClient.destroy()
            initialServer.destroy()
            initialClient = PacketKeys([], [], [])
            initialServer = PacketKeys([], [], [])
        }
        return true
    }

    private func queueFrame(space: Int64, bytes: Array<UInt8>): Unit {
        recovery.spaces[space].pending.addLast(RecoveryFrame(bytes))
    }

    private func flushRecovery(): Unit {
        for (space in 0..3) {
            if (space == 2 && !established && !canSendEarlyData) {
                continue
            }
            let queue = recovery.spaces[space].pending
            while (queue.size > 0) {
                let frame = queue.first.getOrThrow()
                if (space == 2 && established && !frame.delivered && frame.bytes.size > pathMtu - 21 - dcid.size &&
                    frame.bytes.size > 0 && (frame.bytes[0] & 0xf8) == 8) {
                    // A migrated path or MTU black hole may require smaller retransmissions.
                    queue.removeFirst()
                    resegmentStream(frame.bytes)
                    continue
                }
                if (!frame.delivered && !sendPacket(space, frame.bytes, Some(frame))) {
                    return
                }
                queue.removeFirst()
            }
        }
    }

    private func resegmentStream(frame: Array<UInt8>): Unit {
        let r = ByteReader(frame)
        let kind = r.readU8()
        let stream = Varint.read(r)
        var offset = if ((kind & 4) != 0) { Varint.read(r) } else { 0u64 }
        Varint.read(r)
        while (!r.eof()) {
            let size = if (r.remaining() < pathMtu - 96) { r.remaining() } else { pathMtu - 96 }
            let w = ByteWriter()
            w.putU8(if (size == r.remaining()) { 0x0e | (kind & 1) } else { 0x0e })
            Varint.write(w, stream)
            Varint.write(w, offset)
            Varint.write(w, UInt64(size))
            w.putBytes(r.readBytes(size))
            queueFrame(2, w.toArray())
            offset += UInt64(size)
        }
    }

    private func updatePathMtu(now: Int64): Unit {
        if (!handshakeDone || config.sendMtu <= 1200) { return }
        if (recovery.largePacketLost) {
            recovery.largePacketLost = false
            pathMtu = 1200
            mtuProbe = None
            nextMtuProbe = now + 60000
        }
        if (let Some(frame) <- mtuProbe) {
            if (frame.delivered) {
                pathMtu = probeSize
                mtuProbe = None
            } else if (frame.inFlight == 0) {
                mtuProbe = None
                nextMtuProbe = now + 60000
            }
            return
        }
        let peerLimit = Int64(peerTp.maxUdpPayloadSize)
        let ceiling = if (config.sendMtu < peerLimit) { config.sendMtu } else { peerLimit }
        if (now < nextMtuProbe || pathMtu >= ceiling) { return }
        probeSize = if (pathMtu + 128 < ceiling) { pathMtu + 128 } else { ceiling }
        let bytes = Array<UInt8>(probeSize - 21 - dcid.size, repeat: 0)
        bytes[0] = 1 // PING followed by PADDING, independent of application delivery.
        let probe = RecoveryFrame(bytes, retransmittable: false, mtuProbe: true)
        if (sendPacket(2, bytes, Some(probe))) {
            mtuProbe = Some(probe)
        } else {
            if (nextMtuProbe <= now) { nextMtuProbe = now + recovery.pto(Int64(peerTp.maxAckDelay)) }
        }
    }

    private func tick(): Unit {
        let now = nowMillis()
        if (!ecnValidated && ecnTrialSent > 0 && now - ecnTrialStart >= 3 * recovery.pto(Int64(peerTp.maxAckDelay))) {
            ecnFailed = true
        }
        if (pendingAck > 0 && now >= ackDeadline) { sendAck(2) }
        if (now >= previousKeyExpires) {
            if (let Some(keys) <- previousAppServer) { keys.destroy() }
            previousAppServer = None
        }
        let peerIdle = Int64(peerTp.maxIdleTimeout)
        let localIdle = Int64(tp.maxIdleTimeout)
        let idle = if (peerIdle > 0 && (peerIdle < localIdle || localIdle == 0)) { peerIdle } else { localIdle }
        if (idle > 0 && now - lastActivity >= idle && now - lastActivity >= 3 * recovery.pto(Int64(peerTp.maxAckDelay))) {
            cause = Some(QuicCloseCause.IdleTimeout)
            terminate("idle timeout")
            return
        }
        if (established && config.keepaliveMs > 0 && now - lastActivity >= config.keepaliveMs &&
            now - lastKeepalive >= config.keepaliveMs && recovery.bytesInFlight == 0) {
            queueFrame(2, [1])
            lastKeepalive = now
        }
        for (space in 0..3) {
            recovery.detectLoss(space, now)
        }
        nextPacedSend = Int64.Max
        updatePathMtu(now)
        flushRecovery()
        flushStreamData()
        let probeSpace = recovery.probeSpace(now, handshakeDone, Int64(peerTp.maxAckDelay))
        if (probeSpace >= 0) {
            let probe = recovery.probe(probeSpace)
            if (sendPacket(probeSpace, probe.bytes, Some(probe), probe: true)) {
                recovery.probeSent()
            }
        }
    }

    public func pollOnce(): Bool {
        if (closed) {
            return false
        }
        if (nextPacedSend <= nowMicros()) {
            tick()
            if (closed) {
                return false
            }
        }
        let untilSend = nextPacedSend - nowMicros()
        let ackWait = if (pendingAck > 0) { (ackDeadline - nowMillis()) * 1000 } else { 10000 }
        let wait = if (untilSend < ackWait) { untilSend } else { ackWait }
        let timeout = if (wait <= 0) { 1 } else if (wait < 10000) { wait } else { 10000 }
        socket.receiveTimeout = Some(Duration.microsecond * timeout)
        let received = readSocket(socket, false)
        if (received && !closed && config.receiveBatch > 1) {
            socket.receiveTimeout = Some(Duration.microsecond)
            for (_ in 1..config.receiveBatch) {
                if (closed || !readSocket(socket, false)) { break }
            }
        }
        if (!closed) {
            tick()
        }
        return received
    }

    private func readSocket(source: QuicSocket, probing: Bool): Bool {
        let buf = receiveBuffer
        var received = false
        try {
            let (sender, n) = source.receiveFrom(buf)
            if (n > 0 && sender == peer) {
                received = true
                rxCount++
                fromProbe = probing
                inputEcn = source.receivedEcn
                processDatagram(buf[0..n])
            }
        } catch (e: Exception) {
            // Receive timeout also drives the recovery timers.
        }
        fromProbe = false
        return received
    }

    private func processAuthenticated(space: Int64, pkt: ParsedPacket): Unit {
        if (!pkt.validReservedBits) {
            lastError = "nonzero QUIC reserved bits"
            closeWithError(0x0a, lastError)
            return
        }
        lastActivity = nowMillis()
        let immediate = space != 2 || fromProbe || pkt.pn != largestRecvApp + 1
        if (!recordRecv(space, pkt.pn)) {
            return
        }
        if (space == 2 && pkt.pn == largestRecvApp) { largestAppTime = nowMicros() }
        if (inputEcn == 2) { ecnReceived[space][0]++ }
        if (inputEcn == 1) { ecnReceived[space][1]++ }
        if (inputEcn == 3) { ecnReceived[space][2]++ }
        tracePacket("received", space, pkt.pn)
        inputCid = pkt.dcid
        try {
            handleFrames(space, pkt.payload, immediate || inputEcn == 3)
        } catch (e: Exception) {
            lastError = "protocol error: ${e}"
            closeWithError(0x0a, lastError)
        }
    }

    private func processDatagram(data: Array<UInt8>): Unit {
        var off: Int64 = 0
        while (off + 1 < data.size) {
            let b0 = data[off]
            if ((b0 & 0x80) != 0) {
                if (off + 7 > data.size) {
                    return
                }
                let wireVersion = beU32(data, off + 1)
                if (wireVersion != version && wireVersion != 0) {
                    return
                }
                let typeBits = packetType(Int64((b0 >> 4) & 0x03), wireVersion)
                let dcil = Int64(data[off + 5])
                var p = off + 6 + dcil
                if (p + 1 > data.size) {
                    return
                }
                let scil = Int64(data[p])
                if (p + 1 + scil > data.size) {
                    return
                }
                let peerScid = sliceBytes(data, p + 1, scil)
                let packetDcid = sliceBytes(data, off + 6, dcil)
                p = p + 1 + scil
                if (!ctEqual(packetDcid, scid)) {
                    return
                }
                if (wireVersion == 0) {
                    if (off == 0) {
                        onVersionNegotiation(peerScid, ByteReader(data, p, data.size))
                    }
                    return
                }
                if (scil > 20 || (b0 & 0x40) == 0) {
                    return
                }
                if (typeBits == 3) {
                    if (off == 0) {
                        onRetry(data, peerScid, p)
                    }
                    return
                }
                if (typeBits == 1) {
                    return
                }
                if (typeBits == 0) {
                    let tr = ByteReader(data, p, data.size)
                    let tokenLen = Int64(Varint.read(tr))
                    p = tr.pos + tokenLen
                }
                let lr = ByteReader(data, p, data.size)
                let lengthVal = Int64(Varint.read(lr))
                let pnOffset = lr.pos
                let pktEnd = pnOffset + lengthVal
                if (pnOffset + 4 + 16 > pktEnd || pktEnd > data.size) {
                    return
                }
                let space = if (typeBits == 0) { 0 } else { 1 }
                let keys = if (space == 0) { initialServer } else { handshakeServer }
                if (keys.hp.size == 0) {
                    off = pktEnd
                    continue
                }
                let largest = if (space == 0) {
                    largestRecvInitial
                } else if (space == 1) {
                    largestRecvHandshake
                } else {
                    largestRecvApp
                }
                var pkt: ParsedPacket
                try {
                    pkt = PacketBuilder.openLong(sliceBytes(data, off, pktEnd - off), keys,
                        largest)
                } catch (e: Exception) {
                    printDecryptFailure(space, sliceBytes(data, off, pktEnd - off))
                    off = pktEnd
                    continue
                }
                if (space == 0 && !authenticatedInitial) {
                    dcid = peerScid
                    peerCid = peerScid
                    authenticatedInitial = true
                }
                if (!ctEqual(peerScid, peerCid)) {
                    off = pktEnd
                    continue
                }
                processAuthenticated(space, pkt)
                if (closed) {
                    return
                }
                off = pktEnd
            } else {
                // Trailing zero padding after the coalesced packets is legal; a
                // QUIC packet always has the fixed bit set (RFC 9000 section 17.2).
                if ((b0 & 0x40) == 0) {
                    return
                }
                if (appServer.key.size == 0) {
                    return
                }
                let pnOffset = off + 1 + scid.size
                let input = sliceBytes(data, off, data.size - off)
                if (pnOffset + 4 + 16 > data.size) {
                    checkStatelessReset(input)
                    return
                }
                let cid = sliceBytes(input, 1, scid.size)
                if (!localCidMatches(cid)) {
                    checkStatelessReset(input)
                    return
                }
                if (let Some(pkt) <- openApplicationPacket(input)) {
                    processAuthenticated(2, pkt)
                } else {
                    checkStatelessReset(input)
                    failedAppAuthentications++
                    let integrityLimit = if (appServer.chacha) { 68719476736 } else { 4503599627370496 }
                    if (failedAppAuthentications >= integrityLimit) {
                        closeWithError(0x0f, "AEAD integrity limit reached")
                    }
                }
                return
            }
        }
    }

    /** Initiate a QUIC key phase change once the current send keys have been acknowledged. */
    public func updateKeys(): Bool {
        if (closed || !handshakeDone || recovery.spaces[2].largestAcked < writePhaseStart ||
            readPhase != writePhase || nowMillis() < earliestWriteRotation) {
            return false
        }
        rotateWriteKeys()
        return true
    }

    private func rotateWriteKeys(): Unit {
        let previous = appClient
        appClient = PacketCrypto.nextKeys(appClient, tls.hashAlg, tls.keyLen)
        previous.destroy()
        writePhase = !writePhase
        writePhaseStart = nextPn[2]
        earliestWriteRotation = nowMillis() + 3 * recovery.pto(Int64(peerTp.maxAckDelay))
    }

    private func openApplicationPacket(input: Array<UInt8>): Option<ParsedPacket> {
        try {
            let pkt = PacketBuilder.openShort(input, scid.size, appServer, largestRecvApp)
            if (pkt.phase == readPhase) {
                if (pkt.pn > largestInReadPhase) {
                    largestInReadPhase = pkt.pn
                }
                return Some(pkt)
            }
            return None
        } catch (e: Exception) {
            // Header protection is unchanged across generations, but AEAD keys are not.
        }
        if (let Some(previous) <- previousAppServer) {
            try {
                let pkt = PacketBuilder.openShort(input, scid.size, previous, largestRecvApp)
                if (pkt.phase != readPhase && pkt.pn < readPhaseStart) {
                    return Some(pkt)
                }
            } catch (e: Exception) {
                // Check for a peer-initiated update below.
            }
        }
        if (let Some(next) <- nextAppServer) {
            try {
                let pkt = PacketBuilder.openShort(input, scid.size, next, largestRecvApp)
                if (pkt.phase == readPhase || pkt.pn <= largestInReadPhase) {
                    return None
                }
                if (let Some(old) <- previousAppServer) { old.destroy() }
                previousAppServer = Some(appServer)
                previousKeyExpires = nowMillis() + 3 * recovery.pto(Int64(peerTp.maxAckDelay))
                appServer = next
                nextAppServer = Some(PacketCrypto.nextKeys(next, tls.hashAlg, tls.keyLen))
                readPhase = pkt.phase
                readPhaseStart = pkt.pn
                largestInReadPhase = pkt.pn
                if (writePhase != readPhase) {
                    rotateWriteKeys()
                }
                return Some(pkt)
            } catch (e: Exception) {
                printDecryptFailure(2, input)
            }
        }
        return None
    }

    private func onVersionNegotiation(sourceCid: Array<UInt8>, versions: ByteReader): Unit {
        if (!started || authenticatedInitial || switchedVersion || retryToken.size > 0 ||
            !ctEqual(sourceCid, originalDcid) || versions.remaining() == 0 ||
            versions.remaining() % 4 != 0) {
            return
        }
        let proposed = Array<UInt32>(versions.remaining() / 4, repeat: 0)
        for (i in 0..proposed.size) {
            let version = versions.readU32()
            if (version == this.version || version == 0) {
                return
            }
            proposed[i] = version
        }
        offeredVersions = proposed
        let next = if (version == QUIC_V1) { QUIC_V2 } else { QUIC_V1 }
        for (candidate in proposed) {
            if (candidate == next) {
                restartVersion(next)
                return
            }
        }
        lastError = "no mutually supported QUIC version"
        terminate(lastError)
    }

    private func restartVersion(next: UInt32): Unit {
        switchedVersion = true
        version = next
        dcid = randomBytes(8)
        originalDcid = dcid
        scid = randomBytes(8)
        localConnectionIds.remove(0)
        localConnectionIds.add(0, scid)
        tp.initialSourceConnectionId = scid
        tp.chosenVersion = version
        tp.availableVersions = [version] // This client uses incompatible version negotiation.
        for (space in 0..3) {
            recovery.discard(space)
            nextPn[space] = 0
        }
        recovery.newPath(nowMillis())
        wireNumbers = [SentNumbers(), SentNumbers(), SentNumbers()]
        nextPacedSend = Int64.Max
        if (let Some(keys) <- earlyClient) { keys.destroy() }
        earlyClient = None
        initialCryptoSent = 0
        let (client, server) = PacketCrypto.initialSecrets(dcid, backend: tls.backend, version: version)
        initialClient.destroy()
        initialServer.destroy()
        initialClient = client
        initialServer = server
        tls.destroy()
        tls = TlsClient(host, "h3", tp.encode(), tls.store, tls.verifyPeer, backend: tls.backend,
            options: tls.options, labelPrefix: keyLabelPrefix(version))
        clientHello = tls.start()
        queueInitial(clientHello)
        flushRecovery()
    }

    private func onRetry(packet: Array<UInt8>, sourceCid: Array<UInt8>, tokenOffset: Int64): Unit {
        let tokenLen = packet.size - tokenOffset - 16
        if (!started || authenticatedInitial || retryToken.size > 0 || tokenLen <= 0 || tokenLen > 1100 ||
            sourceCid.size == 0 || ctEqual(sourceCid, originalDcid) ||
            !PacketCrypto.verifyRetry(originalDcid, packet, version: version, backend: tls.backend)) {
            return
        }
        retryCid = sourceCid
        retryToken = sliceBytes(packet, tokenOffset, tokenLen)
        dcid = sourceCid
        let (client, server) = PacketCrypto.initialSecrets(dcid, backend: tls.backend, version: version)
        initialClient.destroy()
        initialServer.destroy()
        initialClient = client
        initialServer = server
        recovery.discard(0)
        initialCryptoSent = 0
        queueInitial(clientHello)
        flushRecovery()
    }

    private func printDecryptFailure(space: Int64, pkt: Array<UInt8>): Unit {
        if (let Some(log) <- config.log) {
            let n = if (pkt.size < 40) {
                pkt.size
            } else {
                40
            }
            log("decrypt-fail space=${space} len=${pkt.size} hdr=" + hexEncode(sliceBytes(pkt, 0, n)))
        }
    }

    private func recordRecv(space: Int64, pn: Int64): Bool {
        if (!received[space].record(pn)) { return false }
        if (space == 0 && pn > largestRecvInitial) { largestRecvInitial = pn }
        if (space == 1 && pn > largestRecvHandshake) { largestRecvHandshake = pn }
        if (space == 2 && pn > largestRecvApp) { largestRecvApp = pn }
        return true
    }

    // ------------------------------------------------------------------

    private func handleFrames(space: Int64, payload: Array<UInt8>, immediate: Bool): Unit {
        let r = ByteReader(payload)
        var needAck = false
        while (!r.eof()) {
            let frameStart = r.pos
            let ftype = Varint.read(r)
            if (ftype == 0) {
                continue
            } else if (ftype == 1) {
                needAck = true
            } else if (ftype == 2 || ftype == 3) {
                handleAck(r, space, ftype == 3)
            } else if (ftype == 6) {
                needAck = true
                let off = Int64(Varint.read(r))
                let len = Int64(Varint.read(r))
                let data = r.readBytes(len)
                onCrypto(space, off, data)
            } else if (space != 2 && ftype != 0x1c) {
                throw Exception("frame forbidden at this encryption level")
            } else if (ftype == 4) {
                needAck = true
                let id = Int64(Varint.read(r))
                let code = Varint.read(r)
                let finalSize = Int64(Varint.read(r))
                if (wasReleased(id, finalSize, true)) { continue }
                let st = receiveStream(id)
                accountReceived(st, finalSize, true)
                st.receiveReset = Some(code)
            } else if (ftype == 5) {
                needAck = true
                let id = Int64(Varint.read(r))
                let code = Varint.read(r)
                if ((id & 3) == 3) {
                    throw Exception("STOP_SENDING on receive-only stream")
                }
                if (let Some(st) <- getStream(id)) {
                    resetSend(st, code)
                } else if ((id & 1) == 1) {
                    resetSend(receiveStream(id), code)
                } else if (!wasReleased(id, 0, false)) {
                    throw Exception("STOP_SENDING on unopened local stream")
                }
            } else if (ftype == 7) {
                needAck = true
                if (r.readBytes(Int64(Varint.read(r))).size == 0) {
                    throw Exception("empty NEW_TOKEN")
                }
            } else if (ftype >= 8 && ftype <= 15) {
                needAck = true
                let sid = Int64(Varint.read(r))
                var o: Int64 = 0
                if ((ftype & 0x04) != 0) {
                    o = Int64(Varint.read(r))
                }
                var len: Int64 = -1
                if ((ftype & 0x02) != 0) {
                    len = Int64(Varint.read(r))
                }
                let fin = (ftype & 0x01) != 0
                let data = if (len < 0) { r.readBytes(r.remaining()) } else { r.readBytes(len) }
                onStreamFrame(sid, o, data, fin)
            } else if (ftype == 0x10) {
                needAck = true
                let limit = Varint.read(r)
                if (limit > peerTp.initialMaxData) {
                    peerTp.initialMaxData = limit
                }
            } else if (ftype == 0x11) {
                needAck = true
                let sid = Int64(Varint.read(r))
                let lim = Int64(Varint.read(r))
                if (let Some(st) <- getStream(sid)) {
                    if (lim > st.maxSend) {
                        st.maxSend = lim
                    }
                }
            } else if (ftype == 0x12 || ftype == 0x13) {
                needAck = true
                let limit = Varint.read(r)
                if (limit > 0x1000000000000000) {
                    throw Exception("invalid MAX_STREAMS")
                }
                if (ftype == 0x12 && limit > peerTp.initialMaxStreamsBidi) {
                    peerTp.initialMaxStreamsBidi = limit
                } else if (ftype == 0x13 && limit > peerTp.initialMaxStreamsUni) {
                    peerTp.initialMaxStreamsUni = limit
                }
            } else if (ftype >= 0x14 && ftype <= 0x17) {
                needAck = true
                Varint.read(r)
                if (ftype == 0x15) {
                    Varint.read(r)
                }
            } else if (ftype == 0x18) {
                needAck = true
                rememberPeerCid(r)
            } else if (ftype == 0x19) {
                needAck = true
                retireLocalCid(Varint.read(r))
            } else if (ftype == 0x1a || ftype == 0x1b) {
                needAck = true
                let challenge = r.readBytes(8)
                if (ftype == 0x1a) {
                    if (fromProbe) {
                        let probe = pathProbe.getOrThrow()
                        sendPathFrame(probe.socket, probe.connectionId, 0x1b, challenge)
                    } else {
                        sendPathFrame(socket, dcid, 0x1b, challenge, activePath: true)
                    }
                } else if (fromProbe) {
                    let probe = pathProbe.getOrThrow()
                    if (ctEqual(probe.challenge, challenge)) {
                        probe.validated = true
                    }
                }
            } else if (ftype == 0x1c || ftype == 0x1d) {
                let code = Varint.read(r)
                if (ftype == 0x1c) {
                    Varint.read(r)
                }
                let message = r.readBytes(Int64(Varint.read(r)))
                cause = Some(if (ftype == 0x1c) { QuicCloseCause.Transport(code) } else { QuicCloseCause.Application(code) })
                retainClosingPath(None)
                terminate("peer closed (code ${code}): " + String.fromUtf8(message))
                return
            } else if (ftype == 0x30 || ftype == 0x31) {
                let size = if (ftype == 0x31) { Int64(Varint.read(r)) } else { r.remaining() }
                if (UInt64(r.pos - frameStart + size) > tp.initialMaxDatagramFrameSize) {
                    throw Exception("DATAGRAM exceeds local transport parameter")
                }
                let payload = r.readBytes(size)
                if (let Some(deliver) <- config.onDatagram) { deliver(payload) }
                needAck = true
            } else if (ftype == 0x1e) {
                needAck = true
                if (!handshakeDone) {
                    handshakeDone = true
                    recovery.discard(1)
                    tls.clientHs.destroy()
                    tls.serverHs.destroy()
                    handshakeClient.destroy()
                    handshakeServer.destroy()
                    handshakeClient = PacketKeys([], [], [])
                    handshakeServer = PacketKeys([], [], [])
                    ensureLocalCids()
                }
            } else {
                throw Exception("unsupported frame ${ftype}")
            }
            if (closed) {
                return
            }
        }
        if (needAck) {
            if (space == 2) {
                pendingAck++
                if (pendingAck == 1) { ackDeadline = nowMillis() + Int64(tp.maxAckDelay) }
            }
            if (immediate || pendingAck >= config.ackEvery || tp.maxAckDelay == 0) { sendAck(space) }
        }
    }

    private func handleAck(r: ByteReader, space: Int64, hasEcn: Bool): Unit {
        let (ranges, encodedDelay) = wireNumbers[space].decodeAck(r)
        let maxDelay = Int64(peerTp.maxAckDelay)
        let exponent = peerTp.ackDelayExponent
        let scaledLimit = (maxDelay * 1000) >> exponent
        let delay = if (space != 2 || !handshakeDone) {
            0
        } else if (encodedDelay > scaledLimit) {
            maxDelay
        } else {
            (encodedDelay << exponent) / 1000
        }
        let forward = ranges[0].high > recovery.spaces[space].largestAcked
        let ect0 = if (hasEcn) { Varint.read(r) } else { 0u64 }
        let ect1 = if (hasEcn) { Varint.read(r) } else { 0u64 }
        let ce = if (hasEcn) { Varint.read(r) } else { 0u64 }
        let now = nowMillis()
        recovery.ack(space, ranges, delay, now, maxAckDelay: maxDelay)
        if (space != 2 || !forward || markedSent == 0 || ecnFailed) { return }
        let acked = UInt64(recovery.newlyAckedEct)
        if (!hasEcn && acked == 0) { return }
        if (!hasEcn || ect1 != 0 || ect0 < peerEct0 || ce < peerCe || ect0 + ce > markedSent ||
            ect0 - peerEct0 + ce - peerCe < acked) {
            ecnFailed = true
            return
        }
        if (acked > 0) { ecnValidated = true }
        if (ce > peerCe) { recovery.ecnCongestion(now) }
        peerCe = ce
        peerEct0 = ect0
    }

    private func onCrypto(space: Int64, off: Int64, data: Array<UInt8>): Unit {
        if (off + data.size > 1048576) {
            throw Exception("CRYPTO receive limit exceeded")
        }
        let ready = ByteWriter(1024)
        cryptoReceive[space].append(off, data, ready)
        if (ready.size == 0) {
            return
        }
        tls.onData(ready.toArray(), cryptoSpace: space)
        if (tls.state == 7) {
            lastError = tls.failure
            closeWithError(0x128, tls.failure)
            return
        }
        if (tls.state == 2 && handshakeClient.key.size == 0) {
            handshakeClient = trafficKeys(tls.clientHs, tls.cipherSuite)
            handshakeServer = trafficKeys(tls.serverHs, tls.cipherSuite)
        }
        let out = tls.takeOutput()
        if (out.size > 0 && !tls.handshakeComplete) {
            if (let Some(keys) <- earlyClient) { keys.destroy() }
            earlyClient = None
            queueInitial(out)
        }
        if (tls.handshakeComplete && !established) {
            let remembered = peerTp
            peerTp = TransportParams.decode(tls.peerParams)
            if (!validPeerVersion()) {
                lastError = "QUIC version information mismatch"
                closeWithError(0x11, lastError)
                return
            }
            reconcileEarlyData(remembered)
            if (!ctEqual(peerTp.originalDestinationConnectionId, originalDcid) ||
                !ctEqual(peerTp.initialSourceConnectionId, peerCid) ||
                !ctEqual(peerTp.retrySourceConnectionId, retryCid)) {
                throw Exception("connection IDs in transport parameters do not match")
            }
            peerAppParams = tls.peerParams
            if (peerCid.size > 0) {
                peerConnectionIds.add(0, ConnectionId(peerCid, peerTp.statelessResetToken))
            }
            appClient = trafficKeys(tls.clientApp, tls.cipherSuite)
            appServer = trafficKeys(tls.serverApp, tls.cipherSuite)
            nextAppServer = Some(PacketCrypto.nextKeys(appServer, tls.hashAlg, tls.keyLen))
            var offset = 0
            while (offset < out.size) {
                let remaining = out.size - offset
                let length = if (remaining > 1100) { 1100 } else { remaining }
                queueFrame(1, cryptoFrame(offset, sliceBytes(out, offset, length)))
                offset += length
            }
            established = true
        }
    }

    private func validPeerVersion(): Bool {
        if (peerTp.chosenVersion == 0) {
            return version == QUIC_V1
        }
        if (peerTp.chosenVersion != version) {
            return false
        }
        if (switchedVersion && peerTp.availableVersions.size == 0) {
            return false
        }
        if (switchedVersion) {
            let original = if (version == QUIC_V1) { QUIC_V2 } else { QUIC_V1 }
            for (advertised in peerTp.availableVersions) {
                if (advertised == original) {
                    return false
                }
            }
        }
        return true
    }

    private func trafficKeys(direction: TlsDirection, suite: Int64): PacketKeys {
        return PacketKeys(direction.key.clone(), direction.iv.clone(), direction.hp.clone(),
            secret: direction.secret.clone(),
            chacha: suite == 0x1303, backend: tls.backend, version: version)
    }

    private func reconcileEarlyData(remembered: TransportParams): Unit {
        if (let Some(keys) <- earlyClient) { keys.destroy() }
        earlyClient = None
        if (tls.earlyAccepted &&
            (peerTp.initialMaxData < remembered.initialMaxData ||
            peerTp.initialMaxStreamsBidi < remembered.initialMaxStreamsBidi ||
            peerTp.initialMaxStreamsUni < remembered.initialMaxStreamsUni ||
            peerTp.initialMaxStreamDataBidiRemote < remembered.initialMaxStreamDataBidiRemote ||
            peerTp.initialMaxStreamDataBidiLocal < remembered.initialMaxStreamDataBidiLocal ||
            peerTp.initialMaxStreamDataUni < remembered.initialMaxStreamDataUni ||
            peerTp.activeConnectionIdLimit < remembered.activeConnectionIdLimit)) {
            throw Exception("peer reduced transport limits after accepting early data")
        }
        sendStreams.clear()
        if (!tls.earlyAccepted) {
            recovery.discard(2)
            sentData = 0
        }
        for (stream in earlyStreams) {
            stream.maxSend = Int64(if ((stream.id & 2) == 0) {
                peerTp.initialMaxStreamDataBidiRemote
            } else {
                peerTp.initialMaxStreamDataUni
            })
            if (!tls.earlyAccepted) {
                stream.sendOff = 0
                stream.finSent = false
            }
            stream.scheduled = true
            sendStreams.addLast(stream)
        }
        earlyStreams.clear()
    }

    private func cryptoFrame(offset: Int64, data: Array<UInt8>): Array<UInt8> {
        let w = ByteWriter(data.size + 32)
        w.putU8(0x06)
        Varint.write(w, UInt64(offset))
        Varint.write(w, UInt64(data.size))
        w.putBytes(data)
        return w.toArray()
    }

    private func queueInitial(data: Array<UInt8>): Unit {
        let capacity = 1120 - retryToken.size
        var offset = 0
        while (offset < data.size) {
            let remaining = data.size - offset
            let length = if (remaining < capacity) { remaining } else { capacity }
            queueFrame(0, cryptoFrame(initialCryptoSent, sliceBytes(data, offset, length)))
            offset += length
            initialCryptoSent += length
        }
    }

    private var destinationSequence: UInt64 = 0

    private func rememberPeerCid(r: ByteReader): Unit {
        let seq = Varint.read(r)
        let retire = Varint.read(r)
        let size = Int64(r.readU8())
        if (size < 1 || size > 20 || retire > seq || peerCid.size == 0) {
            throw Exception("invalid NEW_CONNECTION_ID")
        }
        let cid = r.readBytes(size)
        let token = r.readBytes(16)
        if (seq < retiredBefore) {
            retirePeerCid(seq)
            return
        }
        if (let Some(known) <- peerConnectionIds.get(seq)) {
            if (!ctEqual(known.id, cid) || !ctEqual(known.resetToken, token)) {
                throw Exception("peer connection ID sequence was reused")
            }
        } else {
            for ((_, known) in peerConnectionIds) {
                if (ctEqual(known.id, cid) || ctEqual(known.resetToken, token)) {
                    throw Exception("peer connection ID or reset token was reused")
                }
            }
            peerConnectionIds.add(seq, ConnectionId(cid, token))
        }
        if (retire > retiredBefore) {
            retiredBefore = retire
            let obsolete = ArrayList<UInt64>()
            for ((sequence, _) in peerConnectionIds) {
                if (sequence < retire) {
                    obsolete.add(sequence)
                }
            }
            for (sequence in obsolete) {
                retirePeerCid(sequence)
            }
            if (destinationSequence < retire) {
                destinationSequence = seq
                dcid = cid
            }
        }
        if (UInt64(peerConnectionIds.size) > tp.activeConnectionIdLimit) {
            throw Exception("peer exceeded active connection ID limit")
        }
    }

    private func retirePeerCid(sequence: UInt64): Unit {
        peerConnectionIds.remove(sequence)
        let w = ByteWriter(16)
        w.putU8(0x19)
        Varint.write(w, sequence)
        queueFrame(2, w.toArray())
    }

    private func localCidMatches(cid: Array<UInt8>): Bool {
        for ((_, active) in localConnectionIds) {
            if (ctEqual(cid, active)) {
                return true
            }
        }
        return false
    }

    private func ensureLocalCids(): Unit {
        // A small pool suffices for probing a replacement local endpoint.
        while (localConnectionIds.size < 2 && UInt64(localConnectionIds.size) < peerTp.activeConnectionIdLimit) {
            let id = randomBytes(scid.size)
            let sequence = nextLocalCid
            nextLocalCid++
            localConnectionIds.add(sequence, id)
            let frame = ByteWriter(40)
            frame.putU8(0x18)
            Varint.write(frame, sequence)
            Varint.write(frame, 0)
            frame.putVec8(id)
            frame.putBytes(randomBytes(16))
            queueFrame(2, frame.toArray())
        }
    }

    private func retireLocalCid(sequence: UInt64): Unit {
        if (sequence >= nextLocalCid) {
            throw Exception("RETIRE_CONNECTION_ID references an unknown sequence")
        }
        if (let Some(id) <- localConnectionIds.get(sequence)) {
            if (ctEqual(id, inputCid)) {
                throw Exception("RETIRE_CONNECTION_ID carries its own destination CID")
            }
            localConnectionIds.remove(sequence)
            ensureLocalCids()
        }
    }

    private func checkStatelessReset(packet: Array<UInt8>): Unit {
        if (packet.size < 21) { return }
        let token = sliceBytes(packet, packet.size - 16, 16)
        for ((_, candidate) in peerConnectionIds) {
            if (ctEqual(token, candidate.resetToken)) {
                cause = Some(QuicCloseCause.StatelessReset)
            terminate("peer sent a stateless reset")
                return
            }
        }
    }

    private func sendPathFrame(source: QuicSocket, cid: Array<UInt8>, kind: UInt8,
        challenge: Array<UInt8>, activePath!: Bool = false): Unit {
        let payload = Array<UInt8>(1200 - 1 - cid.size - 4 - 16, repeat: 0)
        payload[0] = kind
        copyBytes(payload, 1, challenge, 0, 8)
        let pn = nextPn[2]
        let packet = protectApplication(cid, payload)
        source.sendTo(peer, packet)
        wireNumbers[2].sent(pn)
        if (activePath) {
            let now = nowMicros()
            recovery.sent(2, pn, now / 1000, packet.size, RecoveryFrame([], retransmittable: false),
                timeMicros: now)
        }
    }

    /** Validate a new local UDP endpoint before moving the established connection to it. */
    public func migrate(bindAt: IPSocketAddress, timeoutMs!: Int64 = 3000): Bool {
        if (!handshakeDone || closed || peerTp.disableActiveMigration || pathProbe.isSome()) {
            return false
        }
        let deadline = nowMillis() + timeoutMs
        var next: Option<(UInt64, ConnectionId)> = None
        while (next.isNone() && !closed && nowMillis() < deadline) {
            for ((sequence, cid) in peerConnectionIds) {
                if (sequence != destinationSequence) {
                    next = Some((sequence, cid))
                    break
                }
            }
            if (next.isNone()) { pollOnce() }
        }
        if (let Some((sequence, cid)) <- next) {
            let candidate = QuicSocket(bindAt, peer, config)
            candidate.receiveTimeout = Some(Duration.millisecond * 10)
            let probe = PathProbe(candidate, sequence, cid.id)
            pathProbe = Some(probe)
            var sentAt: Int64 = -1
            try {
                while (!probe.validated && !closed && nowMillis() < deadline && peerConnectionIds.contains(sequence)) {
                    let now = nowMillis()
                    if (sentAt < 0 || now - sentAt >= recovery.pto(Int64(peerTp.maxAckDelay))) {
                        sendPathFrame(candidate, cid.id, 0x1a, probe.challenge)
                        sentAt = now
                    }
                    readSocket(candidate, true)
                    if (!probe.validated && !closed) {
                        pollOnce()
                    }
                }
                if (probe.validated && !closed && peerConnectionIds.contains(sequence)) {
                    let old = socket
                    socket = candidate
                    old.close()
                    let previous = destinationSequence
                    destinationSequence = probe.sequence
                    dcid = probe.connectionId
                    ecnFailed = false
                    ecnValidated = false
                    ecnTrialSent = 0
                    pathMtu = 1200
                    mtuProbe = None
                    nextMtuProbe = 0
                    recovery.newPath(nowMillis())
                    nextPacedSend = Int64.Max
                    retirePeerCid(previous)
                    queueFrame(2, [1])
                    flushRecovery()
                    return true
                }
                if (!closed && sentAt >= 0 && peerConnectionIds.contains(sequence)) {
                    retirePeerCid(sequence)
                }
            } finally {
                pathProbe = None
                if (!probe.validated || closed || destinationSequence != sequence) {
                    candidate.close()
                }
            }
        }
        return false
    }

    private func receiveStream(id: Int64): QuicStream {
        if ((id & 3) == 2) {
            throw Exception("STREAM on send-only stream")
        }
        return if (let Some(existing) <- getStream(id)) {
            existing
        } else {
            if ((id & 1) == 0) {
                throw Exception("STREAM on unopened local stream")
            }
            let limit = if ((id & 2) == 0) { tp.initialMaxStreamsBidi } else { tp.initialMaxStreamsUni }
            if (UInt64(id >> 2) >= limit) {
                throw Exception("peer stream limit exceeded")
            }
            let stream = QuicStream()
            stream.id = id
            putStream(stream)
            stream
        }
    }

    private func accountReceived(st: QuicStream, end: Int64, fin: Bool): Unit {
        if (st.recvFinOffset >= 0 && (end > st.recvFinOffset || (fin && end != st.recvFinOffset)) ||
            (fin && end < st.highestReceived)) {
            throw Exception("inconsistent stream final size")
        }
        if (end > st.maxReceive) {
            throw Exception("stream flow control limit exceeded")
        }
        if (end > st.highestReceived) {
            receivedData += end - st.highestReceived
            st.highestReceived = end
            if (UInt64(receivedData) > tp.initialMaxData) {
                throw Exception("connection flow control limit exceeded")
            }
        }
        if (fin) {
            st.recvFinOffset = end
        }
    }

    private func onStreamFrame(id: Int64, off: Int64, data: Array<UInt8>, fin: Bool): Unit {
        if (wasReleased(id, off + data.size, fin)) { return }
        let stream = receiveStream(id)
        accountReceived(stream, off + data.size, fin)
        if (stream.receiveReset.isNone()) {
            stream.receive.append(off, data, stream.recvBuf)
            stream.recvOff = stream.receive.offset
            stream.recvFin = stream.recvOff == stream.recvFinOffset
        }
    }

    private func resetSend(stream: QuicStream, code: UInt64): Unit {
        if (stream.sendReset.isSome()) { return }
        stream.sendReset = Some(code)
        let frame = ByteWriter(32)
        frame.putU8(4)
        Varint.write(frame, UInt64(stream.id))
        Varint.write(frame, code)
        Varint.write(frame, UInt64(stream.sendOff))
        queueFrame(2, frame.toArray())
    }

    private func sendAck(space: Int64): Unit {
        let delay: UInt64 = if (space == 2) { UInt64(nowMicros() - largestAppTime) >> tp.ackDelayExponent } else { 0 }
        let counts = ecnReceived[space]
        let feedback: Option<Array<UInt64>> = if (counts[0] + counts[1] + counts[2] > 0) { Some(counts) } else { None }
        let ack = received[space].encode(delay: delay, ecn: feedback)
        if (space == 2) { pendingAck = 0; ackDeadline = Int64.Max }
        if (space == 2 && fromProbe) {
            let probe = pathProbe.getOrThrow()
            let pn = nextPn[2]
            probe.socket.sendTo(peer, protectApplication(probe.connectionId, ack))
            wireNumbers[2].sent(pn)
        } else {
            sendPacket(space, ack, None)
        }
    }


    public func sendClientHello(): Unit {
        if (!started && !closed) {
            started = true
            lastActivity = nowMillis()
            queueInitial(clientHello)
            flushRecovery()
        }
    }

    public func handshake(timeoutMs: Int64): Bool {
        sendClientHello()
        let deadline = nowMillis() + timeoutMs
        while (!closed && !established && nowMillis() < deadline) {
            pollOnce()
        }
        if (!established && !closed) {
            cause = Some(QuicCloseCause.HandshakeTimeout)
            lastError = "handshake timeout (tls state ${tls.state})"
            terminate(lastError)
        }
        return established && !closed
    }

    public func openBidiStream(): QuicStream {
        let st = QuicStream()
        st.id = localBidiCount * 4
        putStream(st)
        return st
    }

    public func openUniStream(): QuicStream {
        let st = QuicStream()
        st.id = localUniCount * 4 + 2
        putStream(st)
        return st
    }

    public func putStream(st: QuicStream): Unit {
        if (getStream(st.id).isSome()) {
            throw Exception("stream ${st.id} already exists")
        }
        let index = st.id >> 2
        match (st.id & 3) {
            case 0 =>
                if (index != localBidiCount || UInt64(index) >= peerTp.initialMaxStreamsBidi) {
                    throw Exception("peer bidirectional stream limit reached")
                }
                localBidiCount = index + 1
                st.maxSend = Int64(peerTp.initialMaxStreamDataBidiRemote)
                st.maxReceive = Int64(tp.initialMaxStreamDataBidiLocal)
            case 1 =>
                st.maxSend = Int64(peerTp.initialMaxStreamDataBidiLocal)
                st.maxReceive = Int64(tp.initialMaxStreamDataBidiRemote)
            case 2 =>
                if (UInt64(index) >= peerTp.initialMaxStreamsUni) {
                    throw Exception("peer unidirectional stream limit reached")
                }
                localUniCount = index + 1
                st.maxSend = Int64(peerTp.initialMaxStreamDataUni)
            case _ =>
                st.maxSend = 0
                st.maxReceive = Int64(tp.initialMaxStreamDataUni)
        }
        streams.add(st.id, st)
    }

    /** Release an application-consumed local bidirectional stream. Recovery owns its queued frames. */
    public func releaseStream(id: Int64): Unit {
        if (let Some(stream) <- streams.get(id)) {
            if ((id & 3) != 0 || !stream.recvFin || !stream.finSent) { return }
            let slot = (id >> 2) % retiredIds.size
            retiredIds[slot] = id
            retiredSizes[slot] = stream.recvFinOffset
            streams.remove(id)
        }
    }

    private func wasReleased(id: Int64, end: Int64, fin: Bool): Bool {
        if ((id & 3) != 0 || (id >> 2) >= localBidiCount || streams.contains(id)) { return false }
        let slot = (id >> 2) % retiredIds.size
        if (retiredIds[slot] == id && (end > retiredSizes[slot] || (fin && end != retiredSizes[slot]))) {
            throw Exception("inconsistent closed stream final size")
        }
        return true
    }

    public func getStream(id: Int64): Option<QuicStream> {
        return streams.get(id)
    }

    public func peerUniStreams(): Array<QuicStream> {
        let result = ArrayList<QuicStream>()
        for ((id, stream) in streams) {
            if ((id & 3) == 3) {
                result.add(stream)
            }
        }
        return result.toArray()
    }

    /** Replenish flow-control credit after the caller has read or buffered stream bytes. */
    public func extendReceiveWindow(st: QuicStream, consumed: Int64): Unit {
        if (consumed > st.recvOff || consumed < 0) {
            throw Exception("invalid consumed stream offset")
        }
        let delta = consumed - st.creditedReceive
        if (delta <= 0 || (delta < 65536 && !st.recvFin && st.maxReceive - consumed > delta &&
            Int64(tp.initialMaxData) - receivedData > delta) || closed) {
            return
        }
        st.creditedReceive = consumed
        tp.initialMaxData += UInt64(delta)
        if (!st.recvFin) {
            st.maxReceive += delta
            let streamCredit = ByteWriter(24)
            streamCredit.putU8(0x11)
            Varint.write(streamCredit, UInt64(st.id))
            Varint.write(streamCredit, UInt64(st.maxReceive))
            queueFrame(2, streamCredit.toArray())
        }
        let connectionCredit = ByteWriter(16)
        connectionCredit.putU8(0x10)
        Varint.write(connectionCredit, tp.initialMaxData)
        queueFrame(2, connectionCredit.toArray())
        flushRecovery()
    }

    /** Queue explicitly replay-safe bytes for 0-RTT. Rejected data is resent after authentication. */
    public func sendEarlyStream(st: QuicStream, data: Array<UInt8>, fin: Bool): Unit {
        if (!canSendEarlyData) {
            throw Exception("0-RTT keys are unavailable")
        }
        sendClientHello()
        if (!st.earlyRegistered) {
            st.earlyRegistered = true
            earlyStreams.add(st)
        }
        enqueueStream(st, data, fin)
    }

    public func sendStream(st: QuicStream, data: Array<UInt8>, fin: Bool): Unit {
        if (!established) {
            throw Exception("connection is not established")
        }
        enqueueStream(st, data, fin)
    }

    private func enqueueStream(st: QuicStream, data: Array<UInt8>, fin: Bool): Unit {
        if (closed || st.finQueued || st.sendReset.isSome() || (st.id & 3) == 3 ||
            !streams.contains(st.id)) {
            throw Exception("stream is not writable")
        }
        if (!st.scheduled) {
            st.scheduled = true
            sendStreams.addLast(st)
        }
        st.outgoing.putBytes(data)
        if (fin) {
            st.finQueued = true
        }
        flushStreams()
    }

    public func flushStreams(): Unit {
        if (closed) {
            return
        }
        flushRecovery()
        flushStreamData()
    }

    private func flushStreamData(): Unit {
        if ((!established && !canSendEarlyData) || closed) {
            return
        }
        var blocked = 0
        while (blocked < sendStreams.size) {
            let st = sendStreams.first.getOrThrow()
            if (st.sendReset.isSome() || (st.sendOff == st.outgoing.size && (!st.finQueued || st.finSent))) {
                sendStreams.removeFirst()
                st.scheduled = false
                continue
            }
            let streamLimit = if ((st.id & 2) == 0) { peerTp.initialMaxStreamsBidi } else {
                peerTp.initialMaxStreamsUni
            }
            let avail = st.outgoing.size - st.sendOff
            let room = st.maxSend - st.sendOff
            let credit = Int64(peerTp.initialMaxData) - sentData
            var n = if (avail < room) { avail } else { room }
            if (n > credit) {
                n = credit
            }
            let payloadLimit = pathMtu - 96
            if (n > payloadLimit) {
                n = payloadLimit
            }
            if (((st.id & 1) == 0 && UInt64(st.id >> 2) >= streamLimit) || n < 0 || (n == 0 && avail > 0)) {
                sendStreams.removeFirst()
                sendStreams.addLast(st)
                blocked++
                continue
            }
            let fin = st.finQueued && st.sendOff + n == st.outgoing.size
            let w = ByteWriter(n + 32)
            var ftype: UInt8 = if (fin) { 0x0b } else { 0x0a }
            if (st.sendOff > 0) {
                ftype |= 0x04
            }
            w.putU8(ftype)
            Varint.write(w, UInt64(st.id))
            if (st.sendOff > 0) {
                Varint.write(w, UInt64(st.sendOff))
            }
            Varint.write(w, UInt64(n))
            w.putBytes(st.sendBuf, st.sendOff, n)
            let bytes = w.toArray()
            if (!sendPacket(2, bytes, Some(RecoveryFrame(bytes)))) {
                return
            }
            st.sendOff += n
            sentData += n
            st.finSent = fin
            sendStreams.removeFirst()
            if (st.sendOff < st.outgoing.size) { sendStreams.addLast(st) } else { st.scheduled = false }
            blocked = 0
        }
    }

    /** Send an unreliable RFC 9221 DATAGRAM when the peer and congestion budget allow it. */
    public func sendDatagram(data: Array<UInt8>): Bool {
        if (closed || !established || UInt64(data.size) + 1 > peerTp.initialMaxDatagramFrameSize ||
            UInt64(data.size + dcid.size + 22) > peerTp.maxUdpPayloadSize ||
            data.size + dcid.size + 22 > pathMtu) { return false }
        let bytes = concat([0x30], data)
        return sendPacket(2, bytes, Some(RecoveryFrame(bytes, retransmittable: false)))
    }

    public func closeConnection(reason: String): Unit {
        closeWithError(0, reason)
    }

    public func closeApplication(code: UInt64, reason: String): Unit {
        closeWithError(code, reason, application: true)
    }

    private func closeWithError(code: UInt64, reason: String, application!: Bool = false): Unit {
        if (closed) {
            return
        }
        let space = if (established) { 2 } else if (handshakeClient.key.size > 0) { 1 } else { 0 }
        let w = ByteWriter(128)
        let app = application && space == 2
        w.putU8(if (app) { 0x1d } else { 0x1c })
        Varint.write(w, if (application && !app) { 0x0c } else { code })
        if (!app) {
            Varint.write(w, 0)
        }
        let msg = reason.toArray()
        let size = if (msg.size < 1000) { msg.size } else { 1000 }
        Varint.write(w, UInt64(size))
        w.putBytes(msg, 0, size)
        cause = Some(if (app) { QuicCloseCause.Application(code) } else { QuicCloseCause.Transport(code) })
        try {
            if (started) {
                let frame = w.toArray()
                let packet = if (space == 2) {
                    protectApplication(dcid, frame)
                } else {
                    let keys = if (space == 1) { handshakeClient } else { initialClient }
                    PacketBuilder.longHeader(space, dcid, scid, retryToken, nextPn[space], 4, keys,
                        frame, if (space == 0) { 1200 } else { 0 })
                }
                socket.sendTo(peer, packet)
                retainClosingPath(Some(packet))
            }
        } catch (e: Exception) {
            lastError = "close send failed: " + e.message
        } finally {
            terminate(reason)
        }
    }

    // The endpoint owns the socket until three PTOs elapse. Reuse the identical protected
    // close packet, at most once per PTO, and send nothing while draining a peer close.
    private func retainClosingPath(packet: Option<Array<UInt8>>): Unit {
        closed = true
        let pto = recovery.pto(Int64(peerTp.maxAckDelay))
        let deadline = nowMillis() + 3 * pto
        var next = nowMillis()
        while (true) {
            let remaining = deadline - nowMillis()
            if (remaining <= 0) { break }
            socket.receiveTimeout = Some(Duration.millisecond * remaining)
            try {
                let (source, n) = socket.receiveFrom(receiveBuffer)
                if (source == peer && n >= 21 && nowMillis() >= next) {
                    if (let Some(response) <- packet) { socket.sendTo(peer, response) }
                    next = nowMillis() + pto
                }
            } catch (e: Exception) { break }
        }
    }

    private func terminate(reason: String): Unit {
        closed = true
        closeReason = reason
        tls.destroy()
        for (keys in [initialClient, initialServer, handshakeClient, handshakeServer, appClient, appServer]) {
            keys.destroy()
        }
        for (keys in [previousAppServer, nextAppServer, earlyClient]) {
            if (let Some(value) <- keys) { value.destroy() }
        }
        socket.close()
    }
}

private let MONOTONIC_START = MonoTime.now()

private func nowMicros(): Int64 {
    return (MonoTime.now() - MONOTONIC_START).toNanoseconds() / 1000
}

public func nowMillis(): Int64 {
    return nowMicros() / 1000
}
