package quic.transport

import std.net.*
import quic.crypto.copyBytes

@When[os == "Linux"]
@C
struct IoVector {
    var data = CPointer<UInt8>()
    var length: UIntNative = 0
}

@When[os == "Linux"]
@C
struct MessageHeader {
    var name = CPointer<UInt8>()
    var nameLength: UInt32 = 0
    var vectors = CPointer<IoVector>()
    var vectorCount: UIntNative = 0
    var control = CPointer<UInt8>()
    var controlLength: UIntNative = 0
    var flags: Int32 = 0
}

@When[os == "Linux"]
@C
struct MultiMessage {
    var header = MessageHeader()
    var length: UInt32 = 0
}

@When[os == "Linux"]
@C
struct ControlHeader {
    var length: UIntNative = 0
    var level: Int32 = 0
    var kind: Int32 = 0
}

@When[os == "Linux"]
@C
struct PollFd {
    var fd: Int32 = -1
    var events: Int16 = 1
    var returned: Int16 = 0
}

@When[os == "Linux"]
@C
struct TimeSpec {
    var seconds: IntNative = 0
    var nanos: IntNative = 0
}

@When[os == "Linux"]
foreign func socket(domain: Int32, kind: Int32, protocol: Int32): Int32
@When[os == "Linux"]
foreign func bind(fd: Int32, address: CPointer<UInt8>, length: UInt32): Int32
@When[os == "Linux"]
foreign func connect(fd: Int32, address: CPointer<UInt8>, length: UInt32): Int32
@When[os == "Linux"]
foreign func close(fd: Int32): Int32
@When[os == "Linux"]
foreign func send(fd: Int32, data: CPointer<UInt8>, length: UIntNative, flags: Int32): IntNative
@When[os == "Linux"]
foreign func ppoll(fds: CPointer<PollFd>, count: UIntNative, timeout: CPointer<TimeSpec>, mask: CPointer<UInt8>): Int32
@When[os == "Linux"]
foreign func recvmmsg(fd: Int32, headers: CPointer<MultiMessage>, count: UInt32, flags: Int32, timeout: CPointer<TimeSpec>): Int32
@When[os == "Linux"]
foreign func setsockopt(fd: Int32, level: Int32, kind: Int32, value: CPointer<Int32>, length: UInt32): Int32

@When[os == "Linux"]
private func socketOption(fd: Int32, level: Int32, kind: Int32, value: Int32): Bool {
    var option = value
    return unsafe { setsockopt(fd, level, kind, inout option, 4) == 0 }
}

@When[os == "Linux"]
private func closeDescriptor(fd: Int32): Unit {
    if (fd >= 0) { unsafe { close(fd) }; () }
}

/** A connected UDP socket only receives packets from the selected remote endpoint. */
@When[os == "Linux"]
class QuicSocket {
    private let peer: IPSocketAddress
    private var fd: Int32 = -1
    private let slots: Int64
    private let slab: Array<UInt8>
    private let messages: CPointer<MultiMessage>
    private let vectors: CPointer<IoVector>
    private let controls: CPointer<UInt8>
    private var count: Int64 = 0
    private var slot: Int64 = 0
    private var offset: Int64 = 0
    private var segment: Int64 = 0
    private var mark: Int64 = 0
    private var ectEnabled = false
    private var marking = false
    var receiveTimeout: Option<Duration> = Some(Duration.millisecond * 10)
    prop receivedEcn: Int64 { get() { mark } }
    prop supportsEcn: Bool { get() { ectEnabled } }

    init(local: IPSocketAddress, peer: IPSocketAddress, config: QuicConfig) {
        this.peer = peer
        slots = if (config.receiveBatch < 4) { config.receiveBatch } else { 4 }
        slab = Array<UInt8>(slots * 65536, repeat: 0)
        unsafe {
            messages = LibC.malloc<MultiMessage>(count: slots)
            vectors = LibC.malloc<IoVector>(count: slots)
            controls = LibC.malloc<UInt8>(count: slots * 128)
            try {
                if (messages.isNull() || vectors.isNull() || controls.isNull()) { throw Exception("UDP batch allocation failed") }
                let ipv6 = peer.isIPv6()
                fd = socket(if (ipv6) { 10 } else { 2 }, 0x80802, 17) // SOCK_DGRAM | NONBLOCK | CLOEXEC
                if (fd < 0) { throw Exception("UDP socket creation failed") }
                let localBytes = local.getAddressBytes()
                let peerBytes = peer.getAddressBytes()
                let localAddr = acquireArrayRawData(localBytes)
                let remoteAddr = acquireArrayRawData(peerBytes)
                let ready = bind(fd, localAddr.pointer, UInt32(localBytes.size)) == 0 &&
                    connect(fd, remoteAddr.pointer, UInt32(peerBytes.size)) == 0
                releaseArrayRawData(remoteAddr)
                releaseArrayRawData(localAddr)
                if (!ready) { throw Exception("UDP bind/connect failed") }
                let level: Int32 = if (ipv6) { 41 } else { 0 }
                if (config.sendMtu > 1200 && !socketOption(fd, level, if (ipv6) { 23 } else { 10 }, 2)) {
                    throw Exception("cannot enforce path MTU discovery")
                }
                // IP_RECVTOS / IPV6_RECVTCLASS and UDP_GRO. All three are optional.
                ectEnabled = config.ecn && socketOption(fd, level, if (ipv6) { 66 } else { 13 }, 1)
                socketOption(fd, 17, 104, 1)
            } catch (e: Exception) {
                closeDescriptor(fd)
                LibC.free(messages)
                LibC.free(vectors)
                LibC.free(controls)
                throw e
            }
        }
    }

    func close(): Unit {
        if (fd >= 0) {
            closeDescriptor(fd)
            fd = -1
            unsafe { LibC.free(messages); LibC.free(vectors); LibC.free(controls) }
        }
    }

    func sendTo(address: IPSocketAddress, data: Array<UInt8>, ect!: Bool = false): Unit {
        if (fd < 0 || address != peer) { throw Exception("invalid UDP destination") }
        if (ect != marking) {
            let ipv6 = peer.isIPv6()
            if (!socketOption(fd, if (ipv6) { 41 } else { 0 }, if (ipv6) { 67 } else { 1 }, if (ect) { 2 } else { 0 })) {
                throw Exception("could not set ECN marking")
            }
            marking = ect
        }
        unsafe {
            let raw = acquireArrayRawData(data)
            let sent = send(fd, raw.pointer, UIntNative(data.size), 0)
            releaseArrayRawData(raw)
            if (Int64(sent) != data.size) { throw Exception("UDP send failed") }
        }
    }

    private unsafe func refill(): Bool {
        var poll = PollFd()
        poll.fd = fd
        let ns = receiveTimeout.getOrThrow().toNanoseconds()
        var timeout = TimeSpec()
        timeout.seconds = IntNative(ns / 1000000000)
        timeout.nanos = IntNative(ns % 1000000000)
        if (ppoll(inout poll, 1, inout timeout, CPointer<UInt8>()) <= 0) { return false }
        let raw = acquireArrayRawData(slab)
        try {
            for (i in 0..slots) {
                var v = IoVector()
                v.data = raw.pointer + i * 65536
                v.length = 65536
                vectors.write(i, v)
                var m = MultiMessage()
                m.header.vectors = vectors + i
                m.header.vectorCount = 1
                m.header.control = controls + i * 128
                m.header.controlLength = 128
                messages.write(i, m)
            }
            count = Int64(recvmmsg(fd, messages, UInt32(slots), 0x40, CPointer<TimeSpec>()))
        } finally { releaseArrayRawData(raw) }
        slot = 0
        offset = 0
        return count > 0
    }

    private unsafe func readMetadata(header: MessageHeader): Unit {
        segment = 0
        mark = 0
        let align = Int64(sizeOf<UIntNative>())
        let base = Int64(sizeOf<ControlHeader>())
        var i = 0
        let limit = Int64(header.controlLength)
        while (i + base <= limit) {
            let p = header.control + i
            let item = CPointer<ControlHeader>(p).read()
            let length = Int64(item.length)
            if (length < base || length > limit - i) { break }
            let data = p + base
            if (item.level == 17 && item.kind == 104 && length >= base + 4) {
                segment = Int64(CPointer<UInt32>(data).read())
            } else if (item.level == 0 && item.kind == 1 && length > base) {
                mark = Int64(data.read() & 3)
            } else if (item.level == 41 && item.kind == 67 && length >= base + 4) {
                mark = Int64(CPointer<UInt32>(data).read() & 3)
            }
            i += ((length + align - 1) / align) * align
        }
    }

    func receiveFrom(out: Array<UInt8>): (SocketAddress, Int64) {
        unsafe {
            if (fd < 0 || (slot >= count && !refill())) { return (peer, 0) }
            let m = messages.read(slot)
            if ((m.header.flags & 0x28) != 0 || m.length == 0) { slot++; offset = 0; return (peer, 0) }
            if (offset == 0) { readMetadata(m.header) }
            let remaining = Int64(m.length) - offset
            let size = if (segment > 0 && segment < remaining) { segment } else { remaining }
            if (size > out.size) { slot++; offset = 0; return (peer, 0) }
            copyBytes(out, 0, slab, slot * 65536 + offset, size)
            offset += size
            if (offset == Int64(m.length)) { slot++; offset = 0 }
            return (peer, size)
        }
    }
}
