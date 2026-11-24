package quic.transport

import std.net.*

@When[os != "Linux"]
class QuicSocket {
    private let udp: UdpSocket
    var receiveTimeout: Option<Duration> = Some(Duration.millisecond * 10)
    prop receivedEcn: Int64 { get() { 0 } }
    prop supportsEcn: Bool { get() { false } }

    init(local: IPSocketAddress, peer: IPSocketAddress, config: QuicConfig) {
        udp = UdpSocket(bindAt: local)
        try {
            udp.bind()
            if (config.sendMtu > 1200) { throw Exception("MTU probing unavailable on this platform") }
        } catch (e: Exception) { udp.close(); throw e }
    }

    func sendTo(peer: IPSocketAddress, data: Array<UInt8>, ect!: Bool = false): Unit { udp.sendTo(peer, data) }
    func receiveFrom(buf: Array<UInt8>): (SocketAddress, Int64) {
        udp.receiveTimeout = receiveTimeout
        return udp.receiveFrom(buf)
    }
    func close(): Unit { udp.close() }
}
