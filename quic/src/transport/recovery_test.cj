package quic.transport

import quic.crypto.*
import std.unittest.*
import std.collection.ArrayList
import std.unittest.testmacro.*

@Test
class RecoveryTest {
    @TestCase
    func ackRangesMergeAndEvictWithoutRedelivery() {
        let history = ReceivedPackets(256)
        for (i in 0..160) { @Assert(history.record(i * 2), true) }
        let sparse = ByteReader(history.encode())
        @Expect(sparse.readU8(), 2)
        let (ranges, _) = AckRanges.decode(sparse, 320)
        @Expect(ranges.size, 160)
        for (i in 0..159) { @Assert(history.record(i * 2 + 1), true) }
        let merged = ByteReader(history.encode())
        merged.readU8()
        let (joined, _) = AckRanges.decode(merged, 320)
        @Expect(joined.size, 1)
        @Expect(joined[0].low, 0)
        @Expect(joined[0].high, 318)
        let bounded = ReceivedPackets(2)
        for (pn in [0, 4, 8]) { @Expect(bounded.record(pn), true) }
        @Expect(bounded.record(0), false)
        @Expect(bounded.record(8), false)
    }

    @TestCase
    func disjointAckRangesDoNotAcknowledgeGap() {
        let data: Array<UInt8> = [5, 0, 1, 1, 0, 1]
        let (ranges, _) = AckRanges.decode(ByteReader(data), 6)
        @Expect(ranges.size, 2)
        @Expect(ranges[0].low, 4)
        @Expect(ranges[1].high, 2)
        let recovery = LossRecovery()
        let frames = Array<RecoveryFrame>(6, { _ => RecoveryFrame([1]) })
        for (pn in 0..6) {
            recovery.sent(2, pn, 10, 1000, frames[pn])
        }
        recovery.ack(2, ranges, 0, 20)
        @Expect(frames[0].delivered, false)
        @Expect(frames[3].delivered, false)
        @Expect(frames[4].delivered, true)
        @Expect(recovery.spaces[2].pending.size, 1)
        @Expect(recovery.bytesInFlight, 1000)
        @Expect(recovery.window < 12000, true)
    }

    @TestCase
    func probeDoesNotForgetOriginalPacket() {
        let recovery = LossRecovery()
        let frame = RecoveryFrame([1])
        recovery.sent(2, 0, 100, 35, frame)
        @Expect(recovery.probeSpace(1000, true, 25), -1)
        @Expect(recovery.probeSpace(1500, true, 25), 2)
        recovery.sent(2, 1, 1500, 35, recovery.probe(2))
        let (ranges, _) = AckRanges.decode(ByteReader([0, 0, 0, 0]), 2)
        recovery.ack(2, ranges, 0, 1510)
        @Expect(frame.delivered, true)
        @Expect(frame.inFlight, 1)
    }

    @TestCase
    func ackCannotCoverSkippedOrUnsentPacketNumbers() {
        let sent = SentNumbers()
        sent.sent(0)
        sent.sent(2)
        let (ranges, _) = sent.decodeAck(ByteReader([2, 0, 1, 0, 0, 0]))
        @Expect(ranges.size, 2)
        @Expect(ranges[1].low, 0)
        @Expect(ackRejected(sent, [3, 0, 0, 0]), true)
        @Expect(ackRejected(sent, [2, 0, 0, 2]), true)
    }

    private func ackRejected(sent: SentNumbers, bytes: Array<UInt8>): Bool {
        try {
            sent.decodeAck(ByteReader(bytes))
            return false
        } catch (e: Exception) {
            return true
        }
    }

    @TestCase
    func pacerRefillsAtTheWindowRateAndCapsIdleBurst() {
        let pacer = SendPacer()
        // 1.25 * 10000 / 100 ms = one byte every 8 microseconds.
        @Expect(pacer.delay(0, 1200, 10000, 100), 0)
        pacer.sent(0, 1200, 10000, 100)
        pacer.sent(0, 1200, 10000, 100)
        pacer.sent(0, 100, 10000, 100)
        @Expect(pacer.delay(0, 1200, 10000, 100), 9600)
        @Expect(pacer.delay(9599, 1200, 10000, 100), 1)
        @Expect(pacer.delay(9600, 1200, 10000, 100), 0)
        let idle = 200000
        // Idle accrual is clipped to the smaller post-congestion burst.
        @Expect(pacer.delay(idle, 1200, 2400, 100), 0)
        pacer.sent(idle, 1200, 2400, 100)
        pacer.sent(idle, 1200, 2400, 100)
        @Expect(pacer.delay(idle, 1200, 2400, 100), 40000)
    }

    @TestCase
    func ackOnlyDoesNotConsumePacingCreditAndProbeCanBorrow() {
        let recovery = LossRecovery()
        recovery.sent(0, 0, 0, 1200, RecoveryFrame([1]), timeMicros: 0)
        recovery.sent(0, 1, 0, 1200, RecoveryFrame([1]), timeMicros: 0)
        let delay = recovery.pacingDelay(0, 1200)
        @Expect(delay > 0, true)
        recovery.sentNonEliciting(0, 2, 0)
        @Expect(recovery.pacingDelay(0, 1200), delay)
        recovery.sent(0, 3, 0, 1200, RecoveryFrame([1]), timeMicros: 0)
        @Expect(recovery.pacingDelay(0, 1200) > delay, true)
    }

    @TestCase
    func persistentCongestionCollapsesTheWindowAcrossSpaces() {
        let recovery = LossRecovery()
        recovery.sent(0, 0, 0, 1200, RecoveryFrame([1]))
        recovery.ack(0, oneAck(0), 0, 10, maxAckDelay: 25)
        recovery.sent(1, 0, 20, 1200, RecoveryFrame([1]))
        recovery.sent(2, 0, 220, 1200, RecoveryFrame([1]))
        recovery.sent(1, 1, 300, 1200, RecoveryFrame([1]))
        recovery.sent(2, 1, 310, 1200, RecoveryFrame([1]))
        recovery.ack(1, oneAck(1), 0, 310, maxAckDelay: 25)
        @Expect(recovery.persistentCongestionEvents, 0)
        recovery.ack(2, oneAck(1), 0, 320, maxAckDelay: 25)
        @Expect(recovery.window, MIN_WINDOW)
        @Expect(recovery.persistentCongestionEvents, 1)
        @Expect(recovery.bytesInFlight, 0)
        @Expect(recovery.spaces[1].pending.size, 1)
        @Expect(recovery.spaces[2].pending.size, 1)
        recovery.newPath(321)
        @Expect(recovery.window, INITIAL_WINDOW)
    }

    @TestCase
    func acknowledgedPacketsAndUnmeasuredLossInterruptThePeriod() {
        let history = CongestionHistory()
        let beforeRtt = CongestionPacket(0, 0, 0, true, false)
        let first = CongestionPacket(1, 63, 100, true, true)
        let ackOnly = CongestionPacket(2, 64, 120, false, true)
        let last = CongestionPacket(1, 65, 400, true, true)
        for (packet in [beforeRtt, first, ackOnly, last]) {
            history.sent(packet)
        }
        beforeRtt.lost = true
        last.lost = true
        @Expect(history.persistent(200), false)
        first.lost = true
        @Expect(history.persistent(300), false)
        @Expect(history.persistent(299), true)
        // Packet 64 is a non-ack-eliciting packet in another number space.
        history.ack(2, oneAck(64))
        @Expect(history.persistent(299), false)
    }

    @TestCase
    func lateAckInterruptsPreviouslyDeclaredLosses() {
        let history = CongestionHistory()
        for (i in 0..3) {
            let packet = CongestionPacket(2, 63 + i, i * 100, true, true)
            packet.lost = true
            history.sent(packet)
        }
        @Expect(history.persistent(150), true)
        history.ack(2, oneAck(64))
        @Expect(history.persistent(150), false)
        history.resetPeriod()
        @Expect(history.persistent(0), false)
    }

    private func oneAck(pn: Int64): ArrayList<AckRange> {
        let ranges = ArrayList<AckRange>()
        ranges.add(AckRange(pn, pn))
        return ranges
    }

    @TestCase
    func receiveRangesTrimOverlapsAndFillMultipleGaps() {
        let ranges = ReceiveRanges()
        let output = ByteWriter()
        ranges.append(3, [4, 5, 6], output)
        ranges.append(7, [8], output)
        ranges.append(1, [2, 3, 4, 5, 6, 7], output)
        ranges.append(0, [1, 2], output)
        ranges.append(5, [6, 7], output)
        @Expect(ranges.offset, 8)
        @Expect(hexEncode(output.toArray()), "0102030405060708")
    }

    @TestCase
    func rfc9001ChaChaAndKeyUpdate() {
        let secret = hexDecode("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
        let key = hexDecode("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
        let iv = hexDecode("e0459b3474bdd0e44a41c144")
        let hp = hexDecode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        let keys = PacketKeys(key, iv, hp, secret: secret, chacha: true)
        let packet = PacketBuilder.shortHeader([], 654360564, 3, keys, [1])
        @Expect(hexEncode(packet), "4cfe4189655e5cd55c41f69080575d7999c25a5bfb")
        let opened = PacketBuilder.openShort(packet, 0, keys, 654360563)
        @Expect(opened.pn, 654360564)
        @Expect(hexEncode(opened.payload), "01")
        let next = PacketCrypto.nextKeys(keys, HashAlg.Sha256, 32)
        @Expect(hexEncode(next.secret), "1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
        @Expect(hexEncode(next.hp), hexEncode(hp))
    }

    @TestCase
    func retryIntegrityCoverage() {
        let dcid = hexDecode("8394c8f03e515708")
        let retry = hexDecode("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba")
        @Expect(PacketCrypto.verifyRetry(dcid, retry), true)
        retry[15] ^= 1
        @Expect(PacketCrypto.verifyRetry(dcid, retry), false)
    }
}
