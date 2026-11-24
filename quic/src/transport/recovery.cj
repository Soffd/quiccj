package quic.transport

import quic.crypto.*
import std.collection.*

const ACK_HISTORY_SIZE: Int64 = 4096

const MIN_WINDOW: Int64 = 2400
const MAX_DATAGRAM: Int64 = 1200
const INITIAL_WINDOW: Int64 = 12000

class AckRange {
    let low: Int64
    let high: Int64

    init(low: Int64, high: Int64) {
        this.low = low
        this.high = high
    }
}

class AckRanges {
    static func decode(r: ByteReader, nextPn: Int64): (ArrayList<AckRange>, Int64) {
        let largest = Int64(Varint.read(r))
        let delay = Int64(Varint.read(r))
        let count = Int64(Varint.read(r))
        let first = Int64(Varint.read(r))
        if (largest >= nextPn || first > largest || count > r.remaining() / 2) {
            throw Exception("invalid ACK range")
        }
        let ranges = ArrayList<AckRange>()
        var low = largest - first
        ranges.add(AckRange(low, largest))
        for (_ in 0..count) {
            let gap = Int64(Varint.read(r))
            let length = Int64(Varint.read(r))
            let high = low - gap - 2
            if (high < length) {
                throw Exception("invalid ACK gap")
            }
            low = high - length
            ranges.add(AckRange(low, high))
        }
        return (ranges, delay)
    }
}

// Packet numbers are consumed before protection. A failed socket write
// creates a gap that must not be mistaken for an acknowledged packet.
class SentNumbers {
    private var largest: Int64 = -1
    private let skipped = ArrayList<AckRange>()

    func sent(pn: Int64): Unit {
        let oldest = pn - ACK_HISTORY_SIZE + 1
        while (skipped.size > 0 && skipped[0].high < oldest) {
            skipped.remove(at: 0)
        }
        if (pn > largest + 1) {
            let start = if (largest + 1 < oldest) { oldest } else { largest + 1 }
            skipped.add(AckRange(start, pn - 1))
        }
        largest = pn
    }

    func decodeAck(r: ByteReader): (ArrayList<AckRange>, Int64) {
        let (ranges, delay) = AckRanges.decode(r, largest + 1)
        var index = skipped.size - 1
        for (range in ranges) {
            while (index >= 0 && skipped[index].low > range.high) {
                index--
            }
            if (index >= 0 && skipped[index].high >= range.low) {
                throw Exception("ACK acknowledges an unsent packet")
            }
        }
        return (ranges, delay)
    }
}

// Every copy of a retransmitted frame shares its delivery state.
class RecoveryFrame {
    let bytes: Array<UInt8>
    var delivered = false
    var inFlight = 0
    let mtuProbe: Bool
    let retransmittable: Bool

    init(bytes: Array<UInt8>, retransmittable!: Bool = true, mtuProbe!: Bool = false) {
        this.mtuProbe = mtuProbe
        this.bytes = bytes
        this.retransmittable = retransmittable
    }
}

class SentPacket {
    let pn: Int64
    let time: Int64
    let size: Int64
    let frame: RecoveryFrame
    var ect = false
    let history: CongestionPacket

    init(pn: Int64, time: Int64, size: Int64, frame: RecoveryFrame, history: CongestionPacket) {
        this.pn = pn
        this.time = time
        this.size = size
        this.frame = frame
        this.history = history
    }
}

class RecoverySpace {
    let sent = ArrayList<SentPacket>()
    let pending = LinkedList<RecoveryFrame>()
    var largestAcked = -1
    var lastSent = -1
}

class LossRecovery {
    let spaces = [RecoverySpace(), RecoverySpace(), RecoverySpace()]
    var bytesInFlight = 0
    var window = INITIAL_WINDOW
    private var history = CongestionHistory()
    private var pacer = SendPacer()
    private var lossSinceAck = false
    var persistentCongestionEvents: Int64 = 0
    private var threshold = Int64.Max
    private var recoveryStart = -1
    private var latestRtt = 0
    private var minRtt = Int64.Max
    var srtt = 333
    var packetsLost: Int64 = 0
    var largePacketLost = false
    private var variance = 166
    private var ptoCount = 0
    private var avoidanceCredit = 0

    func newPath(now: Int64): Unit {
        for (space in 0..3) {
            let state = spaces[space]
            for (packet in state.sent) {
                bytesInFlight -= packet.size
                packet.frame.inFlight--
                if (packet.frame.retransmittable && !packet.frame.delivered && packet.frame.inFlight == 0) {
                    state.pending.addLast(packet.frame)
                }
            }
            state.sent.clear()
        }
        history = CongestionHistory()
        pacer = SendPacer()
        lossSinceAck = false
        window = INITIAL_WINDOW
        threshold = Int64.Max
        recoveryStart = now - 1
        latestRtt = 0
        minRtt = Int64.Max
        srtt = 333
        variance = 166
        ptoCount = 0
        avoidanceCredit = 0
    }

    func pacingDelay(now: Int64, size: Int64): Int64 {
        return pacer.delay(now, size, window, srtt)
    }

    func sent(space: Int64, pn: Int64, time: Int64, size: Int64, frame: RecoveryFrame,
        timeMicros!: Int64 = -1, ect!: Bool = false): Unit {
        let entry = CongestionPacket(space, pn, time, true, minRtt != Int64.Max)
        history.sent(entry)
        if (timeMicros >= 0) {
            pacer.sent(timeMicros, size, window, srtt)
        }
        let packet = SentPacket(pn, time, size, frame, entry)
        packet.ect = ect
        spaces[space].sent.add(packet)
        spaces[space].lastSent = time
        frame.inFlight++
        bytesInFlight += size
    }

    func sentNonEliciting(space: Int64, pn: Int64, time: Int64): Unit {
        history.sent(CongestionPacket(space, pn, time, false, minRtt != Int64.Max))
    }

    func discard(space: Int64): Unit {
        for (p in spaces[space].sent) {
            p.history.discarded = true
            bytesInFlight -= p.size
            p.frame.inFlight--
        }
        spaces[space].sent.clear()
        spaces[space].pending.clear()
        spaces[space].largestAcked = -1
        spaces[space].lastSent = -1
        ptoCount = 0
    }

    var newlyAckedEct: Int64 = 0
    var lastEctSentTime: Int64 = -1

    func ecnCongestion(now: Int64): Unit {
        if (lastEctSentTime > recoveryStart) {
            window = if (window / 2 < MIN_WINDOW) { MIN_WINDOW } else { window / 2 }
            threshold = window
            recoveryStart = now
            avoidanceCredit = 0
        }
    }

    func ack(space: Int64, ranges: ArrayList<AckRange>, delay: Int64, now: Int64,
        maxAckDelay!: Int64 = 0): Unit {
        newlyAckedEct = 0
        lastEctSentTime = -1
        history.ack(space, ranges)
        let state = spaces[space]
        let largest = ranges[0].high
        if (largest > state.largestAcked) {
            state.largestAcked = largest
            for (p in state.sent) {
                if (p.pn == largest) {
                    updateRtt(now - p.time, delay)
                    break
                }
            }
        }
        var i = 0
        while (i < state.sent.size) {
            let p = state.sent[i]
            var acknowledged = false
            for (range in ranges) {
                if (p.pn >= range.low && p.pn <= range.high) {
                    acknowledged = true
                    break
                }
            }
            if (acknowledged) {
                if (p.ect) {
                    newlyAckedEct++
                    if (p.time > lastEctSentTime) { lastEctSentTime = p.time }
                }
                state.sent.remove(at: i)
                bytesInFlight -= p.size
                p.frame.inFlight--
                p.frame.delivered = true
                ptoCount = 0
                if (p.time > recoveryStart) {
                    if (window < threshold) {
                        window += p.size
                    } else {
                        avoidanceCredit += p.size * MAX_DATAGRAM
                        let increase = avoidanceCredit / window
                        avoidanceCredit %= window
                        window += increase
                    }
                }
            } else {
                i++
            }
        }
        detectLoss(space, now)
        if (lossSinceAck && history.persistent(3 * pto(maxAckDelay))) {
            window = MIN_WINDOW
            // Return to slow start until reaching the threshold from the loss event.
            recoveryStart = now
            minRtt = latestRtt
            avoidanceCredit = 0
            history.resetPeriod()
            persistentCongestionEvents++
        }
        lossSinceAck = false
    }

    private func updateRtt(sample: Int64, delay: Int64): Unit {
        latestRtt = if (sample < 1) { 1 } else { sample }
        if (minRtt == Int64.Max) {
            minRtt = latestRtt
            srtt = latestRtt
            variance = srtt / 2
            return
        }
        if (latestRtt < minRtt) {
            minRtt = latestRtt
        }
        let adjusted = if (latestRtt - minRtt >= delay) { latestRtt - delay } else { latestRtt }
        let difference = if (srtt > adjusted) { srtt - adjusted } else { adjusted - srtt }
        variance = (3 * variance + difference) / 4
        srtt = (7 * srtt + adjusted) / 8
    }

    func detectLoss(space: Int64, now: Int64): Unit {
        let state = spaces[space]
        let rtt = if (latestRtt > srtt) { latestRtt } else { srtt }
        let lossDelay = (9 * rtt + 7) / 8
        var i = 0
        while (i < state.sent.size) {
            let p = state.sent[i]
            if (p.pn < state.largestAcked &&
                (p.pn + 3 <= state.largestAcked || now - p.time >= lossDelay)) {
                state.sent.remove(at: i)
                p.history.lost = true
                packetsLost++
                if (p.frame.mtuProbe) {
                    p.history.discarded = true
                    bytesInFlight -= p.size
                    p.frame.inFlight--
                    continue
                }
                if (p.size > 1200) { largePacketLost = true }
                lossSinceAck = true
                bytesInFlight -= p.size
                p.frame.inFlight--
                if (p.frame.retransmittable && !p.frame.delivered && p.frame.inFlight == 0) {
                    state.pending.addLast(p.frame)
                }
                if (p.time > recoveryStart) {
                    window = if (window / 2 < MIN_WINDOW) { MIN_WINDOW } else { window / 2 }
                    threshold = window
                    recoveryStart = now
                    avoidanceCredit = 0
                }
            } else {
                i++
            }
        }
    }

    func pto(maxAckDelay: Int64): Int64 {
        let variation = if (variance == 0) { 1 } else { 4 * variance }
        return srtt + variation + maxAckDelay
    }

    func probeSpace(now: Int64, confirmed: Bool, maxAckDelay: Int64): Int64 {
        var result = -1
        var earliest = Int64.Max
        for (space in 0..3) {
            let state = spaces[space]
            if (state.sent.size == 0 || (space == 2 && !confirmed)) {
                continue
            }
            let extra = if (space == 2) { maxAckDelay } else { 0 }
            let deadline = state.lastSent + (pto(extra) << ptoCount)
            if (deadline < earliest) {
                earliest = deadline
                result = space
            }
        }
        if (now < earliest) {
            return -1
        }
        return result
    }

    func probeSent(): Unit {
        if (ptoCount < 10) {
            ptoCount++
        }
    }

    func probe(space: Int64): RecoveryFrame {
        for (p in spaces[space].sent) {
            if (p.frame.retransmittable && !p.frame.delivered) {
                return p.frame
            }
        }
        return RecoveryFrame([1])
    }
}
