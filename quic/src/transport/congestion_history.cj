package quic.transport

import std.collection.*

// Include both boundary words even when the retained packet range is unaligned.
private const ACK_WORDS: Int64 = ACK_HISTORY_SIZE / 64 + 1

private class AckHistory {
    private var latest = -1
    private let words = Array<UInt64>(ACK_WORDS, repeat: 0)
    private let tags = Array<Int64>(ACK_WORDS, repeat: -1)

    func sent(pn: Int64): Unit {
        latest = pn
    }

    func retained(pn: Int64): Bool {
        return pn > latest - ACK_HISTORY_SIZE
    }

    func ack(ranges: ArrayList<AckRange>): Unit {
        for (range in ranges) {
            let earliest = latest - ACK_HISTORY_SIZE + 1
            let low = if (range.low < earliest) { earliest } else { range.low }
            let high = if (range.high > latest) { latest } else { range.high }
            if (low > high) {
                continue
            }
            for (word in (low / 64)..=(high / 64)) {
                let i = word % ACK_WORDS
                if (tags[i] != word) {
                    tags[i] = word
                    words[i] = 0
                }
                var mask = UInt64.Max
                if (word == low / 64) {
                    mask = mask << (low % 64)
                }
                if (word == high / 64) {
                    mask &= UInt64.Max >> (63 - high % 64)
                }
                words[i] |= mask
            }
        }
    }

    func has(pn: Int64): Bool {
        let word = pn / 64
        let i = word % ACK_WORDS
        return tags[i] == word && ((words[i] >> (pn % 64)) & 1) != 0
    }
}

class CongestionPacket {
    let space: Int64
    let pn: Int64
    let time: Int64
    let ackEliciting: Bool
    let eligible: Bool
    var lost = false
    var discarded = false

    init(space: Int64, pn: Int64, time: Int64, ackEliciting: Bool, eligible: Bool) {
        this.space = space
        this.pn = pn
        this.time = time
        this.ackEliciting = ackEliciting
        this.eligible = eligible
    }
}

// A bounded, path-wide send history. An ACK (including a late ACK for a lost
// packet) in any number space interrupts the loss period. A packet whose fate
// cannot be established acts as a boundary instead of contributing evidence.
class CongestionHistory {
    private let entries = Array<Option<CongestionPacket>>(ACK_HISTORY_SIZE, repeat: None)
    private let acknowledged = [AckHistory(), AckHistory(), AckHistory()]
    private var count = 0
    private var ignoreBefore = 0

    func sent(packet: CongestionPacket): Unit {
        entries[count % ACK_HISTORY_SIZE] = Some(packet)
        acknowledged[packet.space].sent(packet.pn)
        count++
    }

    func ack(space: Int64, ranges: ArrayList<AckRange>): Unit {
        acknowledged[space].ack(ranges)
    }

    func resetPeriod(): Unit {
        ignoreBefore = count
    }

    func persistent(duration: Int64): Bool {
        let retainedFrom = count - ACK_HISTORY_SIZE
        let start = if (retainedFrom > ignoreBefore) { retainedFrom } else { ignoreBefore }
        var firstLoss: Int64 = -1
        for (i in start..count) {
            let packet = entries[i % ACK_HISTORY_SIZE].getOrThrow()
            let acks = acknowledged[packet.space]
            if (!packet.eligible || packet.discarded || !acks.retained(packet.pn) ||
                acks.has(packet.pn) || (packet.ackEliciting && !packet.lost)) {
                firstLoss = -1
            } else if (packet.lost) {
                if (firstLoss < 0) {
                    firstLoss = packet.time
                } else if (packet.time - firstLoss > duration) {
                    return true
                }
            }
        }
        return false
    }
}
