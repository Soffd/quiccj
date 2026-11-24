package quic.transport

import std.collection.ArrayList
import quic.crypto.ByteWriter

private class ReceivedRange {
    var low: Int64
    var high: Int64
    init(pn: Int64) { low = pn; high = pn }
}

/** Newest first. Evicted packet numbers can never become deliverable a second time. */
class ReceivedPackets {
    private let ranges = ArrayList<ReceivedRange>()
    private let limit: Int64
    private var floor = -1
    init(limit: Int64) { this.limit = limit }

    func record(pn: Int64): Bool {
        if (pn <= floor) { return false }
        var i = 0
        while (i < ranges.size && pn < ranges[i].low - 1) { i++ }
        if (i == ranges.size || pn > ranges[i].high + 1) {
            ranges.add(ReceivedRange(pn), at: i)
        } else {
            let current = ranges[i]
            if (pn >= current.low && pn <= current.high) { return false }
            if (pn > current.high) { current.high = pn } else { current.low = pn }
            if (i + 1 < ranges.size && current.low == ranges[i + 1].high + 1) {
                current.low = ranges.remove(at: i + 1).low
            }
        }
        if (ranges.size > limit) {
            floor = ranges.remove(at: ranges.size - 1).high
        }
        return pn > floor
    }

    func encode(delay!: UInt64 = 0, ecn!: Option<Array<UInt64>> = None): Array<UInt8> {
        if (ranges.isEmpty()) { return [] }
        let pairs = ByteWriter()
        var count = 0
        for (i in 1..ranges.size) {
            let gap = UInt64(ranges[i - 1].low - ranges[i].high - 2)
            let span = UInt64(ranges[i].high - ranges[i].low)
            if (pairs.size + 16 > 1100) { break }
            Varint.write(pairs, gap)
            Varint.write(pairs, span)
            count++
        }
        let frame = ByteWriter()
        frame.putU8(if (ecn.isSome()) { 3 } else { 2 })
        Varint.write(frame, UInt64(ranges[0].high))
        Varint.write(frame, delay)
        Varint.write(frame, UInt64(count))
        Varint.write(frame, UInt64(ranges[0].high - ranges[0].low))
        frame.putBytes(pairs.toArray())
        if (let Some(counts) <- ecn) {
            for (value in counts) { Varint.write(frame, value) }
        }
        return frame.toArray()
    }
}
