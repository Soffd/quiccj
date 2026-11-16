package quic.transport

import quic.crypto.*
import std.collection.*

private class Segment {
    let offset: Int64
    let data: Array<UInt8>

    init(offset: Int64, data: Array<UInt8>) {
        this.offset = offset
        this.data = data
    }
}

// Retain only distinct byte ranges and release them when a gap is filled.
class ReceiveRanges {
    var offset: Int64 = 0
    private let segments = ArrayList<Segment>()

    func append(start: Int64, data: Array<UInt8>, output: ByteWriter): Unit {
        let end = start + data.size
        if (end <= offset) {
            return
        }
        var cursor = if (start < offset) { offset } else { start }
        var index = 0
        while (index < segments.size && cursor < end) {
            let segment = segments[index]
            if (cursor < segment.offset) {
                let stop = if (end < segment.offset) { end } else { segment.offset }
                segments.add(Segment(cursor, sliceBytes(data, cursor - start, stop - cursor)),
                    at: index)
                cursor = stop
                index++
                if (cursor == end) {
                    break
                }
            }
            let stop = segment.offset + segment.data.size
            if (stop > cursor) {
                cursor = stop
            }
            index++
        }
        if (cursor < end) {
            segments.add(Segment(cursor, sliceBytes(data, cursor - start, end - cursor)), at: index)
        }
        while (segments.size > 0 && segments[0].offset == offset) {
            let segment = segments.remove(at: 0)
            output.putBytes(segment.data)
            offset += segment.data.size
        }
    }
}
