package quic.http3

import quic.crypto.*
import std.collection.*

let DECODER_CAPACITY: Int64 = 4096

class QpackDecoder {
    private let entries = ArrayList<H3Header>()
    private var bytes: Int64 = 0
    private var capacity: Int64 = 0
    var inserts: Int64 = 0

    func fields(block: Array<UInt8>): (Array<H3Header>, Int64) {
        return decodeFields(block, DECODER_CAPACITY / 32, inserts, { index => at(index) })
    }

    private func at(absoluteIndex: Int64): H3Header {
        let index = absoluteIndex - (inserts - entries.size)
        if (index < 0 || index >= entries.size) {
            throw Exception("QPACK dynamic entry unavailable")
        }
        return entries[index]
    }

    private func sizeOf(entry: H3Header): Int64 {
        return 32 + entry.name.toArray().size + entry.value.toArray().size
    }

    private func evict(extra: Int64): Unit {
        while (bytes + extra > capacity) {
            bytes -= sizeOf(entries.remove(at: 0))
        }
    }

    func instruction(r: ByteReader): Unit {
        let first = r.readU8()
        let entry = H3Header()
        if ((first & 0x80) != 0) {
            let index = readPrefixed(r, first, 6)
            entry.name = if ((first & 0x40) != 0) { staticHeader(index).name } else {
                at(inserts - index - 1).name
            }
            entry.value = decodeString(r)
        } else if ((first & 0x40) != 0) {
            let length = readPrefixed(r, first, 5)
            entry.name = decodeText(r.readBytes(length), (first & 0x20) != 0)
            entry.value = decodeString(r)
        } else if ((first & 0x20) != 0) {
            let limit = readPrefixed(r, first, 5)
            if (limit > DECODER_CAPACITY) {
                throw Exception("QPACK capacity exceeds SETTINGS")
            }
            capacity = limit
            evict(0)
            return
        } else {
            let index = readPrefixed(r, first, 5)
            let duplicate = at(inserts - index - 1)
            entry.name = duplicate.name
            entry.value = duplicate.value
        }
        let size = sizeOf(entry)
        if (size > capacity || entry.name == "") {
            throw Exception("invalid QPACK insertion")
        }
        evict(size)
        bytes += size
        entries.add(entry)
        inserts++
    }
}
