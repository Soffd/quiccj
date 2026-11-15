package quic.crypto

/*
 * Minimal DER reader sufficient for X.509 / TLS structures.
 */

public class Der {
    public var data: Array<UInt8>
    public var pos: Int64
    public var end: Int64

    public init(data: Array<UInt8>, pos: Int64, end: Int64) {
        this.data = data
        this.pos = pos
        this.end = end
    }

    public static func parse(data: Array<UInt8>): Der {
        return Der(data, 0, data.size)
    }

    public func eof(): Bool {
        return pos >= end
    }

    public func peekTag(): Int64 {
        if (eof()) {
            return -1
        }
        return Int64(data[pos])
    }

    public func remaining(): Int64 {
        return end - pos
    }

    /** Read one TLV; returns (tag, contentOff, contentLen, nextPos). */
    public func readTLV(): (Int64, Int64, Int64, Int64) {
        if (pos + 2 > end) {
            throw Exception("DER truncated")
        }
        let tag = Int64(data[pos])
        var p = pos + 1
        var len = Int64(data[p])
        p++
        if ((len & 0x80) != 0) {
            let n = len & 0x7F
            if (n == 0 || n > 4) {
                throw Exception("DER unsupported length")
            }
            len = 0
            var i = 0
            while (i < n) {
                len = (len << 8) | Int64(data[p])
                p++
                i++
            }
        }
        if (p + len > end) {
            throw Exception("DER length out of range")
        }
        let result = (tag, p, len, p + len)
        pos = p + len
        return result
    }

    /** Enter the next element as a child reader, expecting `tag`. */
    public func enter(expectedTag: Int64): Der {
        let t = readTLV()
        if (t[0] != expectedTag) {
            throw Exception("DER: expected tag ${expectedTag}, got ${t[0]}")
        }
        return Der(data, t[1], t[1] + t[2])
    }

    public func enterAny(): (Der, Int64) {
        let t = readTLV()
        return (Der(data, t[1], t[1] + t[2]), t[0])
    }

    public func readContent(): Array<UInt8> {
        let t = readTLV()
        return sliceBytes(data, t[1], t[2])
    }

    public func readIntegerBytes(): Array<UInt8> {
        let t = readTLV()
        var off = t[1]
        var len = t[2]
        // strip leading zero sign byte(s)
        while (len > 1 && data[off] == 0) {
            off++
            len--
        }
        return sliceBytes(data, off, len)
    }

    public func readInt64(): Int64 {
        let b = readIntegerBytes()
        var v: Int64 = 0
        var i = 0
        while (i < b.size) {
            v = (v << 8) | Int64(b[i])
            i++
        }
        return v
    }

    public func readOid(): String {
        let t = readTLV()
        if (t[0] != 0x06) {
            throw Exception("DER: expected OID")
        }
        let off = t[1]
        let len = t[2]
        if (len == 0) {
            return ""
        }
        let first = Int64(data[off])
        var out: String
        if (first >= 80) {
            out = "2.${first - 80}"
        } else {
            out = "${first / 40}.${first % 40}"
        }
        var i = 1
        var v: Int64 = 0
        var started = false
        while (i < len) {
            let b = data[off + i]
            v = (v << 7) | Int64(b & 0x7F)
            started = true
            if ((b & 0x80) == 0) {
                out = out + "." + "${v}"
                v = 0
                started = false
            }
            i++
        }
        if (started) {
            out = out + "." + "${v}"
        }
        return out
    }

    public func readBitString(): (Int64, Array<UInt8>) {
        let t = readTLV()
        if (t[0] != 0x03) {
            throw Exception("DER: expected BIT STRING")
        }
        let unused = Int64(data[t[1]])
        return (unused, sliceBytes(data, t[1] + 1, t[2] - 1))
    }

    public func readOctetString(): Array<UInt8> {
        let t = readTLV()
        if (t[0] != 0x04) {
            throw Exception("DER: expected OCTET STRING")
        }
        return sliceBytes(data, t[1], t[2])
    }

    public func readString(tag: Int64): String {
        let t = readTLV()
        return String.fromUtf8(sliceBytes(data, t[1], t[2]))
    }

    /** UTCTime / GeneralizedTime to Unix seconds. */
    public func readTime(): Int64 {
        let t = readTLV()
        let s = String.fromUtf8(sliceBytes(data, t[1], t[2]))
        let raw = s.toArray()
        var year = 0
        var idx = 0
        if (t[0] == 0x17) {
            // YYMMDDHHMMSSZ
            year = 2000 + Int64((raw[0] - 48) * 10 + (raw[1] - 48))
            idx = 2
        } else {
            // YYYYMMDDHHMMSSZ
            year = 0
            var k = 0
            while (k < 4) {
                year = year * 10 + Int64(raw[k] - 48)
                k++
            }
            idx = 4
        }
        let month = Int64(raw[idx] - 48) * 10 + Int64(raw[idx + 1] - 48)
        let day = Int64(raw[idx + 2] - 48) * 10 + Int64(raw[idx + 3] - 48)
        let hour = Int64(raw[idx + 4] - 48) * 10 + Int64(raw[idx + 5] - 48)
        let minute = Int64(raw[idx + 6] - 48) * 10 + Int64(raw[idx + 7] - 48)
        let second = Int64(raw[idx + 8] - 48) * 10 + Int64(raw[idx + 9] - 48)
        return daysFromCivil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second
    }

    private func daysFromCivil(y: Int64, m: Int64, d: Int64): Int64 {
        var year = y
        if (m <= 2) {
            year = year - 1
        }
        let era = (if (year >= 0) { year } else { year - 399 }) / 400
        let yoe = year - era * 400
        let mp = if (m > 2) { m - 3 } else { m + 9 }
        let doy = (153 * mp + 2) / 5 + d - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146097 + doe - 719468
    }
}
