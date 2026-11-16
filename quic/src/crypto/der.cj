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
            if (n == 0 || n > 4 || p + n > end || data[p] == 0) {
                throw Exception("DER unsupported length")
            }
            len = 0
            var i = 0
            while (i < n) {
                len = (len << 8) | Int64(data[p])
                p++
                i++
            }
            if (len < 128) {
                throw Exception("DER length is not minimal")
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
        let off = t[1]
        let len = t[2]
        if (t[0] != 0x02 || len == 0 || (data[off] & 0x80) != 0) {
            throw Exception("DER: expected nonnegative INTEGER")
        }
        if (len > 1 && data[off] == 0) {
            if ((data[off + 1] & 0x80) == 0) {
                throw Exception("DER: nonminimal INTEGER")
            }
            return sliceBytes(data, off + 1, len - 1)
        }
        return sliceBytes(data, off, len)
    }

    public func readInt64(): Int64 {
        let b = readIntegerBytes()
        if (b.size > 8 || (b.size == 8 && (b[0] & 0x80) != 0)) {
            throw Exception("DER INTEGER exceeds Int64")
        }
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
        if (t[0] != 0x06 || t[2] == 0) {
            throw Exception("DER: expected nonempty OID")
        }
        let encoded = ByteReader(data, t[1], t[3])
        let first = readOidArc(encoded)
        var out = if (first < 80) {
            (first / 40).toString() + "." + (first % 40).toString()
        } else {
            "2." + (first - 80).toString()
        }
        while (!encoded.eof()) {
            out = out + "." + readOidArc(encoded).toString()
        }
        return out
    }

    private func readOidArc(encoded: ByteReader): Int64 {
        var byte = encoded.readU8()
        if (byte == 0x80) {
            throw Exception("DER: nonminimal OID component")
        }
        var value = Int64(byte & 0x7f)
        while ((byte & 0x80) != 0) {
            byte = encoded.readU8()
            let low = Int64(byte & 0x7f)
            if (value > (Int64.Max - low) / 128) {
                throw Exception("DER: OID component exceeds Int64")
            }
            value = value * 128 + low
        }
        return value
    }

    public func readBitString(): (Int64, Array<UInt8>) {
        let t = readTLV()
        if (t[0] != 0x03 || t[2] == 0) {
            throw Exception("DER: expected BIT STRING")
        }
        let unused = Int64(data[t[1]])
        if (unused > 7 || (t[2] == 1 && unused != 0) ||
            (Int64(data[t[3] - 1]) & ((1 << unused) - 1)) != 0) {
            throw Exception("DER: invalid BIT STRING padding")
        }
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
        if (t[0] != tag) {
            throw Exception("DER: unexpected string type")
        }
        return String.fromUtf8(sliceBytes(data, t[1], t[2]))
    }

    /** UTCTime / GeneralizedTime to Unix seconds. */
    public func readTime(): Int64 {
        let t = readTLV()
        let yearDigits = match (t[0]) {
            case 0x17 => 2
            case 0x18 => 4
            case _ => throw Exception("DER: expected certificate time")
        }
        if (t[2] != yearDigits + 11 || data[t[3] - 1] != 90) {
            throw Exception("DER: expected a UTC time with seconds")
        }
        let start = t[1]
        var year = readDigits(start, yearDigits)
        if (yearDigits == 2) {
            year += if (year >= 50) { 1900 } else { 2000 }
        }
        let offset = start + yearDigits
        let month = readDigits(offset, 2)
        let day = readDigits(offset + 2, 2)
        let hour = readDigits(offset + 4, 2)
        let minute = readDigits(offset + 6, 2)
        let second = readDigits(offset + 8, 2)
        let monthDays = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        if (year == 0 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) {
            throw Exception("DER: invalid certificate time")
        }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
        let days = monthDays[month - 1] + (if (month == 2 && leap) { 1 } else { 0 })
        if (day < 1 || day > days) {
            throw Exception("DER: invalid certificate calendar date")
        }
        return daysFromCivil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second
    }

    private func readDigits(offset: Int64, count: Int64): Int64 {
        var result = 0
        for (i in offset..(offset + count)) {
            let digit = data[i]
            if (digit < 48 || digit > 57) {
                throw Exception("DER: nondecimal certificate time")
            }
            result = result * 10 + Int64(digit - 48)
        }
        return result
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
