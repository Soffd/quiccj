package quic.crypto

/** Growable byte writer used by every protocol encoder in this stack. */
public class ByteWriter {
    private var buf: Array<UInt8>
    private var len: Int64

    public init() {
        buf = Array<UInt8>(256, repeat: 0)
        len = 0
    }

    public init(capacity: Int64) {
        buf = Array<UInt8>(capacity, repeat: 0)
        len = 0
    }

    private func ensure(extra: Int64): Unit {
        if (len + extra <= buf.size) {
            return
        }
        var cap = buf.size * 2
        while (cap < len + extra) {
            cap = cap * 2
        }
        let nb = Array<UInt8>(cap, repeat: 0)
        copyBytes(nb, 0, buf, 0, len)
        buf = nb
    }

    public func putU8(v: UInt8): Unit {
        ensure(1)
        buf[len] = v
        len++
    }

    public func putU16(v: UInt16): Unit {
        ensure(2)
        putBeU16(buf, len, v)
        len = len + 2
    }

    public func putU24(v: UInt32): Unit {
        ensure(3)
        putBeU24(buf, len, v)
        len = len + 3
    }

    public func putU32(v: UInt32): Unit {
        ensure(4)
        putBeU32(buf, len, v)
        len = len + 4
    }

    public func putBytes(data: Array<UInt8>): Unit {
        ensure(data.size)
        copyBytes(buf, len, data, 0, data.size)
        len = len + data.size
    }

    public func putBytes(data: Array<UInt8>, off: Int64, count: Int64): Unit {
        ensure(count)
        copyBytes(buf, len, data, off, count)
        len = len + count
    }

    /** 16-bit length prefix followed by the bytes. */
    public func putVec16(data: Array<UInt8>): Unit {
        putU16(UInt16(data.size))
        putBytes(data)
    }

    /** 24-bit length prefix followed by the bytes. */
    public func putVec24(data: Array<UInt8>): Unit {
        putU24(UInt32(data.size))
        putBytes(data)
    }

    public func putVec8(data: Array<UInt8>): Unit {
        putU8(UInt8(data.size))
        putBytes(data)
    }

    public prop size: Int64 {
        get() {
            len
        }
    }

    public func toArray(): Array<UInt8> {
        return sliceBytes(buf, 0, len)
    }

    /** Overwrite a previously written area (used for length backpatching). */
    public func patchU16(off: Int64, v: UInt16): Unit {
        putBeU16(buf, off, v)
    }

    public func patchU24(off: Int64, v: UInt32): Unit {
        putBeU24(buf, off, v)
    }

    public func clear(): Unit {
        len = 0
    }
}

/** Simple cursor reader with bounds checks. */
public class ByteReader {
    public var data: Array<UInt8>
    public var pos: Int64
    public var end: Int64

    public init(data: Array<UInt8>) {
        this.data = data
        pos = 0
        end = data.size
    }

    public init(data: Array<UInt8>, off: Int64, end: Int64) {
        this.data = data
        pos = off
        this.end = end
    }

    public func remaining(): Int64 {
        return end - pos
    }

    public func eof(): Bool {
        return pos >= end
    }

    public func readU8(): UInt8 {
        if (pos + 1 > end) {
            throw Exception("buffer underflow")
        }
        let v = data[pos]
        pos++
        return v
    }

    public func readU16(): UInt16 {
        if (pos + 2 > end) {
            throw Exception("buffer underflow")
        }
        let v = beU16(data, pos)
        pos = pos + 2
        return v
    }

    public func readU24(): UInt32 {
        if (pos + 3 > end) {
            throw Exception("buffer underflow")
        }
        let v = beU24(data, pos)
        pos = pos + 3
        return v
    }

    public func readU32(): UInt32 {
        if (pos + 4 > end) {
            throw Exception("buffer underflow")
        }
        let v = beU32(data, pos)
        pos = pos + 4
        return v
    }

    public func readBytes(n: Int64): Array<UInt8> {
        if (pos + n > end) {
            throw Exception("buffer underflow")
        }
        let v = sliceBytes(data, pos, n)
        pos = pos + n
        return v
    }

    public func readVec8(): Array<UInt8> {
        let n = Int64(readU8())
        return readBytes(n)
    }

    public func readVec16(): Array<UInt8> {
        let n = Int64(readU16())
        return readBytes(n)
    }

    public func readVec24(): Array<UInt8> {
        let n = Int64(readU24())
        return readBytes(n)
    }
}
