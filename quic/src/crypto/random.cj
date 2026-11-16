package quic.crypto

import std.fs.*

/** Linux and Android OS randomness. A failed CSPRNG read fails the connection. */
public func randomBytes(n: Int64): Array<UInt8> {
    let out = Array<UInt8>(n, repeat: 0)
    if (n == 0) {
        return out
    }
    let file = File("/dev/urandom", OpenMode.Read)
    try {
        var offset = file.read(out)
        while (offset < n) {
            let rest = Array<UInt8>(n - offset, repeat: 0)
            let count = file.read(rest)
            if (count <= 0) {
                throw Exception("OS randomness unavailable")
            }
            copyBytes(out, offset, rest, 0, count)
            offset += count
        }
        return out
    } finally {
        file.close()
    }
}
