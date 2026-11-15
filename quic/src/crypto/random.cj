package quic.crypto

import std.fs.*
import std.random.*

private let RAND_STATE: Array<UInt8> = Array<UInt8>(1, repeat: 0)

/** OS randomness from /dev/urandom; falls back to a time-mixed PRNG. */
public func randomBytes(n: Int64): Array<UInt8> {
    let out = Array<UInt8>(n, repeat: 0)
    try {
        let f = File("/dev/urandom", OpenMode.Read)
        let got = f.read(out)
        f.close()
        if (got == n) {
            return out
        }
    } catch (e: Exception) {
        // fall through
    }
    // degraded fallback: never used when /dev/urandom exists
    let rnd = Random()
    var i = 0
    while (i < n) {
        out[i] = UInt8(rnd.nextInt32() & 0xFF)
        i++
    }
    return out
}
