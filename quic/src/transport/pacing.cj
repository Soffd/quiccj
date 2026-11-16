package quic.transport

/** Byte-credit pacer updated from the path's congestion window and smoothed RTT. */
class SendPacer {
    private var updatedAt: Int64 = -1
    private var credit: Float64 = 0.0
    private var rate: Float64 = 0.0
    private var burst: Float64 = 0.0

    private func update(now: Int64, window: Int64, rttMs: Int64): Unit {
        let capacity = window / 4
        let maxBurst = if (capacity > INITIAL_WINDOW) { INITIAL_WINDOW } else if (capacity < MIN_WINDOW) {
            MIN_WINDOW
        } else {
            capacity
        }
        burst = Float64(maxBurst)
        if (updatedAt < 0) {
            credit = burst
        } else if (now > updatedAt) {
            credit += Float64(now - updatedAt) * rate
        }
        updatedAt = now
        if (credit > burst) {
            credit = burst
        }
        rate = 1.25 * Float64(window) / (1000.0 * Float64(rttMs))
    }

    func delay(now: Int64, bytes: Int64, window: Int64, rttMs: Int64): Int64 {
        update(now, window, rttMs)
        if (credit >= Float64(bytes)) {
            return 0
        }
        let exact = (Float64(bytes) - credit) / rate
        let whole = Int64(exact)
        return if (Float64(whole) < exact) { whole + 1 } else { whole }
    }

    func sent(now: Int64, bytes: Int64, window: Int64, rttMs: Int64): Unit {
        update(now, window, rttMs)
        credit -= Float64(bytes)
        // PTO probes can borrow credit. Bound the resulting pacing delay.
        if (credit < -burst) {
            credit = -burst
        }
    }
}
