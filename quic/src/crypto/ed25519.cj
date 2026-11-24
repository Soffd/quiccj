package quic.crypto

// RFC 8032 public signature verification. All field elements are in Montgomery form.
private let edPrime = BigUint.fromBytesBE(hexDecode("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"), 8)
private let edField = MontCtx(edPrime.w, 8)
private let edOrder = BigUint.fromBytesBE(hexDecode("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"), 8)
private let edD = edField.toMont(BigUint.fromBytesBE(hexDecode("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"), 8))
private let sqrtMinusOne = edField.toMont(BigUint.fromBytesBE(hexDecode("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0"), 8))
private let sqrtExponent = BigUint.fromBytesBE(hexDecode("0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"), 8)

private class EdwardsPoint {
    let x: BigUint
    let y: BigUint
    let z: BigUint
    let t: BigUint

    init(x: BigUint, y: BigUint, z: BigUint, t: BigUint) {
        this.x = x
        this.y = y
        this.z = z
        this.t = t
    }

    func plus(other: EdwardsPoint): EdwardsPoint {
        let f = edField
        let a = f.mul(f.sub(y, x), f.sub(other.y, other.x))
        let b = f.mul(f.add(y, x), f.add(other.y, other.x))
        let dt = f.mul(edD, f.mul(t, other.t))
        let c = f.add(dt, dt)
        let zz = f.mul(z, other.z)
        let d = f.add(zz, zz)
        let e = f.sub(b, a)
        let h = f.add(b, a)
        let lo = f.sub(d, c)
        let hi = f.add(d, c)
        return EdwardsPoint(f.mul(e, lo), f.mul(hi, h), f.mul(lo, hi), f.mul(e, h))
    }

    func scale(s: BigUint): EdwardsPoint {
        var r = EdwardsPoint(BigUint(8), edField.one(), edField.one(), BigUint(8))
        var i = s.bitLen() - 1
        while (i >= 0) {
            r = r.plus(r)
            if (s.bit(i)) { r = r.plus(this) }
            i--
        }
        return r
    }

    func equals(other: EdwardsPoint): Bool {
        return edField.mul(x, other.z).cmp(edField.mul(other.x, z)) == 0 &&
            edField.mul(y, other.z).cmp(edField.mul(other.y, z)) == 0
    }
}

private let edIdentity: EdwardsPoint = EdwardsPoint(BigUint(8), edField.one(), edField.one(), BigUint(8))

private func decodeEdPoint(encoded: Array<UInt8>): Option<EdwardsPoint> {
    let bytes = encoded.clone()
    let negative = (bytes[31] & 128) != 0
    bytes[31] &= 127
    let value = BigUint.fromBytesLE(bytes, 8)
    if (value.cmp(edPrime) >= 0) { return None }
    let f = edField
    let y = f.toMont(value)
    let yy = f.mul(y, y)
    let denominator = f.add(f.mul(edD, yy), f.one())
    if (denominator.isZero()) { return None }
    let square = f.mul(f.sub(yy, f.one()), f.inverse(denominator))
    var x = f.pow(square, sqrtExponent)
    if (f.mul(x, x).cmp(square) != 0) { x = f.mul(x, sqrtMinusOne) }
    if (f.mul(x, x).cmp(square) != 0 || (negative && x.isZero())) { return None }
    if (f.fromMont(x).isOdd() != negative) { x = f.negate(x) }
    return Some(EdwardsPoint(x, y, f.one(), f.mul(x, y)))
}

private let edBase = decodeEdPoint(hexDecode("5866666666666666666666666666666666666666666666666666666666666666")).getOrThrow()

func verifyEd25519(key: Array<UInt8>, msg: Array<UInt8>, sig: Array<UInt8>): Bool {
    if (key.size != 32 || sig.size != 64) { return false }
    let s = BigUint.fromBytesLE(sig[32..64], 8)
    if (s.cmp(edOrder) >= 0) { return false }
    let publicPoint = decodeEdPoint(key)
    let noncePoint = decodeEdPoint(sig[0..32])
    if (publicPoint.isNone() || noncePoint.isNone()) { return false }
    let a = publicPoint.getOrThrow()
    if (a.equals(edIdentity) || !a.scale(edOrder).equals(edIdentity)) { return false }
    // With a prime-order public key, the uncofactored equation also checks membership of R.
    let hash = sha512(concat3(sig[0..32], key, msg))
    return edBase.scale(s).equals(noncePoint.getOrThrow().plus(a.scale(BigUint.fromBytesLE(hash, 16))))
}
