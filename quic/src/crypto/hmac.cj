package quic.crypto

/*
 * HMAC (RFC 2104) + HKDF (RFC 5869) + TLS 1.3 HKDF-Expand-Label (RFC 8446 7.1).
 */

public enum HashAlg {
    | Sha256
    | Sha384
}

public func hashSize(alg: HashAlg): Int64 {
    match (alg) {
        case Sha256 => 32
        case Sha384 => 48
    }
}

public func hashOf(alg: HashAlg, data: Array<UInt8>): Array<UInt8> {
    match (alg) {
        case Sha256 => sha256(data)
        case Sha384 => sha384(data)
    }
}

public func hmac(alg: HashAlg, key: Array<UInt8>, data: Array<UInt8>): Array<UInt8> {
    // HMAC block size is the hash's internal block size: 64 for SHA-256 and
    // 128 for SHA-384/512 (RFC 2104 section 2).
    let blockSize = match (alg) {
        case Sha256 => 64
        case Sha384 => 128
    }
    var k = key
    if (k.size > blockSize) {
        k = hashOf(alg, k)
    }
    let inner = Array<UInt8>(blockSize + data.size, repeat: 0x36)
    var i = 0
    while (i < k.size) {
        inner[i] = k[i] ^ 0x36
        i++
    }
    copyBytes(inner, blockSize, data, 0, data.size)
    let innerHash = hashOf(alg, inner)
    let outer = Array<UInt8>(blockSize + innerHash.size, repeat: 0x5c)
    i = 0
    while (i < k.size) {
        outer[i] = k[i] ^ 0x5c
        i++
    }
    copyBytes(outer, blockSize, innerHash, 0, innerHash.size)
    let result = hashOf(alg, outer)
    fillBytes(inner, 0)
    fillBytes(outer, 0)
    return result
}

/** HKDF-Extract(salt, ikm) -> PRK */
public func hkdfExtract(alg: HashAlg, salt: Array<UInt8>, ikm: Array<UInt8>): Array<UInt8> {
    let zeroSalt = Array<UInt8>(hashSize(alg), repeat: 0)
    let realSalt = if (salt.size == 0) { zeroSalt } else { salt }
    return hmac(alg, realSalt, ikm)
}

/** HKDF-Expand(prk, info, length) */
public func hkdfExpand(alg: HashAlg, prk: Array<UInt8>, info: Array<UInt8>,
    length: Int64): Array<UInt8> {
    let hlen = hashSize(alg)
    if (length > 255 * hlen) {
        throw Exception("hkdf: requested length too large")
    }
    let out = Array<UInt8>(length, repeat: 0)
    var t = Array<UInt8>(0, repeat: 0)
    var pos = 0
    var counter: UInt8 = 1
    while (pos < length) {
        let input = Array<UInt8>(t.size + info.size + 1, repeat: 0)
        copyBytes(input, 0, t, 0, t.size)
        copyBytes(input, t.size, info, 0, info.size)
        input[input.size - 1] = counter
        t = hmac(alg, prk, input)
        let take = if (length - pos < hlen) { length - pos } else { hlen }
        copyBytes(out, pos, t, 0, take)
        pos = pos + take
        counter = counter + 1
    }
    return out
}

public func hkdf(alg: HashAlg, salt: Array<UInt8>, ikm: Array<UInt8>, info: Array<UInt8>,
    length: Int64): Array<UInt8> {
    return hkdfExpand(alg, hkdfExtract(alg, salt, ikm), info, length)
}

/**
 * TLS 1.3 HKDF-Expand-Label:
 *   struct {
 *       uint16 length;
 *       opaque label<7..255> = "tls13 " + Label;
 *       opaque context<0..255> = Context;
 *   } HkdfLabel;
 */
public func hkdfExpandLabel(alg: HashAlg, secret: Array<UInt8>, label: String,
    context: Array<UInt8>, length: Int64): Array<UInt8> {
    let fullLabel = "tls13 " + label
    let labelBytes = fullLabel.toArray()
    if (labelBytes.size > 255 || context.size > 255) {
        throw Exception("hkdfExpandLabel: label/context too long")
    }
    let info = Array<UInt8>(2 + 1 + labelBytes.size + 1 + context.size, repeat: 0)
    putBeU16(info, 0, UInt16(length))
    info[2] = UInt8(labelBytes.size)
    copyBytes(info, 3, labelBytes, 0, labelBytes.size)
    info[3 + labelBytes.size] = UInt8(context.size)
    copyBytes(info, 4 + labelBytes.size, context, 0, context.size)
    return hkdfExpand(alg, secret, info, length)
}

/** TLS 1.3 Derive-Secret(Secret, Label, Messages) */
public func deriveSecret(alg: HashAlg, secret: Array<UInt8>, label: String,
    transcriptHash: Array<UInt8>): Array<UInt8> {
    return hkdfExpandLabel(alg, secret, label, transcriptHash, hashSize(alg))
}
