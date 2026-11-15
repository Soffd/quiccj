package quic.transport

import quic.crypto.*

/*
 * QUIC v1 packet layer: varints, packet protection, header protection,
 * Initial secrets and transport parameters.
 */

public const QUIC_V1: UInt32 = 0x00000001

/** QUIC variable-length integer. */
public class Varint {
    public static func size(v: UInt64): Int64 {
        if (v < 64) {
            return 1
        }
        if (v < 16384) {
            return 2
        }
        if (v < 1073741824) {
            return 4
        }
        return 8
    }

    public static func write(w: ByteWriter, v: UInt64): Unit {
        if (v < 64) {
            w.putU8(UInt8(v))
        } else if (v < 16384) {
            let x = UInt16(v) | 0x4000
            w.putU16(x)
        } else if (v < 1073741824) {
            let x = UInt32(v) | 0x80000000
            w.putU32(x)
        } else {
            let x = v | 0xC000000000000000
            w.putU32(UInt32(x >> 32))
            w.putU32(UInt32(x & 0xFFFF_FFFF))
        }
    }

    public static func read(r: ByteReader): UInt64 {
        let first = r.readU8()
        let prefix = Int64(first >> 6)
        if (prefix == 0) {
            return UInt64(first & 0x3F)
        }
        if (prefix == 1) {
            let b2 = r.readU8()
            return UInt64((UInt16(first & 0x3F) << 8) | UInt16(b2))
        }
        if (prefix == 2) {
            let rest = r.readBytes(3)
            return (UInt64(first & 0x3F) << 24) | (UInt64(rest[0]) << 16) |
                (UInt64(rest[1]) << 8) | UInt64(rest[2])
        }
        let rest = r.readBytes(7)
        var v: UInt64 = UInt64(first & 0x3F)
        var i = 0
        while (i < 7) {
            v = (v << 8) | UInt64(rest[i])
            i++
        }
        return v
    }
}

/** Keys for one packet number space / direction. */
public class PacketKeys {
    public var key: Array<UInt8>
    public var iv: Array<UInt8>
    public var hp: Array<UInt8>

    public init(key: Array<UInt8>, iv: Array<UInt8>, hp: Array<UInt8>) {
        this.key = key
        this.iv = iv
        this.hp = hp
    }

    public static func copyOf(o: PacketKeys): PacketKeys {
        return PacketKeys(o.key, o.iv, o.hp)
    }
}

public class Aead {
    private let gcm: AesGcm
    private let keyLen: Int64

    public init(key: Array<UInt8>) {
        gcm = AesGcm(key)
        keyLen = key.size
    }

    public func nonce(pn: Int64, iv: Array<UInt8>): Array<UInt8> {
        let n = Array<UInt8>(12, repeat: 0)
        copyBytes(n, 0, iv, 0, 12)
        let pnBytes = Array<UInt8>(8, repeat: 0)
        putBeU64(pnBytes, 0, UInt64(pn))
        var i = 0
        while (i < 8) {
            n[4 + i] = n[4 + i] ^ pnBytes[i]
            i++
        }
        return n
    }

    /** Encrypt payload in place and append the tag. */
    public func seal(pn: Int64, iv: Array<UInt8>, header: Array<UInt8>, packet: Array<UInt8>,
        payloadOff: Int64, payloadLen: Int64): Unit {
        let tag = Array<UInt8>(16, repeat: 0)
        gcm.seal(nonce(pn, iv), header, packet, payloadOff, payloadLen, tag, 0)
        copyBytes(packet, payloadOff + payloadLen, tag, 0, 16)
    }

    public func open(pn: Int64, iv: Array<UInt8>, header: Array<UInt8>, packet: Array<UInt8>,
        payloadOff: Int64, payloadLen: Int64, tagOff: Int64): Bool {
        return gcm.open(nonce(pn, iv), header, packet, payloadOff, payloadLen, packet, tagOff)
    }
}

/** Header protection using AES-ECB (RFC 9001 §5.4.3). */
public class HeaderProtection {
    public static func mask(hpKey: Array<UInt8>, sample: Array<UInt8>): Array<UInt8> {
        let aes = Aes(hpKey)
        let out = Array<UInt8>(16, repeat: 0)
        aes.encryptBlock(sample, 0, out, 0)
        return out
    }

    public static func apply(packet: Array<UInt8>, pnOffset: Int64, pnLen: Int64,
        mask: Array<UInt8>, longHeader: Bool): Unit {
        if (longHeader) {
            packet[0] = packet[0] ^ (mask[0] & 0x0F)
        } else {
            packet[0] = packet[0] ^ (mask[0] & 0x1F)
        }
        var i = 0
        while (i < pnLen) {
            packet[pnOffset + i] = packet[pnOffset + i] ^ mask[1 + i]
            i++
        }
    }
}

/** Stateless parsers are shared by the connection and the golden-packet tests. */
public class ParsedPacket {
    public var longHeader: Bool = true
    public var typeBits: Int64 = 0
    public var version: UInt32 = 0
    public var dcid: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var scid: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var token: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var pn: Int64 = 0
    public var pnLen: Int64 = 0
    public var header: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var payload: Array<UInt8> = Array<UInt8>(0, repeat: 0)
}

/** Builds and opens QUIC packets without any connection state (RFC 9000 §17, RFC 9001 §5). */
public class PacketBuilder {
    public static func encodePn(w: ByteWriter, pn: Int64, pnl: Int64): Unit {
        var i = pnl - 1
        while (i >= 0) {
            w.putU8(UInt8((pn >> UInt64(i * 8)) & 0xFF))
            i--
        }
    }

    /**
     * Assemble one long header packet (Initial, Handshake or 0-RTT).
     * `padTo` is the target total packet size; the payload is zero padded (PADDING
     * frames) so the datagram reaches the QUIC minimum size.
     */
    public static func longHeader(space: Int64, dcid: Array<UInt8>, scid: Array<UInt8>,
        token: Array<UInt8>, pn: Int64, pnl: Int64, keys: PacketKeys, payload: Array<UInt8>,
        padTo: Int64): Array<UInt8> {
        // RFC 9000 section 17.2 long header types: Initial=00, 0-RTT=01,
        // Handshake=10, Retry=11.
        let typeBits: UInt8 = if (space == 0) {
            0x00
        } else if (space == 1) {
            0x20
        } else {
            0x10
        }
        let w = ByteWriter(64)
        w.putU8(0xC0 | typeBits | UInt8(pnl - 1))
        w.putU32(QUIC_V1)
        w.putU8(UInt8(dcid.size))
        w.putBytes(dcid)
        w.putU8(UInt8(scid.size))
        w.putBytes(scid)
        if (space == 0) {
            Varint.write(w, UInt64(token.size))
            w.putBytes(token)
        }
        // The Length field covers PN + payload (including padding) + tag, so its
        // own encoded size and the padding amount depend on each other. Iterate
        // to the fixed point (at most one extra round in practice).
        let h0 = w.size
        var vs: Int64 = 1
        var lengthVal: Int64 = 0
        var i = 0
        while (i < 4) {
            let unpadded = h0 + vs + pnl + payload.size + 16
            let target = if (padTo > unpadded) {
                padTo
            } else {
                unpadded
            }
            lengthVal = target - h0 - vs
            let need = Varint.size(UInt64(lengthVal))
            if (need == vs) {
                break
            }
            vs = need
            i++
        }
        let padLen = lengthVal - pnl - payload.size - 16
        Varint.write(w, UInt64(lengthVal))
        let pnOffset = w.size
        encodePn(w, pn, pnl)
        let header = w.toArray()
        let packet = Array<UInt8>(header.size + payload.size + padLen + 16, repeat: 0)
        copyBytes(packet, 0, header, 0, header.size)
        copyBytes(packet, header.size, payload, 0, payload.size)
        let aead = Aead(keys.key)
        aead.seal(pn, keys.iv, header, packet, header.size, payload.size + padLen)
        let mask = HeaderProtection.mask(keys.hp, sliceBytes(packet, pnOffset + 4, 16))
        HeaderProtection.apply(packet, pnOffset, pnl, mask, true)
        return packet
    }

    /** Build a short header (1-RTT) packet. */
    public static func shortHeader(dcid: Array<UInt8>, pn: Int64, pnl: Int64,
        keys: PacketKeys, payload: Array<UInt8>): Array<UInt8> {
        let w = ByteWriter(64)
        w.putU8(0x40 | UInt8(pnl - 1))
        w.putBytes(dcid)
        let pnOffset = w.size
        encodePn(w, pn, pnl)
        let header = w.toArray()
        let packet = Array<UInt8>(header.size + payload.size + 16, repeat: 0)
        copyBytes(packet, 0, header, 0, header.size)
        copyBytes(packet, header.size, payload, 0, payload.size)
        let aead = Aead(keys.key)
        aead.seal(pn, keys.iv, header, packet, header.size, payload.size)
        let mask = HeaderProtection.mask(keys.hp, sliceBytes(packet, pnOffset + 4, 16))
        HeaderProtection.apply(packet, pnOffset, pnl, mask, false)
        return packet
    }

    /** RFC 9000 §17.1 packet number reconstruction. */
    public static func decodePn(trunk: Int64, pnl: Int64, largest: Int64): Int64 {
        let expected = largest + 1
        let window: Int64 = 1 << (pnl * 8)
        let half = window / 2
        var candidate = (expected & !(window - 1)) | trunk
        if (candidate + half <= expected) {
            candidate = candidate + window
        } else if (candidate > expected + half && candidate >= window) {
            candidate = candidate - window
        }
        return candidate
    }

    /** Remove header protection and authenticate one long header packet. */
    public static func openLong(input: Array<UInt8>, keys: PacketKeys,
        largest: Int64): ParsedPacket {
        let out = ParsedPacket()
        let b0 = input[0]
        out.longHeader = (b0 & 0x80) != 0
        out.typeBits = Int64((b0 >> 4) & 0x03)
        out.version = beU32(input, 1)
        let dcil = Int64(input[5])
        out.dcid = sliceBytes(input, 6, dcil)
        var p = 6 + dcil
        let scil = Int64(input[p])
        out.scid = sliceBytes(input, p + 1, scil)
        p = p + 1 + scil
        if (out.typeBits == 0) {
            let tr = ByteReader(input, p, input.size)
            let tokenLen = Int64(Varint.read(tr))
            out.token = sliceBytes(input, tr.pos, tokenLen)
            p = tr.pos + tokenLen
        }
        let lr = ByteReader(input, p, input.size)
        let lengthVal = Int64(Varint.read(lr))
        let pnOffset = lr.pos
        return finishOpen(out, input, pnOffset, lengthVal, keys, true, pnOffset + lengthVal,
            largest)
    }

    /** Remove header protection and authenticate one short header packet. */
    public static func openShort(input: Array<UInt8>, dcidLen: Int64, keys: PacketKeys,
        largest: Int64): ParsedPacket {
        let out = ParsedPacket()
        out.longHeader = false
        let pnOffset = 1 + dcidLen
        out.dcid = sliceBytes(input, 1, dcidLen)
        return finishOpen(out, input, pnOffset, input.size - pnOffset, keys, false, input.size,
            largest)
    }

    private static func finishOpen(out: ParsedPacket, input: Array<UInt8>, pnOffset: Int64,
        lengthVal: Int64, keys: PacketKeys, longHeader: Bool, packetEnd: Int64,
        largest: Int64): ParsedPacket {
        if (pnOffset + 4 + 16 > input.size) {
            throw Exception("packet too short for header protection sample")
        }
        let mask = HeaderProtection.mask(keys.hp, sliceBytes(input, pnOffset + 4, 16))
        // RFC 9001 section 5.4.1: unmask the first byte, then read the packet
        // number length from its low two bits.
        let maskedBits: UInt8 = if (longHeader) {
            0x0F
        } else {
            0x1F
        }
        let firstByte = input[0] ^ (mask[0] & maskedBits)
        let pnl = Int64(firstByte & 0x03) + 1
        let work = sliceBytes(input, 0, packetEnd)
        work[0] = firstByte
        var i = 0
        while (i < pnl) {
            work[pnOffset + i] = input[pnOffset + i] ^ mask[1 + i]
            i++
        }
        out.pnLen = pnl
        var trunk: Int64 = 0
        i = 0
        while (i < pnl) {
            trunk = (trunk << 8) | Int64(work[pnOffset + i])
            i++
        }
        out.pn = decodePn(trunk, pnl, largest)
        out.header = sliceBytes(work, 0, pnOffset + pnl)
        let payloadLen = lengthVal - pnl - 16
        if (payloadLen < 0) {
            throw Exception("negative payload length")
        }
        let body = Array<UInt8>(payloadLen + 16, repeat: 0)
        copyBytes(body, 0, work, pnOffset + pnl, payloadLen + 16)
        if (!Aead(keys.key).open(out.pn, keys.iv, out.header, body, 0, payloadLen, payloadLen)) {
            throw Exception("packet authentication failed")
        }
        out.payload = sliceBytes(body, 0, payloadLen)
        return out
    }
}

/** QUIC v1 initial salt. */
private let INITIAL_SALT: String = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"

public class PacketCrypto {
    public static func initialSecrets(dcid: Array<UInt8>): (PacketKeys, PacketKeys) {
        let salt = hexDecode(INITIAL_SALT)
        let initialSecret = hkdfExtract(HashAlg.Sha256, salt, dcid)
        let clientSecret = hkdfExpandLabel(HashAlg.Sha256, initialSecret, "client in",
            Array<UInt8>(0, repeat: 0), 32)
        let serverSecret = hkdfExpandLabel(HashAlg.Sha256, initialSecret, "server in",
            Array<UInt8>(0, repeat: 0), 32)
        return (fromSecret(clientSecret), fromSecret(serverSecret))
    }

    public static func fromSecret(secret: Array<UInt8>): PacketKeys {
        let key = hkdfExpandLabel(HashAlg.Sha256, secret, "quic key",
            Array<UInt8>(0, repeat: 0), 16)
        let iv = hkdfExpandLabel(HashAlg.Sha256, secret, "quic iv",
            Array<UInt8>(0, repeat: 0), 12)
        let hp = hkdfExpandLabel(HashAlg.Sha256, secret, "quic hp",
            Array<UInt8>(0, repeat: 0), 16)
        return PacketKeys(key, iv, hp)
    }

    /** Update keys for a key phase flip. */
    public static func nextKeys(cur: PacketKeys, alg: HashAlg, keyLen: Int64): PacketKeys {
        let secret = hkdfExpandLabel(alg, cur.key, "quic ku", Array<UInt8>(0, repeat: 0),
            hashSize(alg))
        let key = hkdfExpandLabel(alg, secret, "quic key", Array<UInt8>(0, repeat: 0), keyLen)
        let iv = hkdfExpandLabel(alg, secret, "quic iv", Array<UInt8>(0, repeat: 0), 12)
        let hp = hkdfExpandLabel(alg, secret, "quic hp", Array<UInt8>(0, repeat: 0), 16)
        return PacketKeys(key, iv, hp)
    }
}

/** Transport parameters (RFC 9000 §18). */
public class TransportParams {
    public var maxIdleTimeout: UInt64 = 30000
    public var maxUdpPayloadSize: UInt64 = 1200
    public var initialMaxData: UInt64 = 1048576
    public var initialMaxStreamDataBidiLocal: UInt64 = 262144
    public var initialMaxStreamDataBidiRemote: UInt64 = 262144
    public var initialMaxStreamDataUni: UInt64 = 262144
    public var initialMaxStreamsBidi: UInt64 = 16
    public var initialMaxStreamsUni: UInt64 = 16
    public var ackDelayExponent: UInt64 = 3
    public var maxAckDelay: UInt64 = 25
    public var disableActiveMigration: Bool = false
    public var activeConnectionIdLimit: UInt64 = 2
    public var initialSourceConnectionId: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var originalDestinationConnectionId: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var initialMaxDatagramFrameSize: UInt64 = 0

    public func encode(): Array<UInt8> {
        let w = ByteWriter(128)
        putInt(w, 0x01, maxIdleTimeout)
        putInt(w, 0x03, maxUdpPayloadSize)
        putInt(w, 0x04, initialMaxData)
        putInt(w, 0x05, initialMaxStreamDataBidiLocal)
        putInt(w, 0x06, initialMaxStreamDataBidiRemote)
        putInt(w, 0x07, initialMaxStreamDataUni)
        putInt(w, 0x08, initialMaxStreamsBidi)
        putInt(w, 0x09, initialMaxStreamsUni)
        putInt(w, 0x0a, ackDelayExponent)
        putInt(w, 0x0b, maxAckDelay)
        if (disableActiveMigration) {
            putInt(w, 0x0c, 0)
        }
        putInt(w, 0x0e, activeConnectionIdLimit)
        putBytesParam(w, 0x0f, initialSourceConnectionId)
        if (initialMaxDatagramFrameSize > 0) {
            putInt(w, 0x20, initialMaxDatagramFrameSize)
        }
        return w.toArray()
    }

    private static func putInt(w: ByteWriter, id: UInt64, v: UInt64): Unit {
        let val = ByteWriter(8)
        Varint.write(val, v)
        Varint.write(w, id)
        Varint.write(w, UInt64(val.size))
        w.putBytes(val.toArray())
    }

    private static func putBytesParam(w: ByteWriter, id: UInt64, data: Array<UInt8>): Unit {
        Varint.write(w, id)
        Varint.write(w, UInt64(data.size))
        w.putBytes(data)
    }

    public static func decode(data: Array<UInt8>): TransportParams {
        let p = TransportParams()
        let r = ByteReader(data)
        while (!r.eof()) {
            let id = Varint.read(r)
            let len = Int64(Varint.read(r))
            let val = r.readBytes(len)
            if (id == 0x01) {
                p.maxIdleTimeout = readVarint(val)
            } else if (id == 0x03) {
                p.maxUdpPayloadSize = readVarint(val)
            } else if (id == 0x04) {
                p.initialMaxData = readVarint(val)
            } else if (id == 0x05) {
                p.initialMaxStreamDataBidiLocal = readVarint(val)
            } else if (id == 0x06) {
                p.initialMaxStreamDataBidiRemote = readVarint(val)
            } else if (id == 0x07) {
                p.initialMaxStreamDataUni = readVarint(val)
            } else if (id == 0x08) {
                p.initialMaxStreamsBidi = readVarint(val)
            } else if (id == 0x09) {
                p.initialMaxStreamsUni = readVarint(val)
            } else if (id == 0x0a) {
                p.ackDelayExponent = readVarint(val)
            } else if (id == 0x0b) {
                p.maxAckDelay = readVarint(val)
            } else if (id == 0x0c) {
                p.disableActiveMigration = true
            } else if (id == 0x0e) {
                p.activeConnectionIdLimit = readVarint(val)
            } else if (id == 0x0f) {
                p.initialSourceConnectionId = val
            } else if (id == 0x00) {
                p.originalDestinationConnectionId = val
            } else if (id == 0x20) {
                p.initialMaxDatagramFrameSize = readVarint(val)
            }
        }
        return p
    }

    private static func readVarint(b: Array<UInt8>): UInt64 {
        let r = ByteReader(b)
        return Varint.read(r)
    }
}
