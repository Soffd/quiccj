package quic.transport

import quic.crypto.*
import std.collection.HashSet

/*
 * QUIC v1 packet layer: varints, packet protection, header protection,
 * Initial secrets and transport parameters.
 */

public const QUIC_V1: UInt32 = 0x00000001
public const QUIC_V2: UInt32 = 0x6b3343cf

func packetType(bits: Int64, version: UInt32): Int64 {
    return if (version == QUIC_V2) { (bits + 3) & 3 } else { bits }
}

func keyLabelPrefix(version: UInt32): String {
    return if (version == QUIC_V2) { "quicv2 " } else { "quic " }
}

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
    public let secret: Array<UInt8>
    public let chacha: Bool
    public let backend: CryptoBackend
    public let version: UInt32

    public init(key: Array<UInt8>, iv: Array<UInt8>, hp: Array<UInt8>, secret!: Array<UInt8> = [],
        chacha!: Bool = false, backend!: CryptoBackend = PURE_CRYPTO, version!: UInt32 = QUIC_V1) {
        this.key = key
        this.iv = iv
        this.hp = hp
        this.secret = secret
        this.chacha = chacha
        this.backend = backend
        this.version = version
    }

    public static func copyOf(o: PacketKeys): PacketKeys {
        return PacketKeys(o.key, o.iv, o.hp, secret: o.secret, chacha: o.chacha, backend: o.backend, version: o.version)
    }
}

public class Aead {
    private let key: Array<UInt8>
    private let chacha: Bool
    private let backend: CryptoBackend

    public init(key: Array<UInt8>, chacha!: Bool = false, backend!: CryptoBackend = PURE_CRYPTO) {
        this.key = key
        this.chacha = chacha
        this.backend = backend
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
        backend.seal(chacha, key, nonce(pn, iv), header, packet, payloadOff, payloadLen)
    }

    public func open(pn: Int64, iv: Array<UInt8>, header: Array<UInt8>, packet: Array<UInt8>,
        payloadOff: Int64, payloadLen: Int64, tagOff: Int64): Bool {
        return backend.openPacket(chacha, key, nonce(pn, iv), header, packet, payloadOff, payloadLen, tagOff)
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
    public var validReservedBits: Bool = true
    public var phase: Bool = false
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
        let kind = if (space == 0) { 0 } else if (space == 1) { 2 } else { 1 }
        let typeBits = if (keys.version == QUIC_V2) { (kind + 1) & 3 } else { kind }
        let w = ByteWriter(64)
        w.putU8(0xC0 | (UInt8(typeBits) << 4) | UInt8(pnl - 1))
        w.putU32(keys.version)
        w.putU8(UInt8(dcid.size))
        w.putBytes(dcid)
        w.putU8(UInt8(scid.size))
        w.putBytes(scid)
        if (space == 0) {
            Varint.write(w, UInt64(token.size))
            w.putBytes(token)
        }
        let lengthVal = longLength(w.size, pnl + payload.size + 16, padTo)
        let padLen = lengthVal - pnl - payload.size - 16
        Varint.write(w, UInt64(lengthVal))
        let pnOffset = w.size
        encodePn(w, pn, pnl)
        let header = w.toArray()
        let packet = Array<UInt8>(header.size + payload.size + padLen + 16, repeat: 0)
        copyBytes(packet, 0, header, 0, header.size)
        copyBytes(packet, header.size, payload, 0, payload.size)
        let aead = Aead(keys.key, chacha: keys.chacha, backend: keys.backend)
        aead.seal(pn, keys.iv, header, packet, header.size, payload.size + padLen)
        let mask = keys.backend.headerMask(keys.chacha, keys.hp, sliceBytes(packet, pnOffset + 4, 16))
        HeaderProtection.apply(packet, pnOffset, pnl, mask, true)
        return packet
    }

    private static func longLength(prefix: Int64, body: Int64, padTo: Int64): Int64 {
        let unpadded = prefix + Varint.size(UInt64(body)) + body
        if (unpadded >= padTo) {
            return body
        }
        var length = padTo - prefix - Varint.size(UInt64(body))
        // Padding can widen Length's varint. Use the smallest body that
        // satisfies the target without oscillating at a varint boundary.
        while (length > body && prefix + Varint.size(UInt64(length - 1)) + length - 1 >= padTo) {
            length--
        }
        return length
    }

    static func connectionPacketSize(space: Int64, dcid: Int64, scid: Int64, token: Int64,
        payload: Int64, shortHeader: Bool): Int64 {
        let body = 4 + payload + 16
        if (shortHeader) {
            return 1 + dcid + body
        }
        let tokenField = if (space == 0) { Varint.size(UInt64(token)) + token } else { 0 }
        let prefix = 7 + dcid + scid + tokenField
        let length = longLength(prefix, body, if (space == 0) { MAX_DATAGRAM } else { 0 })
        return prefix + Varint.size(UInt64(length)) + length
    }

    /** Build a short header (1-RTT) packet. */
    public static func shortHeader(dcid: Array<UInt8>, pn: Int64, pnl: Int64,
        keys: PacketKeys, payload: Array<UInt8>, phase!: Bool = false): Array<UInt8> {
        let w = ByteWriter(64)
        w.putU8(0x40 | UInt8(pnl - 1) | (if (phase) { 4 } else { 0 }))
        w.putBytes(dcid)
        let pnOffset = w.size
        encodePn(w, pn, pnl)
        let header = w.toArray()
        let packet = Array<UInt8>(header.size + payload.size + 16, repeat: 0)
        copyBytes(packet, 0, header, 0, header.size)
        copyBytes(packet, header.size, payload, 0, payload.size)
        let aead = Aead(keys.key, chacha: keys.chacha, backend: keys.backend)
        aead.seal(pn, keys.iv, header, packet, header.size, payload.size)
        let mask = keys.backend.headerMask(keys.chacha, keys.hp, sliceBytes(packet, pnOffset + 4, 16))
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
        out.version = beU32(input, 1)
        out.typeBits = packetType(Int64((b0 >> 4) & 0x03), out.version)
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
        let mask = keys.backend.headerMask(keys.chacha, keys.hp, sliceBytes(input, pnOffset + 4, 16))
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
        if (!Aead(keys.key, chacha: keys.chacha, backend: keys.backend).open(out.pn, keys.iv, out.header, body, 0, payloadLen, payloadLen)) {
            throw Exception("packet authentication failed")
        }
        let reservedMask: UInt8 = if (longHeader) { 0x0c } else { 0x18 }
        out.validReservedBits = (firstByte & reservedMask) == 0
        out.phase = !longHeader && (firstByte & 4) != 0
        out.payload = sliceBytes(body, 0, payloadLen)
        return out
    }
}

/** QUIC v1 initial salt. */
private let INITIAL_SALT: String = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"

public class PacketCrypto {
    /** RFC 9001 section 5.8 integrity tag over ODCID and the complete Retry header. */
    public static func verifyRetry(originalDcid: Array<UInt8>, packet: Array<UInt8>,
        version!: UInt32 = QUIC_V1): Bool {
        if (packet.size < 16 || originalDcid.size > 20) {
            return false
        }
        let pseudo = ByteWriter(packet.size + originalDcid.size + 1)
        pseudo.putVec8(originalDcid)
        pseudo.putBytes(packet, 0, packet.size - 16)
        let key = hexDecode(if (version == QUIC_V2) { "8fb4b01b56ac48e260fbcbcead7ccc92" } else {
            "be0c690b9f66575a1d766b54e368c84e"
        })
        let nonce = hexDecode(if (version == QUIC_V2) { "d86969bc2d7c6d9990efb04a" } else {
            "461599d35d632bf2239825bb"
        })
        return AesGcm(key).open(nonce, pseudo.toArray(), [], 0, 0, packet, packet.size - 16)
    }

    public static func initialSecrets(dcid: Array<UInt8>, backend!: CryptoBackend = PURE_CRYPTO,
        version!: UInt32 = QUIC_V1): (PacketKeys, PacketKeys) {
        let salt = hexDecode(if (version == QUIC_V2) {
            "0dede3def700a6db819381be6e269dcbf9bd2ed9"
        } else {
            INITIAL_SALT
        })
        let initialSecret = hkdfExtract(HashAlg.Sha256, salt, dcid, backend: backend)
        let clientSecret = hkdfExpandLabel(HashAlg.Sha256, initialSecret, "client in",
            [], 32, backend: backend)
        let serverSecret = hkdfExpandLabel(HashAlg.Sha256, initialSecret, "server in",
            [], 32, backend: backend)
        return (fromSecret(clientSecret, backend: backend, version: version),
            fromSecret(serverSecret, backend: backend, version: version))
    }

    public static func fromSecret(secret: Array<UInt8>, backend!: CryptoBackend = PURE_CRYPTO,
        version!: UInt32 = QUIC_V1): PacketKeys {
        let prefix = keyLabelPrefix(version)
        let key = hkdfExpandLabel(HashAlg.Sha256, secret, prefix + "key",
            [], 16, backend: backend)
        let iv = hkdfExpandLabel(HashAlg.Sha256, secret, prefix + "iv",
            [], 12, backend: backend)
        let hp = hkdfExpandLabel(HashAlg.Sha256, secret, prefix + "hp",
            [], 16, backend: backend)
        return PacketKeys(key, iv, hp, secret: secret, backend: backend, version: version)
    }

    /** RFC 9001 §6: derive from the traffic secret and keep the header protection key. */
    public static func nextKeys(cur: PacketKeys, alg: HashAlg, keyLen: Int64): PacketKeys {
        if (cur.secret.size != hashSize(alg)) {
            throw Exception("missing QUIC traffic secret")
        }
        let backend = cur.backend
        let prefix = keyLabelPrefix(cur.version)
        let secret = hkdfExpandLabel(alg, cur.secret, prefix + "ku", [], hashSize(alg), backend: backend)
        let key = hkdfExpandLabel(alg, secret, prefix + "key", [], keyLen, backend: backend)
        let iv = hkdfExpandLabel(alg, secret, prefix + "iv", [], 12, backend: backend)
        return PacketKeys(key, iv, cur.hp, secret: secret, chacha: cur.chacha, backend: backend, version: cur.version)
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
    public var initialMaxStreamsUni: UInt64 = 32
    public var ackDelayExponent: UInt64 = 3
    public var maxAckDelay: UInt64 = 25
    public var disableActiveMigration: Bool = false
    public var activeConnectionIdLimit: UInt64 = 2
    public var initialSourceConnectionId: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var originalDestinationConnectionId: Array<UInt8> = Array<UInt8>(0, repeat: 0)
    public var statelessResetToken: Array<UInt8> = []
    public var chosenVersion: UInt32 = 0
    public var availableVersions: Array<UInt32> = []
    public var retrySourceConnectionId: Array<UInt8> = []
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
            putBytesParam(w, 0x0c, [])
        }
        putInt(w, 0x0e, activeConnectionIdLimit)
        putBytesParam(w, 0x0f, initialSourceConnectionId)
        if (chosenVersion != 0) {
            let versions = ByteWriter(4 * (availableVersions.size + 1))
            versions.putU32(chosenVersion)
            for (version in availableVersions) {
                versions.putU32(version)
            }
            putBytesParam(w, 0x11, versions.toArray())
        }
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
        p.maxIdleTimeout = 0
        p.maxUdpPayloadSize = 65527
        p.initialMaxData = 0
        p.initialMaxStreamDataBidiLocal = 0
        p.initialMaxStreamDataBidiRemote = 0
        p.initialMaxStreamDataUni = 0
        p.initialMaxStreamsBidi = 0
        p.initialMaxStreamsUni = 0
        let r = ByteReader(data)
        let seen = HashSet<UInt64>()
        while (!r.eof()) {
            let id = Varint.read(r)
            if (seen.contains(id)) {
                throw Exception("duplicate QUIC transport parameter")
            }
            seen.add(id)
            let len = Int64(Varint.read(r))
            let val = r.readBytes(len)
            if (id == 0x01) {
                p.maxIdleTimeout = readVarint(val)
            } else if (id == 0x02) {
                if (val.size != 16) {
                    throw Exception("invalid stateless reset token")
                }
                p.statelessResetToken = val
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
                if (len != 0) {
                    throw Exception("invalid disable_active_migration length")
                }
                p.disableActiveMigration = true
            } else if (id == 0x0e) {
                p.activeConnectionIdLimit = readVarint(val)
            } else if (id == 0x0f) {
                p.initialSourceConnectionId = val
            } else if (id == 0x00) {
                p.originalDestinationConnectionId = val
            } else if (id == 0x10) {
                p.retrySourceConnectionId = val
            } else if (id == 0x11) {
                if (val.size < 4 || val.size % 4 != 0) {
                    throw Exception("invalid version_information length")
                }
                let versions = ByteReader(val)
                p.chosenVersion = versions.readU32()
                p.availableVersions = Array<UInt32>(versions.remaining() / 4, repeat: 0)
                if (p.chosenVersion == 0) {
                    throw Exception("invalid chosen version")
                }
                for (i in 0..p.availableVersions.size) {
                    let version = versions.readU32()
                    if (version == 0) {
                        throw Exception("invalid available version")
                    }
                    p.availableVersions[i] = version
                }
            } else if (id == 0x20) {
                p.initialMaxDatagramFrameSize = readVarint(val)
            }
        }
        if (p.activeConnectionIdLimit < 2 || p.ackDelayExponent > 20 || p.maxAckDelay >= 16384 || p.maxUdpPayloadSize < 1200 ||
            p.initialMaxStreamsBidi > 0x1000000000000000 || p.initialMaxStreamsUni > 0x1000000000000000) {
            throw Exception("invalid transport parameters")
        }
        return p
    }

    private static func readVarint(b: Array<UInt8>): UInt64 {
        let r = ByteReader(b)
        let result = Varint.read(r)
        if (!r.eof()) {
            throw Exception("invalid integer transport parameter length")
        }
        return result
    }
}
