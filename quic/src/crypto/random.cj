package quic.crypto

@When[os != "Windows"]
foreign func getentropy(output: CPointer<UInt8>, length: UIntNative): Int32

@When[os == "Windows"]
foreign func rand_s(output: CPointer<UInt32>): Int32

/** Read directly from the operating system CSPRNG. */
@When[os != "Windows"]
public func randomBytes(n: Int64): Array<UInt8> {
    let out = Array<UInt8>(n, repeat: 0)
    unsafe {
        let data = acquireArrayRawData(out)
        try {
            var offset = 0
            while (offset < n) {
                let size = if (n - offset > 256) { 256 } else { n - offset }
                if (getentropy(data.pointer + offset, UIntNative(size)) != 0) {
                    throw Exception("OS random generator failed")
                }
                offset += size
            }
        } finally { releaseArrayRawData(data) }
    }
    return out
}

@When[os == "Windows"]
public func randomBytes(n: Int64): Array<UInt8> {
    let out = Array<UInt8>(n, repeat: 0)
    var word: UInt32 = 0
    for (i in 0..n) {
        if (i % 4 == 0 && unsafe { rand_s(inout word) } != 0) { throw Exception("OS random generator failed") }
        out[i] = UInt8(word & 255)
        word >>= 8
    }
    return out
}
