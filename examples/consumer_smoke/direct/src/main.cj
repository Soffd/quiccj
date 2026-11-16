package consumer_direct

import quic.crypto.TrustStore
import quic.http3.Http3Client
import std.convert.Parsable

main(args: Array<String>): Int64 {
    if (args.size != 3) {
        println("usage: consumer_direct HOST PORT CA_FILE")
        return 2
    }
    try {
        let port = UInt16.parse(args[1])
        let trust = TrustStore.fromFile(args[2])
        if (let Some(client) <- Http3Client.connect(args[0], port, trust, true, 8000)) {
            try {
                let response = client.get("/")
                if (!response.complete) {
                    println("incomplete response")
                    return 1
                }
                println("status=" + response.status.toString())
                print(String.fromUtf8(response.body))
                return 0
            } finally {
                client.conn.closeConnection("consumer smoke test")
            }
        }
        println("handshake failed")
    } catch (e: Exception) {
        println(e.message)
    }
    return 1
}
