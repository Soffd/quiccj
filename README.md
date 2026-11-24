# quiccj

quiccj 是供仓颉应用嵌入的 QUIC v1/v2 和 HTTP/3 客户端库。核心包提供包保护、同步驱动的 QUIC 连接和流，以及 HTTP/3 GET 和 POST。TLS 和 QUIC 连接默认使用 OpenSSL 3。纯仓颉后端需要按连接显式选择。

## 功能

- **QUIC** 支持 Initial、Handshake、0-RTT 和 1-RTT、ACK 范围、CRYPTO 和 STREAM 重组、连接及流级流控、RTT 和 PTO、包阈值及时间阈值重传、NewReno 拥塞控制、发送节奏控制、持续拥塞检测、Retry、版本协商、密钥轮换、本地 UDP 路径迁移、保活、QUIC DATAGRAM 和可配置的接收窗口。Linux 提供批量接收、ECN 和路径 MTU 探测。
- **TLS 1.3** 支持 X25519、使用 P-256 的 HelloRetryRequest、ECDSA、RSA-PSS 和 Ed25519 CertificateVerify、AES-GCM 和 ChaCha20-Poly1305、证书验证、客户端证书、会话票据和显式启用的 0-RTT。OpenSSL 提供 ML-KEM-768 时默认提供 X25519MLKEM768。
- **HTTP/3** 支持 SETTINGS、GET、POST、流式与整段响应、同源连接池、Alt-Svc、PRIORITY_UPDATE、GOAWAY、服务器推送，以及 QPACK 静态表、Huffman 和动态表。请求编码器可以复用 `:authority`，并遵守对端的阻塞流额度。
- **信任配置** 由调用方传入 `TrustStore`。应用可加载 PEM 信任根，也可调用 `TrustStore.system()` 读取系统信任源。支持通过 `SSL_CERT_FILE` 和 `SSL_CERT_DIR` 指定信任根，按策略验证 CRL 或 OCSP staple。

## 构建与验证

在 WSL Ubuntu 上使用仓颉工具链 1.2.1。

```bash
(cd quic && cjpm build && cjpm test)
(cd quic_openssl && cjpm test)          # 需要 OpenSSL 3 运行库
(cd examples/h3get && cjpm build)
```

构造 `NativeCryptoBackend` 或建立默认连接时加载 OpenSSL 3。可通过 `NativeCryptoBackend(path: ...)` 或 `QUICCJ_LIBCRYPTO` 指定共享库的绝对路径。默认后端加载失败会报告错误。Unicode 主机名还需要 libidn2。旧的 `quic_openssl.OpenSslBackend` 名称仍可使用。

## 命令行示例

```bash
cd examples/h3get
./target/release/bin/main cloudflare-quic.com / 443
./target/release/bin/main cloudflare-quic.com / 443 system openssl
./target/release/bin/main localhost / 4433 ../../interop/cert.pem
```

参数依次为 `host`、`path`、`port`、信任配置和密码学后端。信任配置可以是 `system`、CA PEM 文件或用于本地调试的 `insecure`。后端可以是 `pure` 或 `openssl`。公网示例默认验证证书。

在项目根目录运行 aioquic 互通套件。套件生成短期测试证书和独立的 UDP 监听端口，并覆盖丢包、乱序、1 MiB 响应、固定 RTT 下的发送节奏和持续丢包后的恢复。

```bash
python3 -m pip install aioquic==1.8.0
python3 interop/check.py --backend pure
python3 interop/check.py --backend openssl
```

手动启动本地对端时，在另一个 WSL 终端进入 `interop`，运行 `sh gen_cert.sh` 和 `python3 server.py`。上面的 `localhost` 示例使用新生成的 CA:FALSE 叶子证书校验对端。仓库中的历史示例证书为 CA:TRUE。

## 嵌入

在消费方的 `cjpm.toml` 里添加 `quic` 路径依赖。默认后端已包含在核心包中。

```cangjie
import quic.crypto.TrustStore
import quic.http3.Http3Client

main(): Int64 {
    let store = TrustStore.system()
    if (let Some(client) <- Http3Client.connect("cloudflare-quic.com", 443, store, true, 8000)) {
        try {
            let response = client.get("/")
            if (response.complete && response.status == 200) {
                println(response.body.size)
                return 0
            }
        } finally {
            client.conn.closeConnection("done")
        }
    }
    return 1
}
```

`QuicConfig` 配置传输参数、ACK 范围、接收批量、保活和发送 MTU 上限。`Http3Client.connect` 接受握手超时及 `responseTimeoutMs`。大响应可用 `client.getStreaming(path, onData)` 逐块消费。需要复用连接时可用 `Http3Pool(store)`，使用结束后调用 `pool.close()`。直接使用 QUIC 流时，由一个调用方持续调用 `pollOnce()` 并按消费进度调用 `extendReceiveWindow`。

需要吊销检查时，调用 `store.addCrlPem(...)` 或为 OpenSSL 设置 `store.requireStapledOcsp = true`。使用 mTLS 时，在 `TlsOptions(identity: ...)` 中传入叶子优先的 DER 链、签名方案和签名回调。有可信时钟的应用可通过 `TlsOptions(verificationTime: ...)` 提供 Unix 秒。`TlsOptions.keyLog` 的回调会收到可解密连接的秘密，默认关闭。

验证过的连接可以通过 `session()` 取得会话状态。下一次 `dial` 可以传入该状态及相同 QUIC 版本。只有可安全重放的请求才启用 `allowEarlyData` 和 `getEarly()`。服务器拒绝早期数据时，库在验证握手后以 1-RTT 重发。释放导出的会话时调用 `destroy()`。推送默认关闭，可用 `allowPush()` 和 `getPush()` 显式启用与读取。

要从一个新项目验证依赖或检查 C 宿主调用，运行 `python3 examples/consumer_smoke/run.py`。

## 状态与实现边界

各平台、协议特性、验证命令和已知限制见[开发状态](quic/docs/STATUS.md)。

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 授权。

```
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

允许商用、修改与再分发；再分发时需保留版权与许可声明、标注修改过的文件。

> 注：`docs/rfc/` 下的 RFC 原文版权归 IETF Trust，按其文档许可条款使用，
> 不在本项目的 Apache-2.0 授权范围内。
