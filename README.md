# quiccj

quiccj 是供仓颉应用嵌入的 QUIC v1/v2 和 HTTP/3 客户端库。核心包提供包保护、同步驱动的 QUIC 连接和流，以及 HTTP/3 GET。默认使用纯仓颉密码学。Linux 应用可以按连接选择独立的 OpenSSL 后端。

## 功能

- **QUIC** 支持 Initial、Handshake、0-RTT 和 1-RTT、ACK 范围、CRYPTO 和 STREAM 重组、连接及流级流控、RTT 和 PTO、包阈值及时间阈值重传、NewReno 拥塞控制、发送节奏控制、持续拥塞检测、Retry、版本协商、密钥轮换和本地 UDP 路径迁移。
- **TLS 1.3** 支持 X25519、使用 P-256 的 HelloRetryRequest、ECDSA 和 RSA-PSS CertificateVerify、AES-GCM 和 ChaCha20-Poly1305、证书验证、会话票据和显式启用的 0-RTT。
- **HTTP/3** 支持 SETTINGS、GET、响应头和响应体、GOAWAY、服务器推送，以及 QPACK 静态表、Huffman 和动态表。请求编码器可以复用 `:authority`，并遵守对端的阻塞流额度。
- **信任配置** 由调用方传入 `TrustStore`。可以直接加载 PEM、自带信任根，或使用 `TrustStore.system()` 读取 `SSL_CERT_FILE` 及常见系统 CA 文件。

## 构建与验证

在 WSL Ubuntu 上使用仓颉工具链 1.2.1。

```bash
(cd quic && cjpm build && cjpm test)
(cd quic_openssl && cjpm test)          # 需要 Linux OpenSSL 3 的 libcrypto.so.3
(cd examples/h3get && cjpm build)
```

`quic` 由仓颉代码和标准库组成。选择 `quic_openssl` 时，`OpenSslBackend()` 在运行时加载 `libcrypto.so.3`，通过 EVP 执行摘要、密钥交换、验签和包保护，并使用 OpenSSL 校验证书链。两个后端共用 QUIC、TLS 1.3 和 HTTP/3 状态机。

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

手动启动本地对端时，在另一个 WSL 终端进入 `interop`，运行 `sh gen_cert.sh` 和 `python3 server.py`。上面的 `localhost` 示例使用生成的证书校验对端。

## 嵌入

在消费方的 `cjpm.toml` 里添加 `quic` 路径依赖。使用 OpenSSL 时同时依赖 `quic_openssl`。

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

OpenSSL 路径在 `Http3Client.connect` 或 `QuicConnection.dial` 中传入 `backend: OpenSslBackend()`。直接使用 QUIC 流时，由调用方持续调用 `pollOnce()` 驱动收包和恢复定时器。单连接由一个调用方驱动。读取消费完成后可用 `extendReceiveWindow` 补充接收额度。

验证过的连接可以通过 `session()` 取得会话状态。下一次 `dial` 可以传入该状态及相同 QUIC 版本。只有可安全重放的请求才启用 `allowEarlyData` 和 `getEarly()`。服务器拒绝早期数据时，库在验证握手后以 1-RTT 重发。推送默认关闭，可用 `allowPush()` 和 `getPush()` 显式启用与读取。

要从一个新项目验证依赖或检查 C 宿主调用，运行 `python3 examples/consumer_smoke/run.py`。

## 状态与实现边界

两个后端均已与本地 aioquic 互通，并在 WSL 上通过系统 CA 访问 Cloudflare 公网 HTTP/3。

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
