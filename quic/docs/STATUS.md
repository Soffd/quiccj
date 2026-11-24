# 开发状态

本轮验证使用仓颉 1.2.1、WSL Ubuntu x86_64、OpenSSL 3.5.5 和 aioquic 1.8。验证范围截至 2026-11-24。

## 安全与认证

| 项目 | 行为与部署条件 |
|---|---|
| 默认后端 | TLS、QUIC 和 HTTP/3 的连接入口默认构造 `NativeCryptoBackend`。缺少 OpenSSL 3 或必需符号时报告错误。调用方可以显式传入 `PURE_CRYPTO`，此软件实现尚未接受独立常数时间审计。 |
| 服务器证书 | 两个后端检查有效期、SAN、CA 叶子、密钥用途和 RSA 最低 2048 位，支持 Ed25519 和 RSA-PSS 签名。设置 Unicode 主机名时通过 libidn2 转换为 A-label。 |
| 信任根 | `TrustStore.fromFile` 对损坏的 PEM 或证书报错。`TrustStore.system()` 支持 `SSL_CERT_FILE` 与 `SSL_CERT_DIR`，也有 Linux CA bundle、Android CA 目录、Windows CryptoAPI 和 macOS SecTrust 的系统路径。 |
| 吊销策略 | 默认关闭。`addCrlPem` 启用整条链的 CRL 检查。`requireCrl` 可要求存在有效 CRL。纯后端支持签发者直接签署的完整 CRL。OpenSSL 的 `requireStapledOcsp` 要求服务器随握手提供叶子证书的签名状态，并校验签发者、状态和有效时间。纯后端遇到强制 OCSP 策略会拒绝握手。CRL 更新由应用负责。 |
| 客户端证书与密钥交换 | `ClientIdentity` 接受 DER 链和签名回调。`NativeCryptoBackend.signClient` 支持使用 DER 私钥。具备 ML-KEM-768 的 OpenSSL provider 会启用 X25519MLKEM768。 |
| 时间与恢复 | 默认时钟会拒绝与进程启动后的单调时间相差超过五分钟的墙钟跳变。启动前已存在的偏差需要通过可信的 `verificationTime` 修正。票据寿命用单调时钟计算。恢复前使用当前信任根、域名和验证时钟重新检查原证书链。在 mTLS 或强制吊销策略下进行完整握手。 |
| 秘密的生命周期 | TLS 和连接关闭时清零所持的流量密钥、密钥交换材料和 PSK。导出的 `QuicSession` 有独立的票据副本，应用负责 `destroy()`。清零范围为库持有的缓冲区，GC、系统库和调用方产生的其他副本不在此保证范围内。 |

## 传输与 HTTP/3

- `QuicConfig.parameters` 提供空闲超时、接收窗口、流数和 UDP 上限。ACK 历史按连续范围保存。可配置 ACK 间隔、范围数、每轮读取量、保活及发送 MTU。Linux 支持 `recvmmsg`、可用时启用 UDP GRO、验证 ECN 反馈，以带填充的 PING 和已认证的 ACK 探测路径 MTU。其他目标使用标准库 UDP，发送 MTU 为 1200。
- 客户端可切换本地 UDP 绑定并验证新路径。代理在传输期间切换对服务器可见的客户端端口时，原连接仍能下载完整响应。客户端会过滤来自未知服务器地址的包。服务端 preferred address 尚未实现。[RFC 9000 §9](https://www.rfc-editor.org/rfc/rfc9000.html#section-9)
- `closeConnection` 同步保留套接字三个 PTO，closing 期间可限速重发 CONNECTION_CLOSE，draining 期间保持静默。单连接由一个调用方驱动，保活和恢复定时器依赖轮询。
- `QuicConnection.connect` 和 `Http3Client.connect` 在系统 DNS 返回后交错尝试 IPv6/IPv4 地址。需要控制 0-RTT 和版本的低层 `dial` 返回单地址连接对象。高层 HTTP/3 支持 GET、带请求体的 POST、推送、流式响应、PRIORITY_UPDATE 及连接池。`Http3Pool` 复用经过验证的同源连接，支持带有效期的 h3 Alt-Svc，通过替代端点连接时保留源站身份及请求 authority。
- `QuicConfig.onDatagram` 与 `sendDatagram` 提供 RFC 9221 不可靠数据报。WebTransport 会话尚未实现。POST 使用经过认证的 1-RTT 连接。
- 可读指标包含 RTT、拥塞窗口、在途字节、丢包、流数和收发字节。`closeCause` 提供结构化关闭原因。`QuicConfig.qlog` 接收 JSON-SEQ 包事件，`log` 接收诊断文本，`TlsOptions.keyLog` 生成 NSS 密钥日志。这些回调默认关闭。

## 验证矩阵

| 场景 | 已执行的验证 |
|---|---|
| Linux / aioquic | 两个后端各 21 项，覆盖显式后端选择与动态库缺失、RSA-1024、CA 叶子、信任失败、1 MiB POST 的端到端 SHA-256 校验、1 MiB 流式下载、丢包乱序、重绑定、显式迁移、ACK 驱动的 MTU 探测、DATAGRAM 回显、Alt-Svc 的原始 authority 和连接复用、QPACK、GOAWAY、0-RTT 接受与拒绝、版本协商、Retry 和密钥更新。 |
| Linux / nginx QUIC | 强制客户端证书，服务端只接受混合组；Ed25519 叶子、RSA-PSS 签名的链、有效 CRL、签名 OCSP staple 均成功。拒绝撤销证书、过期 CRL 和缺失的客户端身份。 |
| Linux / ngtcp2 与 quiche | 两个后端对 ngtcp2 完成可信 GET 并拒绝已撤销的叶子。OpenSSL 对 ngtcp2 拒绝缺失的强制 OCSP staple，并对 Cloudflare quiche 完成可信 GET。 |
| Windows x86_64 / Kestrel、MsQuic | 从 Linux 交叉编译，在 Windows 上用两个后端及显式 PEM 信任根完成 HTTP/3 GET。两个后端使用 Windows 系统信任库验证固定公网证书链时，正确域名通过，错误域名被拒绝。Chrome、Firefox 和启用 HTTP/3 的 curl 对同一 MsQuic 服务也收到了 HTTP/3 响应。 |
| 外部消费方 | 仓库外仓颉项目及独立 C 宿主完成 GET；C ABI 测试覆盖错误 CA 与短缓冲区。 |
| macOS、Android | 已加入平台代码。尚缺目标系统上的构建、证书库及网络互通实测。 |

55 项核心测试和 3 项 OpenSSL 兼容包测试全部通过。核心单测包括 RFC 向量、错误 Finished、TLS 降级、证书过期、错误 SAN、链断裂、通配符边界、畸形信任根，以及四种解析器的可复现变异测试。覆盖率命令独立构建带覆盖率计数的包，要求生产源代码行覆盖率至少 52%。本轮使用 16,384 个变异输入，实测 53.38%（3,684/6,901 行）。本机使用四个并发客户端进程，每条连接连续发起 8,192 次 GET。最终轮转队列在 309.7 秒内完成 64 条连接、524,288 次成功 GET，该负载下 OpenSSL 握手中位数为 15 ms。在另一次顺序基准中，每个后端独立计时七次本机完整握手，纯仓颉中位数为 141 ms，OpenSSL 为 9 ms。短时压力测试尚未覆盖数小时运行、移动网络和设备能耗。

## 复现

```bash
(cd quic && cjpm test)
(cd quic_openssl && cjpm test)
(cd examples/h3get && cjpm build)
python3 interop/coverage.py
python3 interop/check.py --backend openssl
python3 interop/check.py --backend pure
python3 interop/secure_handshake.py --nginx /path/to/nginx --ngtcp2 /path/to/gtlsserver --quiche /path/to/quiche-server
python3 interop/benchmark.py --backend pure --samples 7
python3 interop/benchmark.py --backend openssl --concurrency 4 --requests 8192 --seconds 300
python3 examples/consumer_smoke/run.py
```

运行更长的稳态压测时可增加 `--seconds`。Linux 网络测试依赖 aioquic 1.8、cryptography 和 openssl 命令。nginx 需要 HTTP/3、OpenSSL 混合组和 stapling 支持。Windows 上运行 `python interop/msquic.py --client C:\path\to\main.exe`，需 .NET 8、仓颉运行库和 OpenSSL 3 DLL。变异测试可通过 `QUICCJ_FUZZ_CASES`、`QUICCJ_FUZZ_SEED` 设置次数和种子。浏览器对照可给 `msquic.py` 传入 `--chrome`、`--curl` 或 `--firefox`。Firefox 测试需要 Playwright 和 Mozilla NSS 的 `certutil`，用 `--nss-certutil` 指定工具，在临时配置中导入测试 CA。脚本要求服务端报告 HTTP/3，降级到 HTTP/2 会使测试失败。
