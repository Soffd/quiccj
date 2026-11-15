# 开发状态

> 更新时间：2026-11-16。本文只记录**已验证可用的能力**与**确切的剩余缺口**，
> 不把已跑通的功能写成未实现，也不把未验证的代码写成已完成。

## 1. 一句话结论

纯仓颉（零 FFI、零外部依赖）实现的 QUIC v1 + HTTP/3 **客户端已端到端跑通**：
与本地 aioquic 服务端完成 TLS 1.3 / QUIC 握手，并成功发出 HTTP/3 GET，
收到 `200`、`content-type` 与 22 字节响应体。`cjpm test` **28/28 通过**。

```
$ ./target/release/bin/main 127.0.0.1 / 4433 insecure
handshake=true rx=1 closed=false reason= err=
status: 200
:status: 200
content-type: text/plain
body bytes: 22
hello from aioquic h3
```

## 2. 已验证的能力（含验证方式）

| 模块 | 能力 | 验证方式 |
|---|---|---|
| crypto | SHA-256/384/512、HMAC（SHA-256 64 字节块 / SHA-384 128 字节块）、HKDF、TLS-Expand-Label | FIPS 180-4、RFC 5869、RFC 8446 向量；含 1M `'a'` 长消息 |
| crypto | AES-128/256（T-table）、GHASH、AES-GCM | FIPS-197、NIST GCM 测试向量（空消息/AAD/篡改检测） |
| crypto | BigUint + Montgomery CIOS、模幂、费马求逆 | 与 Python 随机向量逐一比对 |
| crypto | X25519 | RFC 7748 §5.2 / §6.1（含 DH 双方一致性） |
| crypto | 通用素域曲线 EcCurve（P-256 / P-384）+ ECDSA 验签 | openssl 生成的 P-256 签名（含负例）；Cloudflare 真实链 P-384 根验签 |
| crypto | DER/ASN.1、X.509（SAN/EKU/CA/KeyUsage）、PEM、TrustStore、证书链验证 | 真实 Cloudflare 3 证书链（ECDSA P-256 leaf ← WE1 ← GTS Root R4 P-384，交叉签名）验证通过 |
| crypto | RSA PKCS#1 v1.5 验签（SHA-256/384） | 实现完成；**当前测试链全部是 ECDSA，未用 RSA 签名实测** |
| tls | TLS 1.3 QUIC profile 客户端：ClientHello、密钥调度（early/handshake/master/ap）、EncryptedExtensions、Certificate、CertificateVerify、Finished 校验、客户端 Finished、ALPN、QUIC TP 扩展 | **与 aioquic 端到端握手成功**；服务端 keylog 中的 `CLIENT/SERVER_HANDSHAKE_TRAFFIC_SECRET`、`SERVER_TRAFFIC_SECRET_0` 与本地派生值逐字节一致 |
| transport | varint、传输参数编解码、Initial 盐/密钥派生、AEAD、首部保护、长短头包、包号编解码 | **RFC 9001 A.2 客户端 Initial 解密 + 同输入重编码逐字节相同**；A.3 服务端 Initial 解密；A.1 密钥全对 |
| transport | 连接状态机：Initial/Handshake/1-RTT、ACK、CRYPTO 流重组、STREAM 帧、流控字段、握手 PTO 重发、连接关闭 | 与 aioquic 完成握手并交换 STREAM 数据（HTTP/3 请求/响应） |
| http3 | QPACK：静态表（RFC 9204 附录 A 全 99 项）、字面量编码、field-section prefix、Huffman 解码 | 与 aioquic 双向解码成功（请求头被接受，响应头正确解出 `:status 200`） |
| http3 | 控制流（SETTINGS）、QPACK encoder/decoder 单向流、HEADERS/DATA 帧、请求-响应 | aioquic 服务端返回 200 + 响应体 |
| examples/h3get | 命令行 HTTP/3 GET 客户端 | 本地 200；用法见 §4 |

单元测试：`cd quic && cjpm test` → **28/28 通过**（22 密码学 + 3 包层 + 3 RFC 9001 黄金包）。

## 3. 尚未实现 / 尚未验证（精确列表）

### 3.1 已知缺陷（会影响正确性，建议优先修）

1. **ACK Range 解析越界**：`conn.cj` 的 `handleAck` 按 `rangeCount` 而非 `rangeCount-1`
   读取 gap/range 对，导致响应之后出现一条 `parse error: Exception: buffer underflow`
   并污染 `lastError`。不影响 200 响应，但会掩盖真实错误。
2. **1-RTT 无丢包重传**：只有握手阶段会重发 ClientHello/Finished；1-RTT 的 STREAM
   与 ACK 丢失后不会重传，也没有 RTT/RTO 驱动的 PTO、没有拥塞控制。局域网可用，
   丢包网络下会卡住。
3. **`examples/h3get` 硬编码根证书路径** `/workspace/quic/testdata/roots.pem`，
   换机器需改代码或保证路径存在。

### 3.2 未实现（遇到对应场景会明确失败，不是静默错误）

| 项 | 现状 |
|---|---|
| Retry 包 | 长头 type=3 直接丢弃，不支持 token 重试 |
| Version Negotiation | 版本 0 直接丢弃（仅支持 QUIC v1；服务端不支持 v1 时握不上） |
| HRR / P-256 key share | 只提供 x25519 key share；服务端若选 P-256 会抛异常 |
| CertificateVerify `rsa_pss_rsae_*`(0x0804) / `rsa_pkcs1_*`(0x0401) | 返回失败；ECDSA(0x0403/0x0503) 已支持 |
| ChaCha20-Poly1305 | 未实现（两端都支持 AES 时不受影响） |
| KeyUpdate / 1-RTT 密钥轮换 | 未实现（长连接超过 AEAD 用量上限前需补） |
| 连接迁移、PATH_CHALLENGE、NEW_CONNECTION_ID 完整语义 | 仅接收并切换 DCID，无路径验证 |
| 0-RTT / 会话恢复 | 未实现 |
| HTTP/3 push、GOAWAY 处理、动态表编码 | 未实现；QPACK 编码端只用静态表+字面量（永不阻塞解码端） |
| 服务端（QUIC server） | 不在本库范围 |

### 3.3 未验证

- **公网互通**：尚未对 `cloudflare-quic.com` 跑通（本地 aioquic 已通）。公网会走
  SHA-384 + ECDSA 路径，理论上与本地一致，但需实测确认证书链与传输参数。
- **RSA 证书站点**：`rsaVerifyPkcs1` 无真实链验证用例。
- **丢包/乱序网络**：未做仿真测试（见 3.1 第 2 条）。

## 4. 如何运行

```bash
# 1) 库与测试
cd quic && cjpm build && cjpm test      # 28/28

# 2) 本地互通（需要 python3 + aioquic）
cd ../interop && sh gen_cert.sh         # 首次：生成自签证书（key.pem 不入库）
python3 server.py &                     # 监听 127.0.0.1:4433，日志写 server.log
pip install aioquic                     # 如未安装

# 3) 客户端
cd ../examples/h3get && cjpm build
./target/release/bin/main 127.0.0.1 / 4433 insecure
# 参数：host path port [insecure]；insecure 关闭证书校验（自签证书时需要）

# 4) 公网（默认强制校验，需要 testdata/roots.pem）
./target/release/bin/main cloudflare-quic.com / 443
```

## 5. 实现要点（供接手者参考）

- 目录：`src/crypto`（原语）、`src/tls`（TLS 1.3，无记录层）、`src/transport`
  （包层 + 连接）、`src/http3`（QPACK + H3）。
- 包层拆出了无状态的 `PacketBuilder`（`longHeader`/`shortHeader`/`openLong`/`openShort`），
  连接层与黄金包测试共用同一份代码，避免"测试与线上不一致"。
- 收包为同步轮询模型（`pollOnce()`），无线程；`handshake()` 内部按 250ms 重发握手包。
- 传输参数、QPACK 静态表等常量集中在各自模块顶部，便于对照 RFC 修改。
- 调试：`QuicConnection.debug = true` 会打印对端地址、首个 Initial 十六进制与解密失败
  摘要；**不要在生产路径打开**（会泄露握手字节）。
- 性能现状：X25519 ≈100ms、P-256 验签 ≈345ms、证书链验证 ≈600ms、SHA-256 ≈3.5MB/s。
  握手总耗时明显偏高，优化点见 `docs/QUIC_PLAN.md`（复用 w 数组、减少 BigUint 分配、
  窗口标量乘）。
