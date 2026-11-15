# quiccj — 纯仓颉 QUIC v1 / HTTP-3 客户端

用仓颉（Cangjie）从零实现的 QUIC v1 + HTTP/3 客户端库，**零 FFI、零外部依赖**：
从大整数、AES-GCM、X25519、X.509 一直到 TLS 1.3、QUIC 传输层与 QPACK 全部自实现，
不链接 OpenSSL，也不调用任何系统加密库。

**当前状态**：本地与 [aioquic](https://github.com/aiortc/aioquic) 服务端完成握手并成功
`GET` 到 `200` + 响应体；`cjpm test` **28/28 通过**，含 RFC 9001 附录 A 的黄金包逐字节校验。
详细证据与缺口见 [`quic/docs/STATUS.md`](quic/docs/STATUS.md)。

```
$ ./target/release/bin/main 127.0.0.1 / 4433 insecure
handshake=true rx=1 closed=false reason= err=
status: 200
content-type: text/plain
body bytes: 22
hello from aioquic h3
```

## 特性

**密码学（`quic/src/crypto`）**

- SHA-256 / SHA-384 / SHA-512，HMAC（SHA-256 64 字节块、SHA-384 128 字节块），HKDF，TLS 1.3 HKDF-Expand-Label
- AES-128 / AES-256（32 位 T-table）、GHASH、AES-GCM（含 AAD、篡改检测）
- 固定容量 `BigUint` + Montgomery CIOS 乘法、模幂、费马求逆
- X25519（RFC 7748）；通用素域曲线 `EcCurve` + ECDSA 验签，支持 P-256 / P-384
- RSA PKCS#1 v1.5 验签（SHA-256 / SHA-384；实现完成，尚未用 RSA 证书链实测）
- DER/ASN.1、X.509（SAN / EKU / BasicConstraints / KeyUsage）、主机名匹配（单标签通配符）、
  PEM、`TrustStore`、证书链验证（支持交叉签名链）

**TLS 1.3（`quic/src/tls`）**

- QUIC profile（无 TLS 记录层），ClientHello → Finished 全流程
- `TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`
- X25519 key share、ALPN `h3`、QUIC transport parameters 扩展
- EncryptedExtensions / Certificate / CertificateVerify（ECDSA P-256/P-384）/ Finished 校验

**QUIC v1（`quic/src/transport`）**

- varint、长短头包、首部保护、Initial 密钥派生、AEAD、包号编解码
- 传输参数编解码、ACK、CRYPTO 流重组、STREAM 帧、流控字段、连接关闭
- 无状态 `PacketBuilder`：连接层与黄金包测试**共用同一份**打包/解包代码

**HTTP/3（`quic/src/http3`）**

- QPACK：RFC 9204 附录 A 完整静态表（99 项）、字面量编码、field-section prefix、Huffman 解码
- 控制流（SETTINGS）、QPACK encoder/decoder 单向流、HEADERS / DATA 帧、请求-响应

## 环境要求

- 仓颉工具链 **1.2.1**（`cjc` / `cjpm`），在 `aarch64-unknown-linux-gnu` 上验证
- 运行测试与示例不需要网络
- 仅**本地互通测试**需要 `python3` + `aioquic`（`pip install aioquic`）

## 构建与测试

```bash
cd quic
cjpm build
cjpm test          # 28/28：密码学向量 + 包层 + RFC 9001 黄金包
```

## 运行示例

```bash
cd examples/h3get
cjpm build
./target/release/bin/main <host> <path> [port] [insecure]
# 例：./target/release/bin/main cloudflare-quic.com / 443
# 第 4 个参数为 insecure 时关闭证书校验（自签证书测试用）
```

本地互通（自签证书）：

```bash
cd interop
sh gen_cert.sh          # 首次运行，生成 cert.pem / key.pem（私钥不入库）
python3 server.py &     # 监听 127.0.0.1:4433，日志写入 server.log
cd ../examples/h3get
./target/release/bin/main 127.0.0.1 / 4433 insecure
```

## 目录结构

```
quic/               库（output-type = static）
  src/crypto/       密码学原语、DER/PEM/X.509
  src/tls/          TLS 1.3（QUIC profile）
  src/transport/    包层（packet.cj）+ 连接状态机（conn.cj）
  src/http3/        QPACK、H3 帧与客户端
  testdata/         证书链、信任根、RFC 9001 黄金包十六进制
  docs/STATUS.md    实测状态、已知缺陷、未实现清单
examples/h3get/     命令行 HTTP/3 GET 客户端（path 依赖 quic）
interop/            aioquic 互通服务端脚本与自签证书生成脚本
docs/QUIC_PLAN.md   开发方案与 M0–M6 实施状态
docs/rfc/           RFC 9000/9001/9002/9114/9204/7541/8446 原文
```

## 设计要点

- **自底向上**：标准库只有抽象 `Digest` / `BlockCipher` 接口，因此所有原语自实现，
  每个原语先过官方向量（FIPS / RFC）再往上叠。
- **测试与实现同源**：包层抽出 `PacketBuilder`，连接层和黄金包测试调用同一段代码，
  避免"测试通过了但线上另一个实现"。
- **同步轮询、无后台线程**：`pollOnce()` 由调用方驱动，`handshake()` 内部按 250ms 重发握手包，
  适配 Android / Termux 等受限环境。
- **正确性优先**：首部保护采样点、AAD 范围、length 覆盖范围等都以 RFC 9001 A.2/A.3
  逐字节比对为准。

## 已知限制（摘要）

- 1-RTT 无丢包重传与拥塞控制；局域网可用，丢包网络会卡住
- 不支持 Retry、Version Negotiation、HRR/P-256 key share、RSA-PSS 验签、ChaCha20-Poly1305、
  KeyUpdate、连接迁移、0-RTT、HTTP/3 push / GOAWAY / 动态表编码
- `tests` 与示例使用固定信任库文件；`examples/h3get` 目前硬编码
  `/workspace/quic/testdata/roots.pem`
- 公网（Cloudflare）互通尚未实测
- 性能：X25519 ≈100ms、P-256 验签 ≈345ms、SHA-256 ≈3.5MB/s，握手延迟偏高，待优化

完整清单（含每条的证据与建议修法）见 [`quic/docs/STATUS.md`](quic/docs/STATUS.md) §3。

## 文档

- [开发状态与缺口](quic/docs/STATUS.md)
- [开发方案、架构与里程碑](docs/QUIC_PLAN.md)
- RFC 原文：[docs/rfc/](docs/rfc/)

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 授权，版权归 Soffd 所有（Copyright 2026 Soffd）。

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

要点：允许商用、修改与再分发；再分发时需保留版权与许可声明、标注修改过的文件；
附带专利授权（同时禁止贡献者发起专利诉讼）。

> 注：`docs/rfc/` 下的 RFC 原文版权归 IETF Trust，按其文档许可条款使用，
> 不在本项目的 Apache-2.0 授权范围内。
