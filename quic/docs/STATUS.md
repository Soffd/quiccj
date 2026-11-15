# 开发状态（本次会话交付）

## 已完成并通过验证

| 模块 | 内容 | 验证 |
|---|---|---|
| quic.crypto | SHA-256/384/512、HMAC、HKDF、TLS-Expand-Label | FIPS/RFC 5869 向量全过（含 1M 'a'） |
| quic.crypto | AES-128/256（T-table）、GHASH、AES-GCM | FIPS-197 + NIST GCM 向量全过 |
| quic.crypto | 大整数 + Montgomery CIOS、模幂、费马求逆 | 与 Python 随机向量逐一比对 |
| quic.crypto | X25519 | RFC 7748 §5.2/§6.1 全过 |
| quic.crypto | 通用素域曲线 EcCurve（a=-3）+ ECDSA 验签，P-256/P-384 | openssl 生成的 P-256 签名验签通过（含反向用例） |
| quic.crypto | RSA PKCS#1 v1.5 验签（SHA-256/384） | 代码完成，待证书链实测 |
| quic.crypto | DER/ASN.1、X.509 解析、SAN/EKU/CA、主机名匹配、PEM、TrustStore、证书链验证 | 真实 Cloudflare 证书链（ECDSA P-256 leaf ← WE1 ← GTS Root R4 P-384）验证通过 |
| quic.tls | TLS 1.3 QUIC profile 客户端：ClientHello、密钥调度、EE/Cert/CV/Finished 校验、客户端 Finished、应用密钥、ALPN、QUIC TP 扩展 | 代码完成、可编译；未端到端跑通（见下） |
| quic.transport | varint、传输参数编解码、Initial 盐/密钥派生、AEAD、首部保护、帧编解码、ACK、流、流控、PTO 重传、连接状态机 | Initial 密钥/IV/HP 与 RFC 9001 A.1 完全一致 |
| quic.http3 | 静态表 QPACK 编码、Huffman 解码（RFC 7541 码长重建）、控制流/SETTINGS、HEADERS/DATA 帧、请求-响应 | 代码完成、可编译 |
| examples/h3get | 命令行 HTTP/3 GET 客户端 | 可编译运行 |

单元测试：`cjpm test` → **25/25 通过**（22 密码学 + 3 包层）。

## 当前阻塞点（明确的下一步）

端到端 QUIC 握手未通：本机向 `cloudflare-quic.com:443` 与本地 aioquic 服务端发送 Initial，
**收到 0 个 UDP 回包**（对方确实收到了数据报——aioquic 日志出现 "Network path discovered"），
说明 Initial 包被对端判定为不可解析而静默丢弃。

已排除：
- UDP 出网正常（Python 用同格式长头包能收到 Version Negotiation）。
- Initial 密钥派生与 RFC 9001 A.1 逐字节一致。
- 头字段布局（类型位 0xC1、版本、CID 长度、token=0、length varint、PN、1200 填充）人工核对无误。

下一步建议（按优先级）：
1. 用 RFC 9001 附录 A.2 的黄金包做双向校验：用 A.1 密钥解密 RFC 给出的客户端 Initial，
   断言能从解析器还原出 CRYPTO 帧与 ClientHello；再以相同输入重编码并逐字节比对。
2. 打开 aioquic 的包级日志，确认它是在首部保护、AEAD 还是 TLS 解析阶段丢弃。
3. 重点复查：`length` 是否覆盖 pn+payload+tag、sample 偏移是否为 `pn_offset+4`、
   AAD 是否使用未保护首部、填充是否计入 AEAD 长度。

## 复现

```bash
cd quic && cjpm build && cjpm test
cd ../examples/h3get && cjpm build
./target/release/bin/main cloudflare-quic.com / 443 insecure   # 第 3 参数端口，第 4 参数 insecure 关闭证书校验
```

## 设计要点（已完成部分）

- 零 FFI、零外部依赖：AES/GHASH/SHA/HKDF/X25519/P-256/P-384/RSA/Ed25519 预留位全部自实现。
- `@OverflowWrapping` 用于所有密码学热路径，避免溢出检查开销。
- 证书链按 subject 名匹配信任锚、按 SPKI+签名验证，支持交叉签名链（Cloudflare 的 GTS R4 场景）。
- QUIC 密钥分离与 RFC 9001 完全一致，为后续定位握手问题提供了可信基线。
