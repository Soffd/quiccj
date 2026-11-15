# 纯仓颉 QUIC / HTTP/3 底层库 开发方案 (v1)

> 目标：在仓颉 1.2.1 (cjnative, aarch64) 上实现**零 FFI、零外部加密库**的 QUIC v1 (RFC 9000/9001/9002)
> 与 HTTP/3 (RFC 9114/9204) 客户端库，可直接用于真实站点（如 cloudflare-quic.com）。

---

## 0. 环境勘察结论（已验证）

| 项 | 结论 |
|---|---|
| 编译器 | `cjc 1.2.1`，target `aarch64-unknown-linux-gnu`，`cjpm` 1.2.1 可用 |
| 多包工程 | 模块内子目录 = 子包（`src/tls/` → 包 `quic.tls`）；跨模块用 `path` 依赖，均已实测通过 |
| **密码学** | `std.crypto.cipher` **只有 `BlockCipher` 接口**，`std.crypto.digest` **只有 `Digest` 接口**；**无 AES / SHA / HKDF / 曲线实现** |
| 网络 | `std.net.UdpSocket`（`bind` / `sendTo` / `receiveFrom` / `receiveTimeout`）、`IPSocketAddress` 可用；UDP 出网可用 |
| 随机数 | `std.random.Random` 为梅森旋转，**不可用于密码学**；改用 `/dev/urandom`（`std.fs.File`，已验证） |
| 时间 | `std.time.MonoTime` / `Duration`，实测 1M 次 32 位乘法 ~9ms |
| 并发 | `spawn` / `Mutex` / `AtomicInt64` / `Condition` 可用 |
| 整数溢出 | 默认抛异常；`@OverflowWrapping` 注解可让函数内算术回绕（已验证） |
| 互操作 | `python3 + aioquic 1.8.0` 本地 HTTP/3 服务端可用；`curl` 带 nghttp3；公网 UDP 可达 |

**因此必须自底向上实现：大整数 → 对称/非对称密码 → X.509 → TLS 1.3 → QUIC → HTTP/3。**

---

## 1. 总体架构

```
quic/                      (cjpm 模块，output-type = static)
├── cjpm.toml
├── src/crypto/            quic.crypto   纯仓颉密码学
│   ├── bytes.cj           字节工具 / 常量时间比较 / hex
│   ├── sha2.cj            SHA-256, SHA-384/512
│   ├── hmac.cj            HMAC + HKDF (RFC 5869) + TLS-Expand-Label
│   ├── aes.cj             AES-128/256 密钥扩展、加密、CTR
│   ├── ghash.cj           GF(2^128) 乘法（4-bit 表）
│   ├── gcm.cj             AES-GCM AEAD
│   ├── chacha20.cj        ChaCha20-Poly1305 (RFC 8439)
│   ├── curve25519.cj      X25519 (RFC 7748, 5×51bit)
│   ├── p256.cj            secp256r1 点运算 + ECDSA 验签
│   ├── bigint.cj          多字长大整数（32bit limb, Montgomery）
│   ├── rsa.cj             RSA PKCS#1 v1.5 / PSS 验签（MGF1）
│   ├── ed25519.cj         Ed25519 验签
│   ├── asn1.cj            DER 解析器
│   ├── x509.cj            证书 / 扩展 / 有效期 / SAN / EKU
│   ├── pem.cj             PEM 编解码
│   └── truststore.cj      系统 CA 加载 + 内置根证书
├── src/tls/               quic.tls     TLS 1.3 握手（QUIC 版，无记录层）
│   ├── consts.cj          握手类型 / 扩展 / 分组 / 签名算法
│   ├── keyschedule.cj     Early/Handshake/Application 密钥派生
│   ├── extensions.cj      扩展编解码（SNI/ALPN/key_share/...）
│   ├── messages.cj        ClientHello..Finished 编解码
│   ├── verifier.cj        证书路径构建 + 签名验证 + 主机名匹配
│   └── session.cj         状态机：feed() → 输出握手字节 + 事件
├── src/transport/         quic.transport
│   ├── varint.cj          可变长整数
│   ├── buffer.cj          零切片读写缓冲（自定义，避免 Array 复制）
│   ├── frame.cj           全部帧类型编解码
│   ├── packet.cj          Long/Short 头、包号、首部保护
│   ├── crypto.cj          Initial 盐 / 包保护密钥派生
│   ├── params.cj          传输参数
│   ├── rtt.cj             RTT / ACK / PTO / 丢包检测 (RFC 9002)
│   ├── cc.cj              NewReno + pacing
│   ├── flow.cj            连接/流级流控
│   ├── stream.cj          发送/接收流状态机
│   ├── conn.cj            连接状态机（握手/1-RTT/关闭）
│   ├── cid.cj             连接 ID 与 demux
│   └── endpoint.cj        UDP 收发包、定时器、连接分发
└── src/http3/             quic.http3
    ├── frame.cj            DATA/HEADERS/SETTINGS/GOAWAY/...
    ├── huffman.cj          RFC 7541 Huffman
    ├── qpack.cj            静态表/动态表/编解码
    ├── request.cj          请求-响应 API
    └── client.cj           Http3Client
```

示例与测试独立成模块（避免污染库产物）：

```
examples/h3get/      命令行 HTTP/3 客户端（path 依赖 quic）
tests/interop/       aioquic 本地服务端脚本、抓包对照
docs/                RFC 原文 + 方案 + 测试记录
```

---

## 2. 依赖策略（“自用依赖”）

不引入第三方仓颉包（生态中无可用 QUIC/TLS 库，且要求纯仓颉）。自建顺序与理由：

1. **随机数**：`/dev/urandom` 直接读（`std.fs`）。若不可用则退化为 `MonoTime + 进程内计数` 的 HKDF 混合（仅降级，不用于生产）。
2. **对称密码**：AES 用 T-table（4×256×32bit，1KB 表 + 旋转复用）；GHASH 用 4-bit 查表；ChaCha20 用 32 位 ARX。
3. **曲线**：X25519 用 5×51bit limb（无分支、无大整数依赖）；P-256 用 4×64bit limb 的 Jacobian 坐标。
4. **RSA**：自建 32bit limb 大整数 + Montgomery 乘法，仅做**公钥运算**（e=65537），成本可控。
5. **证书**：只实现验证所需子集（TBSCertificate、SPKI、SAN、BasicConstraints、KeyUsage、EKU、Validity），GTS/ISRG/DigiCert 等根证书内置 + 系统 CA 兜底。
6. **TLS**：QUIC 不使用 TLS 记录层，因此只实现握手消息层（RFC 9001 §4），不做 record layer / 不做 DTLS。
7. **HTTP/3**：QPACK 编码端只用静态表 + 字面量（永不阻塞），解码端完整支持动态表（兼容服务端插入）。

---

## 3. 分阶段计划

| 阶段 | 内容 | 验收标准 |
|---|---|---|
| **M0** | 工程骨架、cjpm 多包、测试框架、RFC 文本入库 | `cjpm build` / `cjpm test` 通过 |
| **M1** | 密码学底座：SHA-2、HMAC、HKDF、AES-GCM、ChaCha20-Poly1305、X25519、P-256、RSA、Ed25519、DER/X.509、PEM、TrustStore | 全部通过 RFC/NIST 官方向量；`openssl` 交叉验证 |
| **M2** | TLS 1.3 握手（ClientHello→Finished、HRR、KeyUpdate）、证书链校验、主机名校验 | 与 `openssl s_server -tls1_3`（TCP 模拟）及 aioquic 的 TLS 层握手成功 |
| **M3** | QUIC 包层：varint、帧、长短头、首部保护、Initial 密钥、ACK、传输参数 | RFC 9001 A.2/A.3 逐字节复现 Initial 包与首部保护 |
| **M4** | QUIC 连接：握手、流、流控、丢包重传、PTO、NewReno、连接迁移基础、关闭 | 与 aioquic 完成 QUIC 握手并收发 STREAM 数据 |
| **M5** | HTTP/3：控制流、QPACK、请求/响应、GOAWAY、错误处理 | 本地 aioquic 服务端 GET 200；公网 cloudflare-quic.com GET 200 |
| **M6** | 加固：并发收发、超时、0-RTT / 会话恢复（可选）、服务端（可选）、文档与示例 | 压测 + 异常包鲁棒性测试 |

---

## 4. 关键设计决策

### 4.1 内存与性能
- 自建 `Buf`（`Array<UInt8>` + `readPos/writePos`），所有编解码零额外分配；帧解析用 `(offset,len)` 游标。
- 加密热路径全部 `@OverflowWrapping`，避免溢出检查开销。
- UDP 单 socket + 1 收包线程 + 1 定时器线程；连接状态用 `Mutex` 保护，避免复杂锁层级。
- 接收缓冲 64KB（QUIC 数据报上限 1500，留余量）。

### 4.2 正确性优先
- 每个密码原语先跑官方向量，再做端到端。
- QUIC 首部保护、Initial 包用 RFC 9001 附录 A 的**十六进制黄金样本**做逐字节断言。
- 每个阶段保留可独立运行的测试入口，失败可定位到包/字段级。

### 4.3 安全边界
- 默认强制证书校验（链 + 有效期 + 主机名 + EKU serverAuth）；提供显式 `insecureSkipVerify` 仅用于测试。
- 所有密钥材料使用后尽量清零（`fill(0)`），不打印。
- 常量时间比较用于 Finished / tag 校验。

### 4.4 兼容性范围
- QUIC v1（0x00000001）；收到 Version Negotiation 报错并提示。
- TLS 1.3 仅；cipher suite：`TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`。
- 密钥交换：X25519 为主，P-256 兜底（HRR）。
- HTTP/3：无 push、无 0-RTT（后续可加）、支持 DATAGRAM 以外的标准帧。

---

## 5. 对外 API 草案

```cangjie
// 最简用法
let client = Http3Client("cloudflare-quic.com", 443u16)
let resp = client.get("/")
println("${resp.status} ${resp.headers.size}")
let body = resp.readAll()

// 显式配置
let cfg = ClientConfig(
    alpn: ["h3"],
    verify: VerifyMode.Strict,
    caFile: None,                 // 默认系统 CA + 内置根
    idleTimeout: Duration.second * 30,
    maxUdpPayload: 1350
)
let c = QuicClient(cfg)
let conn = c.connect("example.com", 443u16)
let stream = conn.openBidiStream()
```

---

## 6. 风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| 无标准库 AES/SHA | 必须自实现，性能有限 | T-table/查表 + `@OverflowWrapping`；握手数据量小，实测优先 |
| RSA 大整数实现复杂 | 部分站点握手失败 | 先支持 ECDSA/Ed25519（覆盖多数 CDN），RSA 作为 M1 后段补齐 |
| 证书链多样 | 校验失败 | 优先按 SPKI 匹配信任根，内置主流根 + 系统 CA；支持交叉签名链 |
| UDP 丢包/MTU | 握手卡住 | 实现 PTO + 重传 + 1200 字节填充；本地 aioquic 可观测 |
| 仓颉语言细节（无 `&+`、API 名称差异） | 编译反复 | 已用探针确认；后续每步先编译再扩展 |
| 设备性能 | 大量下载慢 | 分块 + 流量控制；后续可加 AES 位切片优化 |

---

## 7. 测试矩阵

1. **单元向量**：SHA-256/384、HMAC-SHA256、HKDF（RFC 5869）、AES-GCM（NIST GCM test vectors）、ChaCha20-Poly1305（RFC 8439 §2.8.2）、X25519（RFC 7748 §5.2/6.1）、ECDSA P-256（NIST）、Ed25519（RFC 8032）、QPACK（RFC 9204 附录）、Huffman（RFC 7541 附录 C）。
2. **协议字节级**：RFC 9001 A.2 Initial 包、A.3 首部保护、A.4 ChaCha20 短包。
3. **互通**：aioquic 本地服务端（自签 P-256）→ 握手 / GET / 大响应 / 多流；cloudflare-quic.com → 完整链校验。
4. **异常**：截断包、非法 varint、超大帧、错误 tag、重复包、乱序包。

---

## 8. 里程碑产物

- `libquic.a`（静态库）+ 各子包 `.cjo`
- `examples/h3get`：`h3get https://cloudflare-quic.com/`
- `docs/QUIC_PLAN.md`（本文）、`docs/TESTLOG.md`（每阶段实测记录）、`README.md`
