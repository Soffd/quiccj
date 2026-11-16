# 消费方和跨语言测试

测试脚本把两个仓颉模块复制到仓库外的临时目录，再以普通 `cjpm` 路径依赖构建。临时目录包含测试用证书和构建产物，运行结束后会清理。

| 模块 | 调用链路 | 检查 |
|---|---|---|
| `direct` | 独立仓颉项目 → `quic` | 证书校验、HTTP/3 200、完整的 22 字节响应体、拒绝错误 CA |
| `native` | C 可执行文件 → 仓颉共享库 → `quic` | 同一个 C 进程分别选择纯仓颉与 OpenSSL 后端，检查 HTTP 状态、响应体、错误 CA，以及短缓冲区的长度报告与原内容保护 |

## 运行

在 WSL Linux x86_64 加载仓颉 1.2.1 环境。在安装了 aioquic 1.8.0 的 Python 环境中，从仓库根目录执行。

```bash
python3 examples/consumer_smoke/run.py
```

完整测试使用 C 编译器、OpenSSL 3 运行库和 `openssl` 命令。脚本默认下载仓颉 1.2.1 的 `Cangjie.h` 并检查 SHA-256，可用 `--runtime-header /path/to/Cangjie.h` 指定本地头文件。[仓颉 1.2.1 运行时接口](https://github.com/cangjielanguage/cangjie_runtime/blob/v1.2.1/runtime/src/Cangjie.h)

使用 `--direct-only` 时，仓颉模块只依赖 `quic`，无需 C 编译器或运行时头文件。脚本仍使用 `openssl` 命令生成测试证书。也可直接进入 `direct` 运行 `cjpm build`，再向产物传入主机、UDP 端口和 PEM CA 文件。

## C ABI 示例

C 宿主通过 `InitCJRuntime` 初始化运行时，通过 `LoadCJLibraryWithInit` 加载共享库，再将 `@C` 导出函数交给 `RunCJTask` 调度。`GetTaskRet` 返回后，宿主读取 `smoke.h` 定义的结果，并在退出前关闭运行时。[仓颉与 C 互操作](https://docs.cangjie-lang.cn/cjnative/user_manual/source_zh_cn/FFI/cangjie-c.html)

输入字符串和输出缓冲区由 C 调用方持有，在任务结束前必须有效。输出为字节序列，以 `body_size` 指明长度。容量不足时只报告所需长度，缓冲区内容保持原样。这个桥接层的作用域是消费方测试，库的仓颉 API 仍是应用嵌入接口。
