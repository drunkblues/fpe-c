## Design Document: FPE C Implementation

## Context

Format-Preserving Encryption (FPE) 允许在加密敏感数据的同时保持原始格式（例如，16 位信用卡号保持 16 位数字）。这对于 PCI DSS 合规、数据库约束和无法处理密文格式的遗留系统至关重要。

当前状况：
- 大多数 FPE 实现是 Python/Java，许可证限制严格
- 缺乏广泛使用的开源 C 实现
- 嵌入式系统和原生应用程序需要 FPE 能力
- 中国市场需要 SM4 国密支持

约束：
- 必须实现 NIST SP 800-38G 批准的算法（FF1、FF3、FF3-1）
- 必须可移植跨平台（Linux、macOS、Windows）
- 必须避免除 OpenSSL 外的额外依赖（广泛部署）
- 性能必须足以应对高吞吐量环境
- 必须提供原生 C 测试套件，无需 Python

## Goals / Non-Goals

**Goals:**
- 实现 FF1、FF3（已弃用）、FF3-1 算法，符合 NIST SP 800-38G
- 支持 AES（128/192/256 位）和 SM4（128 位）加密算法
- 提供干净、线程安全的 C API，使用不透明指针模式
- 支持通用字母表（数字、字母数字、自定义）
- 包含来自 NIST 的全面测试向量
- 使用 CMake 构建跨平台支持
- 使用原生 C 测试套件（无 Python 依赖）
- 提供统一 API 和便利 API（One-shot、字符串）

**Non-Goals:**
- 实现其他 FPE 算法（BPS、VAE3 等）
- 侧信道防护（超出 OpenSSL 的保护范围）
- 硬件加速（AES-NI 通过 OpenSSL 提供）
- 与特定框架集成（仅纯 C API）
- FIPS 140-2 认证（使用 OpenSSL 的认证模块）
- C++ 类封装（C++ 友好但不提供类）

## Decisions

### 算法选择: FF1, FF3 (已弃用), FF3-1

**FF1**:
- 10 轮 Feistel 网络
- 基于 AES-CMAC/SM4-CMAC
- 更灵活的 tweak 处理（0 到 2^32 字节）
- 更广泛采用，在许多平台上性能更好

**FF3**:
- 8 轮 Feistel 网络
- 基于 AES-ECB/SM4-ECB
- 严格的最小长度要求
- NIST 已标记为不安全（2019 年发现安全缺陷）
- **保留原因**: 兼容性需求

**FF3-1**:
- FF3 的改进版本
- 修复了 FF3 的安全问题
- NIST SP 800-38G Rev 1 推荐
- 主要推荐算法

**替代方案考虑**: 仅实现 FF1
**理由**: 所有三个都是 NIST 批准的；用户可能偏好其中一个。FF3-1 比 FF3 更安全，应优先使用。

### 底层加密算法: AES + SM4

**AES (Advanced Encryption Standard)**:
- 国际标准 (NIST FIPS 197)
- 支持 128/192/256 位密钥
- 广泛部署和优化
- OpenSSL 完整支持（所有版本）

**SM4 (国密算法)**:
- 中国国家标准 (GB/T 32907-2016)
- 仅支持 128 位密钥
- 适用于中国政府/金融系统
- OpenSSL 3.0+ 正式支持，OpenSSL 1.1.1+ 实验性支持

**替代方案考虑**: 仅实现 AES
**理由**: 中国市场需要 SM4 支持。两个算法都使用相同的 Feistel 网络结构，增加开销很小。

### API 设计: 统一接口 vs 分离接口

**选择: 统一接口**

```c
// 统一接口（实际实现）
FPE_CTX *ctx = FPE_CTX_new();
FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
FPE_encrypt(ctx, in, out, len, tweak, tweak_len);
```

**分离接口（替代方案）**:
```c
fpe_ctx_t ctx;
fpe_ctx_init_ff1(&ctx, key, 128, 10);
fpe_encrypt_ff1(&ctx, in, out, len, tweak, tweak_len);
```

**权衡分析**:

| 优点 | 缺点 |
|------|------|
| ✅ 更灵活 - 运行时切换算法 | ❌ 运行时分发开销 (switch) |
| ✅ 扩展性强 - 添加新算法无需新 API | ❌ 编译器无法静态优化特定算法 |
| ✅ 代码更少 | ❌ 错误可能在运行时才发现 |
| ✅ 用户友好 - 一个接口统治所有 | ❌ 调试更复杂 |

**理由**: 运行时分发开销与加密操作相比可忽略不计。统一 API 更优雅且可扩展，用户友好。

### 上下文管理: 堆分配 vs 栈分配

**选择: 堆分配（不透明指针模式）**

```c
// 堆分配（实际实现）
FPE_CTX *ctx = FPE_CTX_new();  // 堆分配
FPE_CTX_init(ctx, ...);
FPE_CTX_free(ctx);
```

**栈分配（替代方案）**:
```c
fpe_ctx_t ctx;  // 栈分配
fpe_ctx_init(&ctx, key, 128, 10);
```

**权衡分析**:

| 方面 | 栈分配 | 堆分配 |
|------|--------|--------|
| **性能** | ✅ 零分配开销 | ❌ malloc/free 开销 |
| **自动清理** | ✅ 离开作用域自动释放 | ❌ 需要手动 free |
| **大小灵活性** | ❌ 编译时固定大小 | ✅ 运行时决定 |
| **ABI 稳定性** | ❌ 结构体可见，可能变化 | ✅ 不透明指针，ABI 稳定 |
| **错误处理** | ❌ 需要额外的错误状态 | ✅ NULL = 分配失败 |
| **线程安全** | ✅ 每个栈帧独立 | ✅ 每个堆对象独立 |

**理由**: 不透明指针模式确保 ABI 稳定性（可以更改内部结构而不破坏二进制兼容性）。这对于库长期维护至关重要。堆分配开销在大多数用例中可接受。

**内存布局**:
```
FPE_CTX 结构 (堆分配)
┌─────────────────────────────────────────┐
│ mode: FPE_MODE_FF1/FF3/FF3_1          │
│ algo: FPE_ALGO_AES/SM4                 │
│ radix: 10/62/custom                    │
│ key_bits: 128/192/256                 │
├─────────────────────────────────────────┤
│ OpenSSL 内部对象 (堆分配):              │
│   • EVP_CIPHER_CTX                     │
│   • CMAC_CTX (for FF1)                │
│   • ECB contexts (for FF3/FF3-1)       │
├─────────────────────────────────────────┤
│ 预计算值:                             │
│   • derived keys                       │
│   • A, B, m, t (算法常数)            │
└─────────────────────────────────────────┘

大小估计: ~300-700 字节
```

### 数据表示: 整数数组 vs 字符串

**选择: 整数数组作为基础表示**

```c
// 基础表示（整数数组）
unsigned int plaintext[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
FPE_encrypt(ctx, plaintext, ciphertext, 16, tweak, 8);

// 便利 API（字符串）
const char alphabet[] = "0123456789";
const char cc_number[] = "1234567890123456";
char encrypted[17];
FPE_encrypt_str(ctx, alphabet, cc_number, encrypted, tweak, 8);
```

**理由**:
- 整数数组是算法层的"自然"表示（纯数学运算）
- 字符串 API 是包装器，内部使用整数数组
- 性能关键路径可以直接使用整数数组，避免字符转换
- 字符串 API 提供易用性

**数据流**:
```
用户空间 (字符串)
    ↓ FPE_encrypt_str (映射)
    字符 → 索引: '1' → 1, '2' → 2, ...
    ↓ unsigned int 数组
    ↓ FPE_encrypt (Feistel 网络)
    纯数学运算: [1,2,3,4,...] → [9,8,7,6,...]
    ↓ unsigned int 数组 (加密后)
    ↓ FPE_encrypt_str (映射)
    索引 → 字符: 1 → '1', 2 → '2', ...
    ↓
用户空间 (加密字符串)
```

### One-shot 无状态 API

**选择: 提供便利函数**

```c
int FPE_encrypt_oneshot(FPE_MODE mode, FPE_ALGO algo,
                        const unsigned char *key, unsigned int key_bits,
                        unsigned int radix,
                        const unsigned int *in, unsigned int *out, unsigned int len,
                        const unsigned char *tweak, unsigned int tweak_len);
```

**内部实现**:
```c
int FPE_encrypt_oneshot(...) {
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) return -1;
    int ret = FPE_CTX_init(ctx, mode, algo, key, key_bits, radix);
    if (ret == 0) {
        ret = FPE_encrypt(ctx, in, out, len, tweak, tweak_len);
    }
    FPE_CTX_free(ctx);
    return ret;
}
```

**权衡**:

| 场景 | 传统方式 | One-shot |
|------|---------|----------|
| **代码简洁性** | ❌ 需要管理上下文 | ✅ 一行代码 |
| **性能（单次操作）** | ✅ 上下文重用 | ❌ 每次分配 |
| **性能（批量操作）** | ✅ 上下文重用 | ❌ 每次分配+密钥推导 |
| **适用场景** | 批量操作 | 简单/一次性操作 |

**理由**: 便利性对简单用例很重要。批量操作的用户应该使用传统 API。

### 错误处理: 简单返回值

**选择: 整数返回值 (0=成功, -1=失败)**

```c
int FPE_encrypt(...);  // 返回 0 或 -1
int FPE_CTX_init(...);  // 返回 0 或 -1
FPE_CTX *FPE_CTX_new();  // 返回 NULL 表示失败
```

**替代方案**: 详细错误代码

```c
#define FPE_SUCCESS 0
#define FPE_ERR_INVALID_RADIX -1
#define FPE_ERR_INVALID_KEY_LENGTH -2
...
const char *FPE_error_string(int code);
```

**权衡**:

| 方面 | 简单返回 | 详细错误代码 |
|------|---------|-------------|
| **API 简洁性** | ✅ 简单 | ❌ 需要了解错误码 |
| **调试友好** | ❌ 不知道具体错误 | ✅ 知道具体错误 |
| **实现复杂度** | ✅ 简单 | ❌ 需要映射表 |
| **文档负担** | ✅ 少文档 | ❌ 多文档 |

**理由**: API 保持简洁。通过文档和参数验证防止常见错误。未来可以添加可选的详细错误处理。

### 测试框架: 原生 C vs Python

**选择: 原生 C 测试框架 (Unity)**

**理由**:
- 无需 Python 运行时依赖
- 可以在嵌入式/受限环境运行
- 测试向量硬编码到 C 代码
- `make test` 即验证，无脚本依赖

**替代方案考虑**: Python 脚本（常见于开源 FPE 实现）
**理由**: Python 增加部署复杂度，不适合纯 C 工具链。

### OpenSSL 版本策略

**版本要求**:
- **OpenSSL 3.0+**: SM4 完整支持
- **OpenSSL 1.1.1+**: AES 完整支持，SM4 实验性支持
- **OpenSSL 1.0.x**: AES 支持，SM4 不支持（已弃用）

**实现策略**:
- **编译时检测**: 使用 CMake 检测 OpenSSL 版本
- **条件编译**: SM4 支持仅在 OpenSSL >= 1.1.1 时编译
- **运行时检查**: 验证算法可用性

```cmake
if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0")
    add_definitions(-DHAVE_OPENSSL_SM4)
elseif(OPENSSL_VERSION VERSION_GREATER_EQUAL "1.1.1")
    add_definitions(-DHAVE_OPENSSL_SM4_EXPERIMENTAL)
endif()
```

**理由**: 平衡广泛支持和现代功能。大多数现代系统使用 OpenSSL 3.0+ 或 1.1.1+。

## Risks / Trade-offs

### 性能开销

**风险**: 统一 API 的运行时分发和堆分配可能影响性能
**缓解**:
- 基准测试与已知实现比较；优化热路径
- 提供快速路径（可选）直接调用特定算法
- 文档说明何时使用 One-shot vs 传统 API

### 内存使用

**风险**: 上下文堆分配 + OpenSSL 内部分配 = 多次 malloc
**缓解**:
- 文档说明上下文重用建议
- 考虑上下文池（可选优化）
- 未来可能支持栈分配的上下文（如果需要）

### OpenSSL 版本兼容性

**风险**: 不同 OpenSSL 版本的 API 差异
**缓解**:
- 使用 CMake 检测版本
- 条件编译处理 API 差异
- 提供清晰的最低版本要求文档
- CI 测试多个 OpenSSL 版本

### SM4 支持可用性

**风险**: 旧系统可能没有 SM4 支持
**缓解**:
- 条件编译：SM4 支持可选
- 运行时检查：FPE_CTX_init 失败时返回错误
- 文档说明 SM4 版本要求

### 大整数运算

**风险**: 64 位算术在 Feistel 网络中可能溢出
**缓解**:
- 使用 uint64_t 和谨慎的模运算
- 添加边界条件测试
- 考虑使用 OpenSSL BIGNUM（如果需要）

### 测试覆盖

**风险**: 不完整测试可能遗漏边缘情况
**缓解**:
- 使用所有 NIST 测试向量
- 添加属性测试（模糊测试）
- 测试边界条件（最小长度、最大长度、边缘 radices）
- 内存泄漏检测（Valgrind/AddressSanitizer）

## Migration Plan

这是一个新库，没有现有代码需要迁移。部署步骤：

1. 使用 `cmake && make install` 构建和安装 libfpe
2. 链接 libfpe 并包含头文件 `#include <fpe.h>`
3. 参考示例进行初始化和使用
4. 运行测试验证平台兼容性

回滚：删除 libfpe 并恢复到先前的加密方案（如果有）。

## Open Questions

- 是否应该提供直接调用特定算法的快速路径 API（性能优化）？
- 是否应该提供详细的错误代码和错误字符串（调试友好性）？
- 上下文池是否值得实现（性能优化）？
- 是否应该支持栈分配的上下文（嵌入式优化）？
- 是否应该添加硬件检测（AES-NI 通过 OpenSSL）？
- 是否应该添加与真实世界数据格式的集成测试？
- Unity 测试框架是否最佳选择，还是应该使用其他框架？

## Performance Testing Strategy

### Test Vector Integration
All NIST test vectors are hardcoded in `tests/vectors.h` for native C execution:
```c
// Structure from tests/vectors.h
typedef struct {
    const char *alg_name;       // "AES-128", "AES-192", "AES-256", "SM4"
    FPE_MODE mode;              // FPE_MODE_FF1, FPE_MODE_FF3, FPE_MODE_FF3_1
    unsigned int radix;
    const char *key_hex;
    const char *tweak_hex;      // Hex string, use "" for empty
    const char *plaintext;      // ASCII string of digits/chars
    const char *ciphertext;     // Expected result
} fpe_test_vector_t;
```

### Performance Metrics
Multiple performance metrics are tracked:
- **Operation Time**: Microseconds per encryption/decryption operation
- **Throughput (TPS)**: Transactions Per Second
- **Scaling**: How TPS scales with thread count

**TPS Calculation**:
```
TPS = (number_of_operations) / (end_time - start_time)

Example:
- 10,000 operations in 1.0 seconds
- TPS = 10,000 ops/sec
```

### Multi-threaded Testing
Thread counts tested: 1, 2, 4, 8, 16, 32 (until CPU saturation)

**Expected Behavior**:
- Linear scaling until CPU core count reached
- Diminishing returns after core saturation
- No race conditions or data corruption

### Performance Comparison Matrix
| Algorithm | AES-128 | AES-192 | AES-256 | SM4-128 |
|-----------|---------|----------|----------|----------|
| FF1       | X TPS     | Y TPS     | Z TPS     | W TPS    |
| FF3       | ...       | ...       | ...       | ...       |
| FF3-1     | ...       | ...       | ...       | ...       |

### Baseline Expectations
To be documented after initial benchmarks:
- FF1 with AES-128: ~X TPS (single-threaded)
- FF3 with AES-128: ~Y TPS (single-threaded)
- FF3-1 with AES-128: ~Z TPS (single-threaded)
- SM4 vs AES: ~W% difference

These baselines will be updated after actual measurements are available.

### Test Vector Coverage
From `tests/vectors.h`:
- **FF1**: 9 test vectors (3 × AES-128/192/256)
- **FF3**: 15 test vectors (5 × 3 key sizes, various tweaks)
- **FF3-1**: 15 test vectors (5 × 3 key sizes, various tweaks)
- **SM4**: 11 test vectors (FF1: 4 vectors, FF3: 3 vectors, FF3-1: 1 vector)

Total: **50 test vectors** for correctness validation.

### Performance Benchmark Design
**Benchmark Structure**:
```
tests/perf.c:
  - Parse tests/vectors.h
  - For each algorithm (FF1, FF3, FF3-1):
    - For each cipher (AES-128, AES-192, AES-256, SM4-128):
      - Warm-up (100 operations)
      - Measure N operations (10,000 recommended)
      - Calculate TPS
      - Test with multiple thread counts
      - Report results
```

**Reporting Format**:
```
Algorithm: FF1
Cipher: AES-128
Thread Count: 1 | 2  | 4  | 8  | 16
TPS:         X     | Y  | Z  | W  | V

(Repeat for all combinations)
```
