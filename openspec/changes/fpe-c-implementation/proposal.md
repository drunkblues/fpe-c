# Proposal: High-Performance FPE Library (Clean Build)

## Intent (意图)
本项目旨在**从零开始构建**一个工业级的、符合 NIST SP 800-38G 标准的格式保留加密 (FPE) C 语言库。该库将支持 AES 和 SM4 算法，提供极致的性能和安全性，并包含一个**完全原生的 C 语言测试套件**，以实现零外部运行时依赖的验证能力。

## Context & Problem (背景与问题)
现有的 FPE 开源实现往往存在架构陈旧、接口设计不合理（暴露底层依赖）、以及测试流程依赖脚本语言（如 Python）等问题。这限制了它们在嵌入式设备、高安全环境或纯 C 工具链中的集成与部署。我们需要一个干净、独立且自包含的全新实现。

## Goals (目标)
1.  **全新架构 (Clean Architecture)**: 使用"不透明指针" (Opaque Pointer) 模式设计 API，彻底隐藏 OpenSSL 等底层库的实现细节，确保 ABI 稳定性。
2.  **原生验证 (Native Verification)**: 摒弃 Python 脚本，将所有 NIST 标准测试向量硬编码到 C 语言单元测试中，实现 `make test` 即验证。
3.  **多算法支持 (Multi-Algo)**: 原生支持 AES (128/192/256) 和国密 SM4 (128)。
4.  **算法完备性**: 完整实现 FF1, FF3 (已弃用, 保留兼容), FF3-1 标准。
5.  **统一接口 (Unified API)**: 提供统一的上层接口屏蔽算法差异，运行时动态分发。
6.  **便利性 API**: 提供 One-shot 无状态 API 和字符串 API，简化使用。

## User Stories (用户故事)
* **嵌入式工程师**: 我需要一个只有 `.h` 和 `.so/.a` 的库，没有任何 Python 依赖，能直接交叉编译并在裸机或 RTOS 上运行测试。
* **安全架构师**: 我需要一个明确支持 SM4 FPE 的库，且其接口设计清晰，不会引入不必要的头文件污染。
* **应用开发者**: 我希望能够用一行代码完成加密操作（One-shot API），或者使用字符串 API 直接加密信用卡号，而不需要手动处理整数数组。

## What Changes

### 核心实现
- **实现 FF1 算法** (10 轮 Feistel 网络，基于 AES-CMAC/SM4-CMAC)
- **实现 FF3 算法** (8 轮 Feistel 网络，基于 AES-ECB/SM4-ECB) - *已弃用，保留兼容*
- **实现 FF3-1 算法** (FF3 改进版本，修复安全问题)
- **支持 AES 算法** (128/192/256 位密钥)
- **支持 SM4 算法** (128 位密钥，符合 GB/T 32907-2016)

### API 设计
- **不透明上下文** (FPE_CTX): 堆分配的上下文，隐藏 OpenSSL 依赖
- **统一加密/解密接口**: FPE_encrypt/FPE_decrypt 根据上下文自动分发
- **One-shot 无状态 API**: 一次性操作，无需管理上下文生命周期
- **字符串 API**: 支持自定义字母表，直接操作字符串
- **整数数组 API**: 底层表示，适用于高性能场景

### 测试与验证
- **原生 C 测试套件**: 无需 Python，直接运行 C 单元测试
- **NIST 测试向量**: 硬编码所有标准测试向量
- **跨平台测试**: 支持 Linux、macOS、Windows

## Capabilities

### New Capabilities
- `fpe-ff1`: FF1 算法实现 (10 轮，CMAC，灵活的 tweak)
- `fpe-ff3`: FF3 算法实现 (8 轮，ECB，已弃用)
- `fpe-ff3-1`: FF3-1 算法实现 (FF3 改进版，更安全)
- `fpe-api`: 统一 C API（上下文管理、加密/解密、One-shot）
- `fpe-sm4`: SM4 国密算法支持
- `fpe-utils`: 字符串工具、字母表转换

### Modified Capabilities
- (无 - 这是一个全新的实现)

## Impact

- **新增 C 库**: `libfpe.a` (静态库) / `libfpe.so` (动态库)
- **公共头文件**: `include/fpe.h` (统一 API)
- **测试框架**: 原生 C 测试套件
- **依赖**: OpenSSL (用于 AES/CMAC)，可选 SM4 支持
- **兼容性**: OpenSSL 3.0+ (SM4 完整支持)，OpenSSL 1.1+ (AES 完整支持)
- **无破坏性变更**: 新项目，无需迁移

## Non-Goals

- **FF3 主要算法**: FF3 被 NIST 标记为不安全，主要推荐使用 FF3-1
- **其他 FPE 算法**: BPS、VAE3 等不在范围内
- **侧信道防护**: 超出 OpenSSL 提供的保护范围
- **硬件加速**: AES-NI 等硬件加速通过 OpenSSL 提供
- **FIPS 140-2 认证**: 依赖 OpenSSL 的认证模块
- **C++ 封装**: 提供 C++ 友好的接口但不提供 C++ 类
