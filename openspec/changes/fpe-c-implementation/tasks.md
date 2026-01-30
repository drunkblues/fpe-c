## 1. Project Setup

- [ ] 1.1 Create project directory structure (src/, include/, tests/, examples/, docs/)
- [ ] 1.2 Set up CMake build system with OpenSSL dependency detection
- [ ] 1.3 Create basic CMakeLists.txt for library compilation
- [ ] 1.4 Add Unity testing framework integration (for native C tests)
- [ ] 1.5 Create version header (include/fpe/version.h)
- [ ] 1.6 Add .gitignore for build artifacts (if not already present)
- [ ] 1.7 Configure package.json with project metadata
- [ ] 1.8 Add cross-platform build configuration (Linux, macOS, Windows)
- [ ] 1.9 Add pkg-config support for library discovery

## 2. Core Data Structures

- [ ] 2.1 Define opaque FPE context structure (struct fpe_ctx_st) in internal headers
- [ ] 2.2 Define algorithm enums (FPE_ALGO, FPE_MODE) in public header
- [ ] 2.3 Create public API header (include/fpe.h) with all function declarations
- [ ] 2.4 Define algorithm-specific context structures (FF1, FF3, FF3-1) internally
- [ ] 2.5 Implement context initialization/deinitialization utilities

## 3. Utility Functions (fpe-utils)

- [ ] 3.1 Create utility module (src/utils.c, internal utils.h)
- [ ] 3.2 Implement character to index conversion with lookup table
- [ ] 3.3 Implement index to character conversion
- [ ] 3.4 Implement string to integer array conversion
- [ ] 3.5 Implement integer array to string conversion
- [ ] 3.6 Implement alphabet validation function (check for duplicates)
- [ ] 3.7 Implement radix validation (2-65536 range)
- [ ] 3.8 Implement null-termination guarantee for output strings
- [ ] 3.9 Implement buffer size validation
- [ ] 3.10 Implement tweak validation by algorithm (FF1 vs FF3/FF3-1)
- [ ] 3.11 Implement secure memory zeroing function
- [ ] 3.12 Add unit tests for all utility functions
- [ ] 3.13 Implement test vector parsing utilities (hex key/tweak/plaintext conversion)
- [ ] 3.14 Implement performance timing utilities (microseconds, TPS calculation)
- [ ] 3.15 Add unit tests for test vector parsing
- [ ] 3.16 Add unit tests for performance timing utilities
- [ ] 3.17 Add support for parsing test vectors from tests/vectors.h (FF1/FF3/FF3-1 with AES + SM4)

## 4. FF1 Algorithm Implementation

- [ ] 4.1 Create FF1 module (src/ff1.c, internal ff1.h)
- [ ] 4.2 Implement FF1 key derivation using AES-CMAC
- [ ] 4.3 Implement FF1 key derivation using SM4-CMAC
- [ ] 4.4 Implement FF1 round function F using AES-CMAC
- [ ] 4.5 Implement FF1 round function F using SM4-CMAC
- [ ] 4.6 Implement FF1 10-round Feistel network
- [ ] 4.7 Implement FF1 encryption function
- [ ] 4.8 Implement FF1 decryption function
- [ ] 4.9 Add input validation (min length, radix range)
- [ ] 4.10 Implement FF1-specific context initialization (with AES or SM4)
- [ ] 4.11 Add unit tests for FF1 key derivation with AES
- [ ] 4.12 Add unit tests for FF1 key derivation with SM4
- [ ] 4.13 Add unit tests for FF1 round function
- [ ] 4.14 Add unit tests for FF1 encryption/decryption with various radices
- [ ] 4.15 Implement NIST FF1 test vectors validation with AES (all 9 vectors from tests/vectors.h)
- [ ] 4.16 Implement equivalent FF1 test vectors with SM4 (all 4 vectors from tests/vectors.h)
- [ ] 4.17 Add tests for edge cases (empty tweak, boundary conditions)
- [ ] 4.18 Add tests for integer array validation
- [ ] 4.19 Verify all FF1 AES-128 test vectors from tests/vectors.h (empty/16-digit/20-digit tweaks)
- [ ] 4.20 Verify all FF1 AES-192 test vectors from tests/vectors.h (empty/16-digit/20-digit tweaks)
- [ ] 4.21 Verify all FF1 AES-256 test vectors from tests/vectors.h (empty/16-digit/20-digit tweaks)
- [ ] 4.22 Test FF1 reversibility (decrypt all ciphertexts from tests/vectors.h)
- [ ] 4.23 Benchmark FF1 performance (encryption/decryption time per operation)
- [ ] 4.24 Measure FF1 throughput (operations per second)
- [ ] 4.25 Test FF1 with multiple thread counts (1/2/4/8/16 threads) for TPS measurement
- [ ] 4.26 Verify FF1 TPS scales with thread count until CPU saturation
- [ ] 4.27 Verify FF1 thread safety (no race conditions, data corruption)
- [ ] 4.28 Compare FF1 AES-128 vs AES-192 vs AES-256 performance
- [ ] 4.29 Verify all FF1 SM4-128 test vectors from tests/vectors.h (empty/16-digit/20-digit tweaks, radix=10/36)
- [ ] 4.30 Test FF1 SM4 reversibility
- [ ] 4.31 Compare FF1 AES vs SM4 performance (same parameters)

## 5. FF3 Algorithm Implementation (Deprecated)

- [ ] 5.1 Create FF3 module (src/ff3.c, internal ff3.h)
- [ ] 5.2 Implement FF3 key derivation using AES-ECB
- [ ] 5.3 Implement FF3 key derivation using SM4-ECB
- [ ] 5.4 Implement FF3 round function F using AES-ECB
- [ ] 5.5 Implement FF3 round function F using SM4-ECB
- [ ] 5.6 Implement FF3 8-round Feistel network
- [ ] 5.7 Implement FF3 encryption function
- [ ] 5.8 Implement FF3 decryption function
- [ ] 5.9 Add input validation (min length, tweak length 56/64 bits)
- [ ] 5.10 Implement FF3-specific context initialization (with AES or SM4)
- [ ] 5.11 Add unit tests for FF3 key derivation with AES
- [ ] 5.12 Add unit tests for FF3 key derivation with SM4
- [ ] 5.13 Add unit tests for FF3 round function
- [ ] 5.14 Add unit tests for FF3 encryption/decryption with various radices
- [ ] 5.15 Implement NIST FF3 test vectors validation with AES (all 15 vectors from tests/vectors.h)
- [ ] 5.16 Implement equivalent FF3 test vectors with SM4 (all 3 vectors from tests/vectors.h)
- [ ] 5.17 Add tests for edge cases (invalid tweak length, minimum length enforcement)
- [ ] 5.18 Add deprecation notice to FF3 documentation
- [ ] 5.19 Verify all FF3 AES-128 test vectors from tests/vectors.h (56/64-bit/empty tweaks, 26-radix)
- [ ] 5.20 Verify all FF3 AES-192 test vectors from tests/vectors.h (56/64-bit/empty tweaks, 26-radix)
- [ ] 5.21 Verify all FF3 AES-256 test vectors from tests/vectors.h (56/64-bit/empty tweaks, 26-radix)
- [ ] 5.22 Test FF3 reversibility (decrypt all ciphertexts from tests/vectors.h)
- [ ] 5.23 Benchmark FF3 performance (encryption/decryption time per operation)
- [ ] 5.24 Measure FF3 throughput (operations per second)
- [ ] 5.25 Test FF3 with multiple thread counts (1/2/4/8/16 threads) for TPS measurement
- [ ] 5.26 Verify FF3 TPS scales with thread count until CPU saturation
- [ ] 5.27 Verify FF3 thread safety (no race conditions, data corruption)
- [ ] 5.28 Compare FF3 AES-128 vs AES-192 vs AES-256 performance
- [ ] 5.29 Verify all FF3 SM4-128 test vectors from tests/vectors.h (8-byte/7-byte/empty tweaks)
- [ ] 5.30 Test FF3 SM4 reversibility
- [ ] 5.31 Compare FF3 AES vs SM4 performance (same parameters)

## 6. FF3-1 Algorithm Implementation

- [ ] 6.1 Create FF3-1 module (src/ff3-1.c, internal ff3-1.h)
- [ ] 6.2 Implement FF3-1 key derivation using AES-ECB (with security fixes)
- [ ] 6.3 Implement FF3-1 key derivation using SM4-ECB (with security fixes)
- [ ] 6.4 Implement FF3-1 round function F using AES-ECB (with security fixes)
- [ ] 6.5 Implement FF3-1 round function F using SM4-ECB (with security fixes)
- [ ] 6.6 Implement FF3-1 8-round Feistel network (with security fixes)
- [ ] 6.7 Implement FF3-1 encryption function
- [ ] 6.8 Implement FF3-1 decryption function
- [ ] 6.9 Add input validation (min length, tweak length 56/64 bits)
- [ ] 6.10 Implement FF3-1-specific context initialization (with AES or SM4)
- [ ] 6.11 Add unit tests for FF3-1 key derivation with AES
- [ ] 6.12 Add unit tests for FF3-1 key derivation with SM4
- [ ] 6.13 Add unit tests for FF3-1 round function
- [ ] 6.14 Add unit tests for FF3-1 encryption/decryption with various radices
- [ ] 6.15 Implement NIST FF3-1 test vectors validation with AES (all 15 vectors from tests/vectors.h)
- [ ] 6.16 Implement equivalent FF3-1 test vectors with SM4 (all 1 vectors from tests/vectors.h)
- [ ] 6.17 Add tests for edge cases (invalid tweak length, minimum length enforcement)
- [ ] 6.18 Add tests verifying security fixes (different from FF3 output)
- [ ] 6.19 Verify all FF3-1 AES-128 test vectors from tests/vectors.h (56/64-bit/empty tweaks, 26-radix)
- [ ] 6.20 Verify all FF3-1 AES-192 test vectors from tests/vectors.h (56/64-bit/empty tweaks, 26-radix)
- [ ] 6.21 Verify all FF3-1 AES-256 test vectors from tests/vectors.h (56/64-bit/empty tweaks, 26-radix)
- [ ] 6.22 Test FF3-1 reversibility (decrypt all ciphertexts from tests/vectors.h)
- [ ] 6.23 Benchmark FF3-1 performance (encryption/decryption time per operation)
- [ ] 6.24 Measure FF3-1 throughput (operations per second)
- [ ] 6.25 Test FF3-1 with multiple thread counts (1/2/4/8/16 threads) for TPS measurement
- [ ] 6.26 Verify FF3-1 TPS scales with thread count until CPU saturation
- [ ] 6.27 Verify FF3-1 thread safety (no race conditions, data corruption)
- [ ] 6.28 Compare FF3-1 vs FF3 performance and output differences
- [ ] 6.29 Verify all FF3-1 SM4-128 test vectors from tests/vectors.h (7-byte tweak)
- [ ] 6.30 Test FF3-1 SM4 reversibility
- [ ] 6.31 Compare FF3-1 AES vs SM4 performance (same parameters)

## 7. SM4 Algorithm Support

- [ ] 7.1 Add OpenSSL version detection in CMake
- [ ] 7.2 Implement conditional compilation for SM4 support (HAVE_OPENSSL_SM4)
- [ ] 7.3 Add runtime check for SM4 availability
- [ ] 7.4 Implement SM4-CMAC wrapper for FF1
- [ ] 7.5 Implement SM4-ECB wrapper for FF3/FF3-1
- [ ] 7.6 Add unit tests for SM4 key derivation
- [ ] 7.7 Add unit tests for SM4 round functions
- [ ] 7.8 Test with OpenSSL 3.0+ (full SM4 support)
- [ ] 7.9 Test with OpenSSL 1.1.1+ (experimental SM4 support)
- [ ] 7.10 Test error handling when SM4 unavailable
- [ ] 7.11 Add documentation about SM4 version requirements
- [ ] 7.12 Verify all FF1 SM4 test vectors from tests/vectors.h (4 vectors: empty/16-digit/20-digit tweaks)
- [ ] 7.13 Verify all FF3 SM4 test vectors from tests/vectors.h (3 vectors: 8-byte/7-byte/empty tweaks)
- [ ] 7.14 Verify all FF3-1 SM4 test vectors from tests/vectors.h (1 vector: 7-byte tweak)
- [ ] 7.15 Test SM4 reversibility for all vectors
- [ ] 7.16 Benchmark SM4 performance (encryption/decryption time per operation)
- [ ] 7.17 Measure SM4 throughput (operations per second)
- [ ] 7.18 Test SM4 with multiple thread counts (1/2/4/8/16 threads) for TPS measurement
- [ ] 7.19 Verify SM4 TPS scales with thread count until CPU saturation
- [ ] 7.20 Compare SM4 vs AES performance for each algorithm (FF1/FF3/FF3-1)
- [ ] 7.21 Document performance differences between AES and SM4 (if any significant)

## 8. Public API Implementation (fpe-api)

- [ ] 8.1 Implement FPE_CTX_new function (heap allocation)
- [ ] 8.2 Implement FPE_CTX_free function (cleanup and zeroing)
- [ ] 8.3 Implement FPE_CTX_init function (unified initialization)
- [ ] 8.4 Implement FPE_encrypt function (unified dispatcher)
- [ ] 8.5 Implement FPE_decrypt function (unified dispatcher)
- [ ] 8.6 Implement FPE_encrypt_str function (string API)
- [ ] 8.7 Implement FPE_decrypt_str function (string API)
- [ ] 8.8 Add parameter validation (NULL checks, buffer sizes)
- [ ] 8.9 Support in-place encryption/decryption (same buffer)
- [ ] 8.10 Implement key length validation (128/192/256 for AES, 128 for SM4)
- [ ] 8.11 Implement radix validation (2-65536)
- [ ] 8.12 Add unit tests for context lifecycle (new/init/free)
- [ ] 8.13 Add unit tests for unified API dispatch (FF1/FF3/FF3-1)
- [ ] 8.14 Add unit tests for string API (various alphabets)
- [ ] 8.15 Add unit tests for in-place operations
- [ ] 8.16 Add thread safety tests with multiple contexts
- [ ] 8.17 Add tests for shared context (undefined behavior documentation)

## 9. One-shot API Implementation

- [ ] 9.1 Implement FPE_encrypt_oneshot function (integer arrays)
- [ ] 9.2 Implement FPE_decrypt_oneshot function (integer arrays)
- [ ] 9.3 Implement FPE_encrypt_str_oneshot function
- [ ] 9.4 Implement FPE_decrypt_str_oneshot function
- [ ] 9.5 Add unit tests for one-shot encryption/decryption
- [ ] 9.6 Add unit tests for one-shot string operations
- [ ] 9.7 Add tests for error handling in one-shot functions
- [ ] 9.8 Benchmark one-shot vs context reuse performance

## 10. Build and Packaging

- [ ] 10.1 Configure CMake to build static library (libfpe.a)
- [ ] 10.2 Configure CMake to build shared library (libfpe.so)
- [ ] 10.3 Add proper versioning to shared library
- [ ] 10.4 Configure installation rules for headers and libraries
- [ ] 10.5 Create Makefile wrapper for convenience
- [ ] 10.6 Add CI/CD configuration (GitHub Actions or similar)
- [ ] 10.7 Test build on Linux
- [ ] 10.8 Test build on macOS
- [ ] 10.9 Test build on Windows (if applicable)
- [ ] 10.10 Test build with multiple OpenSSL versions (1.1.1, 3.0)

## 11. Comprehensive Testing

- [ ] 11.1 Add integration tests for full encryption/decryption cycles
- [ ] 11.2 Add performance benchmarks for FF1, FF3, FF3-1
- [ ] 11.3 Add performance benchmarks comparing AES vs SM4
- [ ] 11.4 Add fuzzing tests for input validation
- [ ] 11.5 Add memory leak detection (Valgrind/AddressSanitizer)
- [ ] 11.6 Add property-based tests for reversibility
- [ ] 11.7 Test with various input sizes and radices
- [ ] 11.8 Verify thread safety with concurrent operations
- [ ] 11.9 Add tests for all error conditions
- [ ] 11.10 Add tests for boundary conditions (minimum/maximum radix)
- [ ] 11.11 Add tests for all NIST test vectors (hardcoded in tests/vectors.h)
- [ ] 11.12 Verify no Python dependencies in test suite
- [ ] 11.13 Implement test runner that loads tests/vectors.h and runs all tests
- [ ] 11.14 Create performance benchmark suite with TPS reporting
- [ ] 11.15 Add multi-threaded performance tests (1/2/4/8/16/32 threads)
- [ ] 11.16 Measure and report TPS for each algorithm (FF1/FF3/FF3-1) with AES
- [ ] 11.17 Measure and report TPS for each algorithm (FF1/FF3/FF3-1) with SM4
- [ ] 11.18 Compare TPS between FF1, FF3, FF3-1 (same cipher, same parameters)
- [ ] 11.19 Compare TPS between AES and SM4 (same algorithm, same parameters)
- [ ] 11.20 Test TPS scaling with different input lengths (10/16/20/100 digits)
- [ ] 11.21 Verify TPS scales linearly until CPU saturation point
- [ ] 11.22 Document CPU core count vs optimal thread count for TPS
- [ ] 11.23 Verify all AES test vectors from tests/vectors.h (39 vectors)
- [ ] 11.24 Verify all SM4 test vectors from tests/vectors.h (11 vectors)
- [ ] 11.25 Verify combined test coverage (50 vectors total: 39 AES + 11 SM4)

## 12. Documentation

- [ ] 12.1 Create README.md with project overview and build instructions
- [ ] 12.2 Add API reference documentation (all functions)
- [ ] 12.3 Document FF1 algorithm implementation details
- [ ] 12.4 Document FF3 algorithm implementation details (with deprecation notice)
- [ ] 12.5 Document FF3-1 algorithm implementation details
- [ ] 12.6 Document SM4 support and version requirements
- [ ] 12.7 Add architecture and design documentation
- [ ] 12.8 Document security considerations and best practices
- [ ] 12.9 Document performance characteristics
- [ ] 12.10 Document thread safety guarantees
- [ ] 12.11 Document error handling and return values
- [ ] 12.12 Add examples for unified API usage
- [ ] 12.13 Add examples for one-shot API usage
- [ ] 12.14 Add examples for string API usage
- [ ] 12.15 Add migration guide from FF3 to FF3-1
- [ ] 12.16 Document tests/vectors.h format and usage
- [ ] 12.17 Document performance baseline expectations (encryption/decryption time)
- [ ] 12.18 Document TPS (Transactions Per Second) measurement methodology
- [ ] 12.19 Document performance characteristics of FF1, FF3, FF3-1
- [ ] 12.20 Document performance comparison between AES and SM4
- [ ] 12.21 Document optimal thread count for multi-threaded operations
- [ ] 12.22 Document how to run performance benchmarks
- [ ] 12.23 Document performance expectations by CPU architecture (x86, ARM, etc.)

## 13. Examples

- [ ] 13.1 Create basic encryption example (examples/basic.c)
- [ ] 13.2 Create credit card encryption example
- [ ] 13.3 Create custom alphabet example
- [ ] 13.4 Create SM4 encryption example
- [ ] 13.5 Create multi-threaded usage example
- [ ] 13.6 Create in-place encryption example
- [ ] 13.7 Create one-shot encryption example
- [ ] 13.8 Create example showing FF3-1 usage
- [ ] 13.9 Create example showing error handling
- [ ] 13.10 Create example comparing FF1, FF3, FF3-1
- [ ] 13.11 Add Makefile for building examples
- [ ] 13.12 Add README for examples directory
- [ ] 13.13 Create performance benchmark example (tests/perf.c)
- [ ] 13.14 Create multi-threaded TPS benchmark example
- [ ] 13.15 Create example showing AES vs SM4 performance comparison
- [ ] 13.16 Create example showing tests/vectors.h usage
- [ ] 13.17 Create example showing TPS calculation and reporting
- [ ] 13.18 Add README for performance examples

## 14. Final Validation

- [ ] 14.1 Run all unit tests and verify 100% pass rate
- [ ] 14.2 Verify all NIST test vectors pass (all 39 AES vectors from tests/vectors.h)
- [ ] 14.3 Verify all SM4 test vectors pass (all 11 SM4 vectors from tests/vectors.h)
- [ ] 14.4 Build and test on Linux
- [ ] 14.5 Build and test on macOS
- [ ] 14.6 Build and test on Windows (if applicable)
- [ ] 14.7 Run code static analysis (clang-tidy/cppcheck)
- [ ] 14.8 Check for memory leaks with Valgrind
- [ ] 14.9 Verify documentation is complete and accurate
- [ ] 14.10 Final code review and cleanup
- [ ] 14.11 Verify ABI stability (opaque pointer encapsulation)
- [ ] 14.12 Verify C++ compatibility (extern "C" linkage)
- [ ] 14.13 Test with OpenSSL 1.1.1 (experimental SM4)
- [ ] 14.14 Test with OpenSSL 3.0+ (full SM4 support)
- [ ] 14.15 Test with OpenSSL < 1.1.1 (no SM4, verify error handling)
- [ ] 14.16 Run performance benchmarks and verify results are reasonable
- [ ] 14.17 Verify TPS measurements are accurate and reproducible
- [ ] 14.18 Verify thread safety in multi-threaded performance tests
- [ ] 14.19 Verify performance targets are met (document baseline expectations)
- [ ] 14.20 Document final performance characteristics (AES vs SM4, FF1 vs FF3 vs FF3-1)
- [ ] 14.21 Verify all 50+ test vectors pass (AES + SM4 combined)
