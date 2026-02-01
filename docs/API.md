# FPE-C API Reference

This document provides comprehensive API documentation for the FPE-C library, a high-performance Format-Preserving Encryption implementation supporting FF1, FF3, and FF3-1 algorithms with both AES and SM4 ciphers.

## Table of Contents

- [Core Data Types](#core-data-types)
- [Context Management](#context-management)
- [Encryption/Decryption Operations](#encryptiondecryption-operations)
- [One-Shot API](#one-shot-api)
- [String API](#string-api)
- [Error Codes](#error-codes)
- [Constants and Enumerations](#constants-and-enumerations)

---

## Core Data Types

### FPE_CTX

```c
typedef struct FPE_CTX FPE_CTX;
```

Opaque structure representing an FPE context. Contains algorithm state, cipher configuration, and operational parameters.

**Lifecycle:**
1. Create with `FPE_CTX_new()`
2. Initialize with `FPE_CTX_init()`
3. Use for encryption/decryption operations
4. Free with `FPE_CTX_free()`

**Thread Safety:** Each FPE_CTX instance is NOT thread-safe. Use separate contexts per thread for concurrent operations.

---

## Context Management

### FPE_CTX_new

```c
FPE_CTX* FPE_CTX_new(void);
```

Creates a new FPE context.

**Returns:**
- Pointer to newly allocated FPE_CTX on success
- NULL on allocation failure

**Example:**
```c
FPE_CTX *ctx = FPE_CTX_new();
if (!ctx) {
    fprintf(stderr, "Failed to create FPE context\n");
    return -1;
}
```

---

### FPE_CTX_init

```c
int FPE_CTX_init(FPE_CTX *ctx, FPE_MODE mode, FPE_ALGO algo,
                 const unsigned char *key, int key_bits, unsigned int radix);
```

Initializes an FPE context with specified parameters.

**Parameters:**
- `ctx` - FPE context to initialize
- `mode` - Algorithm mode (FPE_MODE_FF1, FPE_MODE_FF3, FPE_MODE_FF3_1)
- `algo` - Cipher algorithm (FPE_ALGO_AES, FPE_ALGO_SM4)
- `key` - Encryption key (16, 24, or 32 bytes for AES; 16 bytes for SM4)
- `key_bits` - Key length in bits (128, 192, or 256 for AES; 128 for SM4)
- `radix` - Radix (2-65536 for FF1; 2-256 for FF3/FF3-1)

**Returns:**
- 0 on success
- Non-zero error code on failure

**Example:**
```c
unsigned char key[16] = { /* 128-bit key */ };
int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
if (ret != 0) {
    fprintf(stderr, "Failed to initialize context: %d\n", ret);
    FPE_CTX_free(ctx);
    return -1;
}
```

**Constraints:**
- FF1: radix must be in [2, 65536]
- FF3/FF3-1: radix must be in [2, 256]
- Key size must match key_bits parameter
- SM4 only supports 128-bit keys

---

### FPE_CTX_free

```c
void FPE_CTX_free(FPE_CTX *ctx);
```

Frees an FPE context and securely clears sensitive data.

**Parameters:**
- `ctx` - FPE context to free (can be NULL)

**Example:**
```c
FPE_CTX_free(ctx);
ctx = NULL;  // Good practice
```

---

## Encryption/Decryption Operations

### FPE_encrypt

```c
int FPE_encrypt(FPE_CTX *ctx, const unsigned int *plaintext,
                unsigned int *ciphertext, int length,
                const unsigned char *tweak, int tweak_len);
```

Encrypts data using the initialized FPE context.

**Parameters:**
- `ctx` - Initialized FPE context
- `plaintext` - Input array of unsigned integers (each element < radix)
- `ciphertext` - Output array for encrypted data (same size as plaintext)
- `length` - Number of elements to encrypt
- `tweak` - Tweak value for additional security
- `tweak_len` - Length of tweak in bytes

**Returns:**
- 0 on success
- Non-zero error code on failure

**Constraints:**
- FF1: length ≥ 2, tweak_len in [0, 256]
- FF3: length even and in [4, 56], tweak_len = 8
- FF3-1: length even and in [4, 56], tweak_len = 7

**Example:**
```c
unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
unsigned int ciphertext[10];
unsigned char tweak[8] = {0};

int ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8);
if (ret != 0) {
    fprintf(stderr, "Encryption failed: %d\n", ret);
}
```

**Thread Safety:** Safe when each thread uses its own FPE_CTX instance.

---

### FPE_decrypt

```c
int FPE_decrypt(FPE_CTX *ctx, const unsigned int *ciphertext,
                unsigned int *plaintext, int length,
                const unsigned char *tweak, int tweak_len);
```

Decrypts data using the initialized FPE context.

**Parameters:**
- `ctx` - Initialized FPE context (same parameters as encryption)
- `ciphertext` - Input array of encrypted unsigned integers
- `plaintext` - Output array for decrypted data
- `length` - Number of elements to decrypt
- `tweak` - Tweak value (must match encryption tweak)
- `tweak_len` - Length of tweak in bytes

**Returns:**
- 0 on success
- Non-zero error code on failure

**Example:**
```c
unsigned int decrypted[10];
int ret = FPE_decrypt(ctx, ciphertext, decrypted, 10, tweak, 8);
if (ret == 0) {
    // Verify: decrypted should equal original plaintext
}
```

---

## One-Shot API

Convenience functions for single-use encryption/decryption without explicit context management.

### FPE_encrypt_oneshot

```c
int FPE_encrypt_oneshot(FPE_MODE mode, FPE_ALGO algo,
                        const unsigned char *key, int key_bits,
                        unsigned int radix,
                        const unsigned int *plaintext, unsigned int *ciphertext,
                        int length, const unsigned char *tweak, int tweak_len);
```

Performs encryption without requiring separate context creation/initialization.

**Use Cases:**
- Infrequent encryption operations
- Simple scripts or one-off tasks
- Applications where code simplicity is prioritized over performance

**Performance:** 1.1-1.5x slower than context reuse. For high-throughput applications, use context-based API.

**Example:**
```c
unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
unsigned int ciphertext[10];
unsigned char key[16] = { /* your key */ };
unsigned char tweak[8] = {0};

int ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10,
                               plaintext, ciphertext, 10, tweak, 8);
```

---

### FPE_decrypt_oneshot

```c
int FPE_decrypt_oneshot(FPE_MODE mode, FPE_ALGO algo,
                        const unsigned char *key, int key_bits,
                        unsigned int radix,
                        const unsigned int *ciphertext, unsigned int *plaintext,
                        int length, const unsigned char *tweak, int tweak_len);
```

One-shot decryption counterpart to `FPE_encrypt_oneshot`.

---

## String API

High-level API for encrypting/decrypting strings with custom alphabets.

### FPE_encrypt_str

```c
int FPE_encrypt_str(FPE_CTX *ctx, const char *plaintext, char *ciphertext,
                    const char *alphabet, const unsigned char *tweak, int tweak_len);
```

Encrypts a string using a custom alphabet.

**Parameters:**
- `ctx` - Initialized FPE context with radix matching alphabet length
- `plaintext` - Input string (all characters must be in alphabet)
- `ciphertext` - Output buffer (same length as plaintext + null terminator)
- `alphabet` - Character set defining valid characters
- `tweak` - Tweak value
- `tweak_len` - Length of tweak in bytes

**Returns:**
- 0 on success
- Non-zero error code on failure

**Example:**
```c
const char *alphabet = "0123456789";  // Decimal digits
char plaintext[] = "1234567890";
char ciphertext[11];  // Length + 1 for null terminator

int ret = FPE_encrypt_str(ctx, plaintext, ciphertext, alphabet, tweak, 8);
if (ret == 0) {
    printf("Encrypted: %s\n", ciphertext);
}
```

**Common Alphabets:**
- Decimal: "0123456789"
- Hex (lowercase): "0123456789abcdef"
- Alphanumeric: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
- Credit card: "0123456789" (for PCI-DSS tokenization)

---

### FPE_decrypt_str

```c
int FPE_decrypt_str(FPE_CTX *ctx, const char *ciphertext, char *plaintext,
                    const char *alphabet, const unsigned char *tweak, int tweak_len);
```

Decrypts a string encrypted with `FPE_encrypt_str`.

---

### FPE_encrypt_str_oneshot

```c
int FPE_encrypt_str_oneshot(FPE_MODE mode, FPE_ALGO algo,
                            const unsigned char *key, int key_bits,
                            const char *plaintext, char *ciphertext,
                            const char *alphabet,
                            const unsigned char *tweak, int tweak_len);
```

One-shot string encryption without context management.

**Example:**
```c
char plaintext[] = "secret123";
char ciphertext[10];
unsigned char key[16] = { /* your key */ };
unsigned char tweak[8] = {0};

int ret = FPE_encrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                   plaintext, ciphertext, "0123456789abcdefghijklmnopqrstuvwxyz",
                                   tweak, 8);
```

---

### FPE_decrypt_str_oneshot

```c
int FPE_decrypt_str_oneshot(FPE_MODE mode, FPE_ALGO algo,
                            const unsigned char *key, int key_bits,
                            const char *ciphertext, char *plaintext,
                            const char *alphabet,
                            const unsigned char *tweak, int tweak_len);
```

One-shot string decryption counterpart.

---

## Error Codes

All functions returning `int` use the following error codes:

| Code | Constant | Description |
|------|----------|-------------|
| 0 | - | Success |
| -1 | - | General error (invalid parameters) |
| -2 | - | Memory allocation failure |
| -3 | - | Unsupported mode or algorithm |
| -4 | - | Invalid key size |
| -5 | - | Invalid radix |
| -6 | - | Invalid input length |
| -7 | - | Invalid tweak length |
| -8 | - | Invalid character in string (not in alphabet) |
| -9 | - | SM4 not available (requires OpenSSL 3.0+) |

---

## Constants and Enumerations

### FPE_MODE

Algorithm mode selection:

```c
typedef enum {
    FPE_MODE_FF1,      // NIST SP 800-38G FF1 (recommended)
    FPE_MODE_FF3,      // NIST SP 800-38G FF3 (deprecated - use FF3-1)
    FPE_MODE_FF3_1     // FF3-1 (secure version with fixes)
} FPE_MODE;
```

**Recommendations:**
- **FF1**: Best for most use cases. Supports wide range of radix (2-65536) and input lengths (≥2).
- **FF3-1**: Use when FF3 compatibility is required but with security fixes. Limited to radix ≤256.
- **FF3**: Deprecated. Only use for legacy compatibility.

---

### FPE_ALGO

Cipher algorithm selection:

```c
typedef enum {
    FPE_ALGO_AES,      // AES cipher (recommended, widely supported)
    FPE_ALGO_SM4       // SM4 cipher (Chinese standard, requires OpenSSL 3.0+)
} FPE_ALGO;
```

**Performance:**
- AES-128: ~90K ops/sec (single-threaded)
- SM4-128: ~75K ops/sec (single-threaded)

---

## In-Place Operations

All encryption/decryption functions support in-place operations where input and output buffers are the same:

```c
unsigned int data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

// Encrypt in-place
FPE_encrypt(ctx, data, data, 10, tweak, 8);

// Decrypt in-place
FPE_decrypt(ctx, data, data, 10, tweak, 8);
```

---

## Multi-Threading Guidelines

### Recommended Pattern: Thread-Local Contexts

Each thread should create and manage its own FPE_CTX instance:

```c
void* worker_thread(void* arg) {
    // Create thread-local context
    FPE_CTX *ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    // Perform operations
    for (int i = 0; i < num_operations; i++) {
        FPE_encrypt(ctx, plaintext, ciphertext, length, tweak, tweak_len);
    }
    
    // Cleanup
    FPE_CTX_free(ctx);
    return NULL;
}
```

**Benefits:**
- No synchronization overhead
- Maximum performance
- Thread-safe by design

### Anti-Pattern: Shared Context

**DO NOT** share a single FPE_CTX across multiple threads without external synchronization. The context is not thread-safe and will result in data corruption and undefined behavior.

---

## Performance Considerations

### Context Reuse vs One-Shot API

**Benchmark Results** (1000 operations):

| API | FF1 | FF3 | FF3-1 |
|-----|-----|-----|-------|
| Context Reuse | 10.96 ms | 14.21 ms | 14.02 ms |
| One-Shot | 16.22 ms | 15.38 ms | 14.89 ms |
| **Speedup** | **1.48x** | **1.08x** | **1.06x** |

**Recommendations:**
- **High-throughput:** Use context reuse (FPE_CTX_new/init/free)
- **Low-frequency:** Use one-shot API for simpler code
- **Batch processing:** Create one context, process all items, then free

### Multi-Threading Scaling

Typical scaling efficiency:

| Threads | TPS Speedup | Efficiency |
|---------|-------------|------------|
| 1 | 1.0x | 100% |
| 2 | 1.5x | 75% |
| 4 | 2.0x | 50% |
| 8 | 2.5x | 31% |
| 16 | 3.0x | 19% |

Performance scales well up to CPU core count, then efficiency degrades due to saturation.

---

## Complete Example

```c
#include <stdio.h>
#include <string.h>
#include "fpe.h"

int main(void) {
    // Create and initialize context
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    if (ret != 0) {
        fprintf(stderr, "Initialization failed: %d\n", ret);
        FPE_CTX_free(ctx);
        return 1;
    }
    
    // Encrypt credit card number
    unsigned int plaintext[16] = {4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5};
    unsigned int ciphertext[16];
    unsigned char tweak[8] = {0};
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext, 16, tweak, 8);
    if (ret != 0) {
        fprintf(stderr, "Encryption failed: %d\n", ret);
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Plaintext:  ");
    for (int i = 0; i < 16; i++) printf("%d", plaintext[i]);
    printf("\n");
    
    printf("Ciphertext: ");
    for (int i = 0; i < 16; i++) printf("%d", ciphertext[i]);
    printf("\n");
    
    // Decrypt
    unsigned int decrypted[16];
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 16, tweak, 8);
    if (ret != 0) {
        fprintf(stderr, "Decryption failed: %d\n", ret);
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Decrypted:  ");
    for (int i = 0; i < 16; i++) printf("%d", decrypted[i]);
    printf("\n");
    
    // Verify
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("✓ Decryption successful!\n");
    } else {
        printf("✗ Decryption mismatch!\n");
    }
    
    // Cleanup
    FPE_CTX_free(ctx);
    return 0;
}
```

---

## See Also

- [Security Best Practices](SECURITY.md) - Security guidelines and considerations
- [Performance Guide](PERFORMANCE.md) - Detailed performance analysis and tuning
- [Algorithm Details](ALGORITHMS.md) - Technical details of FF1, FF3, and FF3-1
- [Examples](../examples/) - Complete example programs
