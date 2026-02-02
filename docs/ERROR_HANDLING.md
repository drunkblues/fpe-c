# Error Handling in FPE-C

This document describes error handling mechanisms, return codes, and best practices for robust error management in FPE-C applications.

## Table of Contents

- [Error Handling Overview](#error-handling-overview)
- [Return Codes](#return-codes)
- [Function-Specific Errors](#function-specific-errors)
- [Error Handling Patterns](#error-handling-patterns)
- [Common Error Scenarios](#common-error-scenarios)
- [Debugging Tips](#debugging-tips)

---

## Error Handling Overview

### Design Philosophy

FPE-C uses **integer return codes** for error reporting:
- **0** = Success
- **-1** = Error (generic failure)
- **NULL** = Allocation failure (for functions returning pointers)

This simple scheme provides:
- ✅ Clear success/failure indication
- ✅ No exceptions (C-compatible)
- ✅ Consistent across all functions
- ✅ Easy integration with existing code

### Error Checking Requirement

**CRITICAL:** Always check return values from FPE-C functions.

❌ **Bad:**
```c
FPE_CTX_init(ctx, mode, algo, key, bits, radix);  // Ignoring return value
FPE_encrypt(ctx, in, out, len, tweak, tweak_len);  // May fail silently
```

✅ **Good:**
```c
if (FPE_CTX_init(ctx, mode, algo, key, bits, radix) != 0) {
    fprintf(stderr, "Failed to initialize context\n");
    FPE_CTX_free(ctx);
    return -1;
}

if (FPE_encrypt(ctx, in, out, len, tweak, tweak_len) != 0) {
    fprintf(stderr, "Encryption failed\n");
    return -1;
}
```

---

## Return Codes

### Standard Return Values

| Return Value | Meaning | Context |
|--------------|---------|---------|
| **0** | Success | All functions returning int |
| **-1** | Failure | All functions returning int |
| **NULL** | Allocation failure | FPE_CTX_new() |
| **Non-NULL** | Success (pointer) | FPE_CTX_new() |

### Functions by Return Type

**Integer return (0 = success, -1 = error):**
- `FPE_CTX_init()`
- `FPE_encrypt()`
- `FPE_decrypt()`
- `FPE_encrypt_str()`
- `FPE_decrypt_str()`
- `FPE_encrypt_oneshot()`
- `FPE_decrypt_oneshot()`
- `FPE_encrypt_str_oneshot()`
- `FPE_decrypt_str_oneshot()`

**Pointer return (NULL = error):**
- `FPE_CTX_new()`

**Void return (no error indication):**
- `FPE_CTX_free()`

---

## Function-Specific Errors

### FPE_CTX_new()

**Signature:**
```c
FPE_CTX* FPE_CTX_new(void);
```

**Returns:**
- Pointer to new context on success
- NULL on allocation failure

**Error conditions:**
- Memory allocation failed (out of memory)

**Example:**
```c
FPE_CTX *ctx = FPE_CTX_new();
if (!ctx) {
    fprintf(stderr, "Failed to allocate context: out of memory\n");
    return -1;
}
```

---

### FPE_CTX_init()

**Signature:**
```c
int FPE_CTX_init(FPE_CTX *ctx, FPE_MODE mode, FPE_ALGO algo,
                 const unsigned char *key, unsigned int bits,
                 unsigned int radix);
```

**Returns:**
- 0 on success
- -1 on error

**Error conditions:**

| Error | Cause |
|-------|-------|
| **NULL context** | ctx parameter is NULL |
| **NULL key** | key parameter is NULL |
| **Invalid mode** | mode not FPE_MODE_FF1/FF3/FF3_1 |
| **Invalid algorithm** | algo not FPE_ALGO_AES/SM4 |
| **Invalid key size** | bits not 128/192/256 (AES) or 128 (SM4) |
| **Invalid radix** | radix < 2 or > 65536 (all modes: FF1, FF3, FF3-1) |
| **SM4 unavailable** | SM4 requested but OpenSSL doesn't support it |
| **OpenSSL error** | Cipher initialization failed |

**Example:**
```c
int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
if (ret != 0) {
    fprintf(stderr, "Context initialization failed: ");
    
    // Check common issues
    if (key == NULL) {
        fprintf(stderr, "key is NULL\n");
    } else {
        fprintf(stderr, "invalid parameters or OpenSSL error\n");
    }
    
    FPE_CTX_free(ctx);
    return -1;
}
```

---

### FPE_encrypt() / FPE_decrypt()

**Signature:**
```c
int FPE_encrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                unsigned int len, const unsigned char *tweak,
                unsigned int tweak_len);
                
int FPE_decrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                unsigned int len, const unsigned char *tweak,
                unsigned int tweak_len);
```

**Returns:**
- 0 on success
- -1 on error

**Error conditions:**

| Error | Cause |
|-------|-------|
| **NULL context** | ctx parameter is NULL |
| **NULL input** | in parameter is NULL |
| **NULL output** | out parameter is NULL |
| **Invalid length** | len < minimum for algorithm (typically 2) |
| **Invalid tweak length** | tweak_len doesn't match mode requirements |
| **Invalid input values** | Input values >= radix |
| **Algorithm error** | Internal encryption/decryption failure |

**Example:**
```c
// Validate inputs before calling
if (len < 2) {
    fprintf(stderr, "Input too short (min 2 symbols)\n");
    return -1;
}

// For FF3/FF3-1: tweak must be exactly 7 or 8 bytes
if (ctx->mode == FPE_MODE_FF3_1 && tweak_len != 7) {
    fprintf(stderr, "FF3-1 requires 7-byte tweak (got %u)\n", tweak_len);
    return -1;
}

int ret = FPE_encrypt(ctx, in, out, len, tweak, tweak_len);
if (ret != 0) {
    fprintf(stderr, "Encryption failed\n");
    return -1;
}
```

---

### FPE_encrypt_str() / FPE_decrypt_str()

**Signature:**
```c
int FPE_encrypt_str(FPE_CTX *ctx, const char *alphabet, const char *in,
                    char *out, const unsigned char *tweak,
                    unsigned int tweak_len);
                    
int FPE_decrypt_str(FPE_CTX *ctx, const char *alphabet, const char *in,
                    char *out, const unsigned char *tweak,
                    unsigned int tweak_len);
```

**Returns:**
- 0 on success
- -1 on error

**Error conditions:**

| Error | Cause |
|-------|-------|
| **NULL parameters** | Any parameter is NULL |
| **Alphabet/radix mismatch** | strlen(alphabet) != ctx->radix |
| **Invalid character** | Input contains character not in alphabet |
| **Empty input** | Input string is empty |
| **Invalid tweak length** | tweak_len doesn't match mode requirements |
| **Buffer too small** | Output buffer insufficient (should be strlen(in) + 1) |

**Example:**
```c
const char *alphabet = "0123456789";
const char *input = "1234567890";

// Validate alphabet matches radix
if (strlen(alphabet) != ctx->radix) {
    fprintf(stderr, "Alphabet length %zu doesn't match radix %u\n",
            strlen(alphabet), ctx->radix);
    return -1;
}

// Allocate sufficient output buffer
char *output = malloc(strlen(input) + 1);
if (!output) {
    fprintf(stderr, "Failed to allocate output buffer\n");
    return -1;
}

int ret = FPE_encrypt_str(ctx, alphabet, input, output, tweak, tweak_len);
if (ret != 0) {
    fprintf(stderr, "String encryption failed\n");
    fprintf(stderr, "Check: alphabet, input characters, tweak length\n");
    free(output);
    return -1;
}

free(output);
```

---

### One-Shot Functions

**Signatures:**
```c
int FPE_encrypt_oneshot(...);
int FPE_decrypt_oneshot(...);
int FPE_encrypt_str_oneshot(...);
int FPE_decrypt_str_oneshot(...);
```

**Returns:**
- 0 on success
- -1 on error

**Error conditions:**
- All errors from `FPE_CTX_new()`, `FPE_CTX_init()`, and encrypt/decrypt functions
- Internal context allocation failure
- Internal context initialization failure

**Example:**
```c
int ret = FPE_encrypt_str_oneshot(
    FPE_MODE_FF1, FPE_ALGO_AES,
    key, 128,
    input, alphabet,
    tweak, tweak_len,
    output, output_size
);

if (ret != 0) {
    fprintf(stderr, "One-shot encryption failed\n");
    fprintf(stderr, "Possible causes:\n");
    fprintf(stderr, "  - Memory allocation failed\n");
    fprintf(stderr, "  - Invalid parameters\n");
    fprintf(stderr, "  - OpenSSL error\n");
    fprintf(stderr, "  - Encryption algorithm error\n");
    return -1;
}
```

---

## Error Handling Patterns

### Pattern 1: Early Return on Error

```c
int encrypt_data(const char *plaintext, char *ciphertext) {
    // Create context
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return -1;
    }
    
    // Initialize
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10) != 0) {
        fprintf(stderr, "Failed to initialize context\n");
        FPE_CTX_free(ctx);
        return -1;
    }
    
    // Encrypt
    unsigned char tweak[] = "user-data";
    if (FPE_encrypt_str(ctx, "0123456789", plaintext, ciphertext,
                        tweak, strlen((char*)tweak)) != 0) {
        fprintf(stderr, "Encryption failed\n");
        FPE_CTX_free(ctx);
        return -1;
    }
    
    // Success cleanup
    FPE_CTX_free(ctx);
    return 0;
}
```

### Pattern 2: Goto Cleanup

```c
int process_batch(char **inputs, char **outputs, int count) {
    FPE_CTX *ctx = NULL;
    int ret = -1;
    
    // Allocate context
    ctx = FPE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        goto cleanup;
    }
    
    // Initialize
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10) != 0) {
        fprintf(stderr, "Failed to initialize context\n");
        goto cleanup;
    }
    
    // Process batch
    for (int i = 0; i < count; i++) {
        char tweak[64];
        snprintf(tweak, sizeof(tweak), "record:%d", i);
        
        if (FPE_encrypt_str(ctx, "0123456789", inputs[i], outputs[i],
                            (unsigned char*)tweak, strlen(tweak)) != 0) {
            fprintf(stderr, "Failed to encrypt record %d\n", i);
            goto cleanup;
        }
    }
    
    // Success
    ret = 0;
    
cleanup:
    if (ctx) FPE_CTX_free(ctx);
    return ret;
}
```

### Pattern 3: Error Accumulation

```c
typedef struct {
    int total;
    int succeeded;
    int failed;
} ProcessStats;

int process_best_effort(char **inputs, char **outputs, int count,
                        ProcessStats *stats) {
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) return -1;
    
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10) != 0) {
        FPE_CTX_free(ctx);
        return -1;
    }
    
    stats->total = count;
    stats->succeeded = 0;
    stats->failed = 0;
    
    for (int i = 0; i < count; i++) {
        char tweak[64];
        snprintf(tweak, sizeof(tweak), "record:%d", i);
        
        int ret = FPE_encrypt_str(ctx, "0123456789", inputs[i], outputs[i],
                                  (unsigned char*)tweak, strlen(tweak));
        
        if (ret == 0) {
            stats->succeeded++;
        } else {
            stats->failed++;
            fprintf(stderr, "Record %d failed\n", i);
            // Continue processing other records
        }
    }
    
    FPE_CTX_free(ctx);
    return stats->failed > 0 ? -1 : 0;
}
```

### Pattern 4: Wrapper with Error Context

```c
typedef enum {
    FPE_ERR_NONE = 0,
    FPE_ERR_ALLOC,
    FPE_ERR_INIT,
    FPE_ERR_ENCRYPT,
    FPE_ERR_DECRYPT,
    FPE_ERR_INVALID_INPUT
} FPEError;

typedef struct {
    FPEError code;
    char message[256];
} FPEErrorInfo;

int encrypt_with_error_info(const char *input, char *output, FPEErrorInfo *err) {
    err->code = FPE_ERR_NONE;
    err->message[0] = '\0';
    
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) {
        err->code = FPE_ERR_ALLOC;
        snprintf(err->message, sizeof(err->message), "Failed to allocate context");
        return -1;
    }
    
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10) != 0) {
        err->code = FPE_ERR_INIT;
        snprintf(err->message, sizeof(err->message), 
                 "Failed to initialize context (check key/radix)");
        FPE_CTX_free(ctx);
        return -1;
    }
    
    unsigned char tweak[] = "data";
    if (FPE_encrypt_str(ctx, "0123456789", input, output, 
                        tweak, strlen((char*)tweak)) != 0) {
        err->code = FPE_ERR_ENCRYPT;
        snprintf(err->message, sizeof(err->message),
                 "Encryption failed (check input alphabet)");
        FPE_CTX_free(ctx);
        return -1;
    }
    
    FPE_CTX_free(ctx);
    return 0;
}
```

---

## Common Error Scenarios

### Scenario 1: Context Initialization Failure

**Symptom:** `FPE_CTX_init()` returns -1

**Common causes:**
1. Invalid key size (not 128/192/256 for AES, or not 128 for SM4)
2. Invalid radix (< 2 or > 65536 for all modes: FF1, FF3, FF3-1)
3. SM4 not available in OpenSSL
4. NULL key or context

**Diagnosis:**
```c
// Check key size
if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
    fprintf(stderr, "Invalid key size: %u\n", key_bits);
}

// Check radix
if (radix < 2 || radix > 65536) {
    fprintf(stderr, "Invalid radix: %u\n", radix);
}

// Check SM4 availability
#ifndef HAVE_OPENSSL_SM4
if (algo == FPE_ALGO_SM4) {
    fprintf(stderr, "SM4 not supported in this build\n");
}
#endif
```

### Scenario 2: String Encryption Failure

**Symptom:** `FPE_encrypt_str()` returns -1

**Common causes:**
1. Input contains character not in alphabet
2. Alphabet length doesn't match radix
3. Invalid tweak length for mode
4. Output buffer too small

**Diagnosis:**
```c
// Validate alphabet
if (strlen(alphabet) != ctx->radix) {
    fprintf(stderr, "Alphabet length %zu != radix %u\n",
            strlen(alphabet), ctx->radix);
    return -1;
}

// Validate input characters
for (size_t i = 0; i < strlen(input); i++) {
    if (strchr(alphabet, input[i]) == NULL) {
        fprintf(stderr, "Invalid character '%c' at position %zu\n",
                input[i], i);
        return -1;
    }
}

// Validate tweak length
if (mode == FPE_MODE_FF3_1 && tweak_len != 7) {
    fprintf(stderr, "FF3-1 requires 7-byte tweak (got %u)\n", tweak_len);
    return -1;
}
```

### Scenario 3: Decryption Doesn't Match

**Symptom:** Decrypt succeeds but doesn't produce original plaintext

**Common causes:**
1. **Wrong key** - Different key used for encrypt/decrypt
2. **Wrong tweak** - Different tweak used for encrypt/decrypt
3. **Wrong algorithm** - Different mode/cipher for encrypt/decrypt
4. **Corrupted ciphertext** - Ciphertext modified

**Not errors (by design):**
```c
// These are NOT errors - decryption will succeed but produce different output
// 1. Different key
FPE_encrypt(ctx1, plaintext, ciphertext, ...);  // key1
FPE_decrypt(ctx2, ciphertext, decrypted, ...);  // key2 ≠ key1

// 2. Different tweak
FPE_encrypt(ctx, plaintext, ciphertext, tweak1, ...);
FPE_decrypt(ctx, ciphertext, decrypted, tweak2, ...);  // tweak2 ≠ tweak1

// 3. Corrupted ciphertext
ciphertext[0] = '5';  // Modify ciphertext
FPE_decrypt(ctx, ciphertext, decrypted, ...);  // Produces valid but wrong output
```

**FPE does not detect these conditions** - always verify key/tweak match!

---

## Debugging Tips

### Enable Verbose Error Output

```c
#define FPE_DEBUG 1

void fpe_debug(const char *func, const char *msg) {
#ifdef FPE_DEBUG
    fprintf(stderr, "[FPE] %s: %s\n", func, msg);
#endif
}

// Use in your code
if (FPE_CTX_init(ctx, ...) != 0) {
    fpe_debug("encrypt_data", "Context initialization failed");
    // Additional diagnostics
}
```

### Check OpenSSL Errors

```c
#include <openssl/err.h>

if (FPE_CTX_init(ctx, ...) != 0) {
    fprintf(stderr, "FPE initialization failed\n");
    
    // Get OpenSSL error details
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        fprintf(stderr, "OpenSSL error: %s\n", err_buf);
    }
}
```

### Validate Inputs Before Calling FPE

```c
int validate_and_encrypt(FPE_CTX *ctx, const char *alphabet,
                         const char *input, char *output) {
    // Validate context
    if (!ctx) {
        fprintf(stderr, "NULL context\n");
        return -1;
    }
    
    // Validate alphabet
    if (!alphabet || strlen(alphabet) == 0) {
        fprintf(stderr, "Empty alphabet\n");
        return -1;
    }
    
    if (strlen(alphabet) != ctx->radix) {
        fprintf(stderr, "Alphabet/radix mismatch: %zu != %u\n",
                strlen(alphabet), ctx->radix);
        return -1;
    }
    
    // Validate input
    if (!input || strlen(input) == 0) {
        fprintf(stderr, "Empty input\n");
        return -1;
    }
    
    // Validate input characters
    for (size_t i = 0; i < strlen(input); i++) {
        if (strchr(alphabet, input[i]) == NULL) {
            fprintf(stderr, "Invalid char '%c' at position %zu\n",
                    input[i], i);
            return -1;
        }
    }
    
    // Now safe to call FPE
    return FPE_encrypt_str(ctx, alphabet, input, output, tweak, tweak_len);
}
```

---

## Summary

**Error Handling Best Practices:**

✅ **DO:**
- Always check return values (0 = success, -1 = error)
- Check for NULL from `FPE_CTX_new()`
- Validate inputs before calling FPE functions
- Use goto cleanup or RAII for resource management
- Log errors with context (function, parameters)
- Provide informative error messages

❌ **DON'T:**
- Ignore return values
- Assume operations succeed
- Use uninitialized contexts
- Forget to free contexts on error paths
- Mix error handling styles inconsistently

**Quick Reference:**

| Function | Success | Error | Notes |
|----------|---------|-------|-------|
| FPE_CTX_new() | Non-NULL | NULL | Check for NULL |
| FPE_CTX_init() | 0 | -1 | Validate params first |
| FPE_encrypt() | 0 | -1 | Check input length |
| FPE_decrypt() | 0 | -1 | Check input length |
| FPE_encrypt_str() | 0 | -1 | Check alphabet/input |
| FPE_decrypt_str() | 0 | -1 | Check alphabet/input |
| FPE_*_oneshot() | 0 | -1 | All-in-one operation |
| FPE_CTX_free() | void | void | Always safe to call |

For more information:
- [API.md](API.md) - Complete API reference
- [SECURITY.md](SECURITY.md) - Security best practices
- [THREADING.md](THREADING.md) - Thread safety guidelines
