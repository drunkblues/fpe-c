# Security Best Practices for FPE-C

This document provides security guidance for using the FPE-C library safely and effectively in production environments.

## Table of Contents

- [Key Management](#key-management)
- [Algorithm Selection](#algorithm-selection)
- [Tweak Usage](#tweak-usage)
- [Input Validation](#input-validation)
- [Thread Safety](#thread-safety)
- [Memory Security](#memory-security)
- [Common Pitfalls](#common-pitfalls)
- [Compliance](#compliance)
- [Security Reporting](#security-reporting)

---

## Key Management

### Key Generation

**DO:**
- ✅ Generate keys using cryptographically secure random number generators (CSRNG)
- ✅ Use at least 128 bits of entropy for AES-128 and SM4-128
- ✅ Use 192 or 256 bits for AES-192/256 when higher security is required

**DON'T:**
- ❌ Never hardcode keys in source code
- ❌ Never derive keys from passwords without proper KDF (use PBKDF2, Argon2, or scrypt)
- ❌ Never reuse keys across different applications or contexts

**Example (Secure Key Generation):**
```c
#include <openssl/rand.h>

// Generate 128-bit AES key
unsigned char key[16];
if (RAND_bytes(key, sizeof(key)) != 1) {
    // Handle error - failed to generate secure random key
    return -1;
}

// Use key with FPE
FPE_CTX *ctx = FPE_CTX_new();
FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

// After use, securely zero the key
memset(key, 0, sizeof(key));
FPE_CTX_free(ctx);  // Context cleanup also zeros internal key material
```

### Key Storage

**DO:**
- ✅ Store keys in Hardware Security Modules (HSMs) when possible
- ✅ Encrypt keys at rest using key encryption keys (KEKs)
- ✅ Use secure key management systems (AWS KMS, Azure Key Vault, HashiCorp Vault)
- ✅ Implement proper access controls and audit logging for key access

**DON'T:**
- ❌ Never store keys in plaintext files
- ❌ Never commit keys to version control systems
- ❌ Never log or print keys in application logs
- ❌ Never transmit keys over insecure channels

### Key Rotation

- Rotate encryption keys according to your security policy (e.g., annually)
- Keep old keys accessible for decrypting existing data
- Use versioning or key IDs to track which key encrypted which data
- Re-encrypt data with new keys during rotation periods

**Example (Key Versioning):**
```c
typedef struct {
    int key_version;
    unsigned char key[32];
    int key_bits;
} VersionedKey;

// Store key version with encrypted data
typedef struct {
    int key_version;
    char ciphertext[256];
} EncryptedData;
```

---

## Algorithm Selection

### Recommended Algorithms

| Use Case | Recommended Algorithm | Rationale |
|----------|----------------------|-----------|
| **General Purpose** | FF1 with AES | Widest radix support, proven security |
| **Legacy Compatibility** | FF3-1 with AES | Compatible with FF3 systems (with security fixes) |
| **Chinese Compliance** | FF1 or FF3-1 with SM4 | Required for Chinese regulatory compliance |
| **High Security** | FF1 with AES-256 | Maximum key strength |

### Algorithm Security Levels

| Algorithm | Security Level | Status | Use When |
|-----------|----------------|--------|----------|
| **FF1 + AES-128** | 128-bit | ✅ Recommended | Standard security requirements |
| **FF1 + AES-192** | 192-bit | ✅ Recommended | High security requirements |
| **FF1 + AES-256** | 256-bit | ✅ Recommended | Maximum security requirements |
| **FF1 + SM4-128** | 128-bit | ✅ Recommended | Chinese compliance required |
| **FF3-1 + AES** | 128-bit | ✅ Acceptable | Legacy FF3 compatibility needed |
| **FF3-1 + SM4** | 128-bit | ✅ Acceptable | Chinese compliance + legacy |
| **FF3 + any** | 128-bit | ⚠️ Deprecated | **Do not use** (security vulnerabilities) |

### Why FF3 is Deprecated

FF3 has known security vulnerabilities:
1. **Weak domain separation** - Different domains can leak information
2. **Tweak-related attacks** - Certain tweak patterns compromise security
3. **Limited radix support** - Only supports radix ≤ 256

**Migration Path:** Use FF3-1 for backward compatibility, or migrate to FF1 for new systems.

---

## Tweak Usage

### What are Tweaks?

Tweaks are auxiliary inputs that allow the same key to produce different ciphertexts for the same plaintext. They provide **domain separation** and **context binding**.

### Security Properties

- **Tweaks are NOT secret** - They can be stored or transmitted in plaintext
- **Tweaks provide domain separation** - Different tweaks produce different ciphertexts
- **Tweaks should be unique per context** - Use different tweaks for different data contexts

### Best Practices

**DO:**
- ✅ Use meaningful tweaks that bind ciphertext to its context
- ✅ Use unique tweaks for different data types or purposes
- ✅ Include record IDs, timestamps, or application identifiers in tweaks
- ✅ Document your tweak schema

**DON'T:**
- ❌ Never use tweaks as a substitute for key security
- ❌ Never reuse the same tweak for unrelated data
- ❌ Never leave tweaks empty unless intentional

**Example (Good Tweak Usage):**
```c
// Encrypt credit card for specific user and purpose
char tweak_data[64];
snprintf(tweak_data, sizeof(tweak_data), "user:%d:cc:primary", user_id);

FPE_encrypt_str(ctx, "0123456789", 
                plaintext_cc, encrypted_cc,
                (unsigned char*)tweak_data, strlen(tweak_data));

// Encrypt SSN for same user with different tweak
snprintf(tweak_data, sizeof(tweak_data), "user:%d:ssn", user_id);
FPE_encrypt_str(ctx, "0123456789", 
                plaintext_ssn, encrypted_ssn,
                (unsigned char*)tweak_data, strlen(tweak_data));
```

### Tweak Length Requirements

| Algorithm | Tweak Length | Notes |
|-----------|--------------|-------|
| **FF1** | 0 to 256 bytes | Flexible, can be empty |
| **FF3** | Exactly 7 or 8 bytes | **Deprecated - use FF3-1** |
| **FF3-1** | Exactly 7 bytes | Strict requirement |

---

## Input Validation

### Always Validate Inputs

**DO:**
- ✅ Check return values from all FPE functions
- ✅ Validate input lengths before encryption
- ✅ Verify alphabet matches radix
- ✅ Ensure buffer sizes are sufficient
- ✅ Validate tweaks match algorithm requirements

**Example (Proper Error Handling):**
```c
int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
if (ret != 0) {
    fprintf(stderr, "Failed to initialize FPE context: %d\n", ret);
    FPE_CTX_free(ctx);
    return -1;
}

ret = FPE_encrypt_str(ctx, "0123456789", plaintext, ciphertext, tweak, tweak_len);
if (ret != 0) {
    fprintf(stderr, "Encryption failed: %d\n", ret);
    // Handle error appropriately
    return -1;
}
```

### Radix Constraints

| Algorithm | Minimum Radix | Maximum Radix | Notes |
|-----------|---------------|---------------|-------|
| **FF1** | 2 | 65536 | Wide support |
| **FF3/FF3-1** | 2 | 256 | Limited by design |

### Length Constraints

- **Minimum length:** At least 2 symbols (varies by algorithm)
- **Maximum length:** Constrained by `radix^minlen ≥ 1,000,000` (NIST requirement)

**Example:**
- Radix 10 (digits): Minimum 6 characters for FF1
- Radix 26 (letters): Minimum 4 characters
- Radix 36 (alphanumeric): Minimum 4 characters

---

## Thread Safety

### Context Thread Safety

**CRITICAL:** Each `FPE_CTX` is **NOT thread-safe**. Do not share contexts between threads.

**DO:**
- ✅ Create one context per thread for concurrent operations
- ✅ Use thread-local storage for contexts
- ✅ Synchronize context access with mutexes if sharing is unavoidable

**DON'T:**
- ❌ Never share FPE_CTX between threads without synchronization
- ❌ Never modify context parameters concurrently

**Example (Thread-Safe Usage):**
```c
#include <pthread.h>

// Thread-safe: Each thread has its own context
void* worker_thread(void* arg) {
    // Create thread-local context
    FPE_CTX *ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, global_key, 128, 10);
    
    // Process data with thread-local context
    for (int i = 0; i < work_items; i++) {
        FPE_encrypt_str(ctx, alphabet, input[i], output[i], tweak, tweak_len);
    }
    
    FPE_CTX_free(ctx);
    return NULL;
}
```

### Global State

- FPE-C uses no global state
- OpenSSL may use global state (ensure OpenSSL thread safety)
- Call `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)` once at startup

---

## Memory Security

### Secure Memory Handling

**DO:**
- ✅ Zero sensitive data after use
- ✅ Use `FPE_CTX_free()` to securely clean up contexts
- ✅ Minimize time sensitive data remains in memory
- ✅ Use secure memory allocation when available

**Example (Secure Cleanup):**
```c
unsigned char key[32];
char plaintext[256];

// Use key and plaintext...
FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, tweak_len);

// Securely zero sensitive data
memset(key, 0, sizeof(key));
memset(plaintext, 0, sizeof(plaintext));

// FPE_CTX_free() automatically zeros internal key material
FPE_CTX_free(ctx);
```

### Memory Leak Prevention

- Always call `FPE_CTX_free()` for every `FPE_CTX_new()`
- Use RAII patterns in C++ wrappers
- Test with Valgrind or AddressSanitizer during development

```bash
# Check for memory leaks
valgrind --leak-check=full --show-leak-kinds=all ./your_program
```

### Buffer Overflows

- Always allocate sufficient buffer space for outputs
- Output buffer must be at least `input_length + 1` for string operations
- FPE-C guarantees null-termination for string outputs

---

## Common Pitfalls

### 1. Reusing One-Shot API in Loops

**Problem:** Recreating context on every operation is 100x slower

❌ **Bad:**
```c
for (int i = 0; i < 10000; i++) {
    FPE_encrypt_str_oneshot(mode, algo, key, bits, plaintext[i], alphabet,
                            tweak, tweak_len, ciphertext[i], bufsize);
}
```

✅ **Good:**
```c
FPE_CTX *ctx = FPE_CTX_new();
FPE_CTX_init(ctx, mode, algo, key, bits, radix);

for (int i = 0; i < 10000; i++) {
    FPE_encrypt_str(ctx, alphabet, plaintext[i], ciphertext[i], 
                    tweak, tweak_len);
}

FPE_CTX_free(ctx);
```

### 2. Using Wrong Radix

❌ **Bad:**
```c
// Alphabet has 10 characters, but radix is 16
FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 16);
FPE_encrypt_str(ctx, "0123456789", input, output, tweak, tweak_len);  // FAILS
```

✅ **Good:**
```c
const char *alphabet = "0123456789";
FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, strlen(alphabet));
FPE_encrypt_str(ctx, alphabet, input, output, tweak, tweak_len);  // OK
```

### 3. Ignoring Return Values

❌ **Bad:**
```c
FPE_CTX_init(ctx, mode, algo, key, bits, radix);  // Ignore return
FPE_encrypt_str(ctx, alphabet, input, output, tweak, tweak_len);  // May fail silently
```

✅ **Good:**
```c
if (FPE_CTX_init(ctx, mode, algo, key, bits, radix) != 0) {
    fprintf(stderr, "Initialization failed\n");
    return -1;
}
if (FPE_encrypt_str(ctx, alphabet, input, output, tweak, tweak_len) != 0) {
    fprintf(stderr, "Encryption failed\n");
    return -1;
}
```

### 4. Using FF3 Instead of FF3-1

❌ **Bad:**
```c
// FF3 is deprecated and has security vulnerabilities
FPE_CTX_init(ctx, FPE_MODE_FF3, algo, key, bits, radix);
```

✅ **Good:**
```c
// FF3-1 includes security fixes
FPE_CTX_init(ctx, FPE_MODE_FF3_1, algo, key, bits, radix);
// Or better: use FF1
FPE_CTX_init(ctx, FPE_MODE_FF1, algo, key, bits, radix);
```

### 5. Insufficient Buffer Size

❌ **Bad:**
```c
char output[10];  // Too small if input is longer
FPE_encrypt_str(ctx, alphabet, long_input, output, tweak, tweak_len);  // Buffer overflow
```

✅ **Good:**
```c
char output[256];  // Sufficient size
// Or dynamically allocate:
char *output = malloc(strlen(input) + 1);
FPE_encrypt_str(ctx, alphabet, input, output, tweak, tweak_len);
free(output);
```

---

## Compliance

### NIST SP 800-38G Compliance

FPE-C implements **NIST SP 800-38G Rev. 1** (March 2019):
- ✅ FF1 algorithm (recommended)
- ✅ FF3-1 algorithm (secure FF3 variant)
- ⚠️ FF3 algorithm (deprecated, included for legacy compatibility)

### Standards Compliance

| Standard | Coverage | Notes |
|----------|----------|-------|
| **NIST SP 800-38G** | Full | FF1, FF3-1 recommended |
| **FIPS 140-2** | Underlying ciphers | Depends on OpenSSL FIPS mode |
| **PCI DSS** | Compatible | Suitable for payment card encryption |
| **GDPR** | Compatible | Enables data pseudonymization |
| **HIPAA** | Compatible | Suitable for PHI protection |
| **Chinese Cryptography Law** | SM4 support | Compliant when using SM4 cipher |

### Regulatory Compliance

**For PCI DSS:**
- Use FF1 or FF3-1 with AES-128 minimum
- Implement proper key management (PCI DSS 3.5, 3.6)
- Log access to encrypted data
- Regular key rotation

**For Chinese Regulations:**
- Use SM4 cipher for domestic systems
- Implement according to GM/T standards
- Use approved key management practices

---

## Security Reporting

### Reporting Security Issues

If you discover a security vulnerability in FPE-C:

1. **Do NOT** open a public GitHub issue
2. Email security details to: [security contact - to be added]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Security Updates

- Monitor the GitHub repository for security advisories
- Subscribe to security mailing list (if available)
- Test security patches before deployment
- Keep OpenSSL updated (many vulnerabilities are in underlying crypto)

---

## Security Checklist

Before deploying FPE-C in production:

- [ ] Keys generated using CSRNG
- [ ] Keys stored securely (HSM, KMS, or encrypted)
- [ ] Key rotation policy implemented
- [ ] Using FF1 or FF3-1 (not deprecated FF3)
- [ ] Tweaks provide proper domain separation
- [ ] All return values checked
- [ ] Thread safety requirements met
- [ ] Memory cleanup implemented
- [ ] Input validation in place
- [ ] Buffer sizes verified
- [ ] Tested with Valgrind/ASan
- [ ] OpenSSL version verified (3.0+ for SM4)
- [ ] Compliance requirements met
- [ ] Logging and monitoring configured
- [ ] Incident response plan prepared

---

## Additional Resources

1. **NIST SP 800-38G**: https://csrc.nist.gov/publications/detail/sp/800-38g/rev-1/final
2. **FPE-C Documentation**: `/docs/` directory
3. **API Reference**: `/docs/API.md`
4. **Algorithm Details**: `/docs/ALGORITHMS.md`
5. **SM4 Support**: `/docs/SM4.md`
6. **OpenSSL Security**: https://www.openssl.org/news/secadv/

---

## Summary

**Key Takeaways:**

✅ **Use strong key management** - Generate with CSRNG, store securely, rotate regularly  
✅ **Choose FF1 for new systems** - Best security and flexibility  
✅ **Use meaningful tweaks** - Provide domain separation and context binding  
✅ **Validate all inputs** - Check return values and buffer sizes  
✅ **Ensure thread safety** - One context per thread  
✅ **Clean up securely** - Zero sensitive data, use FPE_CTX_free()  
✅ **Test thoroughly** - Use Valgrind, test edge cases  
✅ **Stay updated** - Monitor for security advisories  

For questions or concerns, consult the documentation or contact the maintainers.
