# FPE-C Examples

This directory contains practical examples demonstrating various features of the FPE-C library.

## Building Examples

### Quick Start

```bash
make          # Build all examples
make basic    # Build specific example
make run      # Build and run all examples
make clean    # Remove built executables
```

### Requirements

The FPE library must be built first:

```bash
cd ..
mkdir build && cd build
cmake ..
make
cd ../examples
```

## Available Examples

### 1. `basic.c` - Comprehensive Introduction

**What it covers:**
- Creating and initializing FPE contexts
- Encrypting/decrypting credit card numbers
- Using different tweaks
- Integer array API (low-level)
- FF3-1 algorithm usage
- Proper cleanup and error handling

**Run:**
```bash
make basic && ./basic
```

**Key takeaways:**
- Same plaintext + different tweak = different ciphertext
- Format is preserved (16 digits in, 16 digits out)
- Reversible encryption (decrypt returns original)

---

### 2. `oneshot.c` - Stateless API

**What it covers:**
- One-shot string encryption (no context management)
- One-shot integer array encryption
- Comparing FF1 vs FF3-1 outputs
- Performance considerations
- Error handling

**Run:**
```bash
make oneshot && ./oneshot
```

**Key takeaways:**
- No need to manage `FPE_CTX` lifecycle
- Perfect for single operations
- Convenient but less efficient for bulk operations
- Automatic error detection (invalid alphabet characters)

---

## Example Patterns

### Pattern 1: Context-Based (Recommended for Multiple Operations)

```c
// Step 1: Create context
FPE_CTX *ctx = FPE_CTX_new();

// Step 2: Initialize once
FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

// Step 3: Encrypt multiple times (reuse context)
for (int i = 0; i < 1000; i++) {
    FPE_encrypt_str(ctx, alphabet, input, output, tweak, tweak_len);
}

// Step 4: Cleanup once
FPE_CTX_free(ctx);
```

**Best for:**
- High-performance scenarios
- Bulk encryption/decryption
- Long-running services
- When using the same key/algorithm repeatedly

---

### Pattern 2: One-Shot (Convenient for Single Operations)

```c
// Encrypt in one call (no context needed)
FPE_encrypt_str_oneshot(
    FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
    alphabet, input, output, tweak, tweak_len
);
```

**Best for:**
- Single encrypt/decrypt operations
- Prototyping and testing
- Simple use cases
- When simplicity > performance

---

## Common Use Cases

### Credit Card Numbers
```c
char alphabet[] = "0123456789";
char card[] = "4111111111111111";  // Visa test card
char encrypted[17];

FPE_encrypt_str(ctx, alphabet, card, encrypted, tweak, tweak_len);
// Result: Format preserved, 16 digits output
```

### Phone Numbers
```c
char phone[] = "5551234567";
char encrypted[11];

FPE_encrypt_str_oneshot(
    FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
    "0123456789", phone, encrypted, tweak, tweak_len
);
```

### Social Security Numbers
```c
unsigned int ssn[] = {1,2,3,4,5,6,7,8,9};  // 123-45-6789
unsigned int encrypted[9];

FPE_encrypt(ctx, ssn, encrypted, 9, tweak, tweak_len);
```

### Alphanumeric Data
```c
char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
char code[] = "ABC123XYZ";
char encrypted[10];

FPE_encrypt_str(ctx, alphabet, code, encrypted, tweak, tweak_len);
```

---

## Algorithm Selection Guide

### FF1 (Recommended)
- **Best for**: General-purpose FPE
- **Advantages**: Most flexible, well-studied, supports any tweak length
- **Performance**: ~90K TPS (AES-128)
- **Use when**: You need maximum flexibility

### FF3-1 (Secure Alternative)
- **Best for**: When FF3 compatibility is needed
- **Advantages**: Security fixes over FF3, slightly faster
- **Performance**: ~55K TPS (AES-128)
- **Constraint**: Requires 56-bit (7-byte) tweak
- **Use when**: You specifically need FF3-1 compliance

### FF3 (Deprecated - Avoid)
- **Status**: ⚠️ Deprecated by NIST
- **Issue**: Security vulnerabilities discovered
- **Recommendation**: Use FF3-1 instead for new code

---

## Troubleshooting

### Compilation Errors

**Error: `fpe.h: No such file or directory`**
```bash
# Make sure library is built first
cd ../build && make && cd ../examples
```

**Error: `cannot find -lfpe`**
```bash
# Library not in linker path
make clean
make  # Makefile handles -L and -rpath automatically
```

### Runtime Errors

**Encryption returns -1**
- Check that all input characters exist in the alphabet
- Verify tweak length matches algorithm requirements (FF3-1 needs 7 bytes)
- Ensure key length is valid (128, 192, or 256 for AES)

**Segmentation fault**
- Did you call `FPE_CTX_new()` before `FPE_CTX_init()`?
- Is your output buffer large enough (length + 1 for null terminator)?
- Did you free the context twice?

---

## Performance Tips

1. **Reuse contexts**: Create once, encrypt many times
2. **Choose appropriate radix**: Larger = more secure but slower
3. **Minimize tweak changes**: Same tweak = better CPU cache usage
4. **Consider input length**: Longer inputs = better security
5. **Profile your use case**: Run `test_ff1_performance` for benchmarks

---

## Security Best Practices

1. **Unique Keys**: Use cryptographically random keys
2. **Protect Keys**: Never hardcode keys in production code
3. **Unique Tweaks**: Use different tweaks for different contexts
4. **Minimum Length**: Use inputs >= 6 characters for security
5. **Prefer FF1**: Most flexible and well-studied algorithm
6. **Avoid FF3**: Use FF3-1 or FF1 instead

---

## Need More Examples?

Check the main README for:
- API reference documentation
- Performance benchmarks
- Thread safety guidelines
- Installation instructions

Or explore the test suite in `../tests/` for additional usage patterns.

---

## Contributing Examples

Have a useful example? Contributions are welcome!

1. Create a new `.c` file in this directory
2. Add it to the `Makefile`
3. Document what it demonstrates
4. Test it thoroughly
5. Submit a pull request

---

**Questions?** See the main project README or open an issue on GitHub.
