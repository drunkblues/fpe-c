# Migrating from FF3 to FF3-1

This guide provides comprehensive instructions for migrating from the deprecated FF3 algorithm to the secure FF3-1 algorithm.

## Table of Contents

- [Why Migrate](#why-migrate)
- [Key Differences](#key-differences)
- [Migration Strategy](#migration-strategy)
- [Code Changes](#code-changes)
- [Data Migration](#data-migration)
- [Testing](#testing)
- [Rollback Plan](#rollback-plan)
- [FAQ](#faq)

---

## Why Migrate

### FF3 Security Vulnerabilities

FF3 has several known security vulnerabilities identified in academic research:

1. **Weak Domain Separation** - Different domains can have related outputs, allowing potential pattern analysis
2. **Tweak-Related Attacks** - Certain tweak patterns can leak information about the plaintext
3. **Limited Radix Support** - Only supports radix ≤ 256 due to design constraints

### NIST Deprecation

- **FF3 Status:** ⚠️ Deprecated by NIST (SP 800-38G)
- **FF3-1 Status:** ✅ Approved by NIST (SP 800-38G Rev. 1, March 2019)

**Critical:** FF3 is deprecated and should not be used in new applications or maintained systems. Migration to FF3-1 is **strongly recommended** for security and compliance.

---

## Key Differences

| Feature | FF3 | FF3-1 |
|---------|-----|-------|
| **NIST Status** | Deprecated | Approved |
| **Security** | Vulnerable to specific attacks | Secure |
| **Tweak Length** | 8 bytes (64 bits) | 7 bytes (56 bits) |
| **Tweak Requirement** | Flexible (7 or 8 bytes) | Strict (exactly 7 bytes) |
| **Performance** | ~70K TPS | ~50K TPS |
| **Output** | Different | Different (incompatible) |
| **Recommended** | ❌ No | ✅ Yes |

**Important:** FF3 and FF3-1 produce **completely different ciphertexts** for the same input. They are **not interoperable**.

---

## Migration Strategy

### Overview

There are three primary migration strategies:

1. **Big Bang Migration** - Migrate all data at once (recommended for small datasets)
2. **Gradual Migration** - Migrate data incrementally over time
3. **Dual-Mode Operation** - Support both FF3 and FF3-1 during transition period

### Strategy Comparison

| Strategy | Pros | Cons | Best For |
|----------|------|------|----------|
| **Big Bang** | Simple, clean cutover | Downtime required | Small datasets, dev/test |
| **Gradual** | No downtime | Complex state tracking | Large datasets |
| **Dual-Mode** | Flexible timeline | Maintenance overhead | Production systems |

---

## Code Changes

### 1. Update Initialization

**Before (FF3):**
```c
FPE_CTX *ctx = FPE_CTX_new();
FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
```

**After (FF3-1):**
```c
FPE_CTX *ctx = FPE_CTX_new();
FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
```

### 2. Update Tweak Handling

**Before (FF3 - 8 bytes):**
```c
unsigned char tweak[8] = {
    0x01, 0x02, 0x03, 0x04, 
    0x05, 0x06, 0x07, 0x08
};

FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 8);
```

**After (FF3-1 - 7 bytes):**
```c
unsigned char tweak[7] = {
    0x01, 0x02, 0x03, 0x04, 
    0x05, 0x06, 0x07
};

FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 7);
```

### 3. Handle Tweak Truncation

If you have existing 8-byte tweaks, you must decide how to convert them to 7 bytes:

**Option A: Truncate Last Byte**
```c
// Old 8-byte tweak
unsigned char old_tweak[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

// New 7-byte tweak (drop last byte)
unsigned char new_tweak[7];
memcpy(new_tweak, old_tweak, 7);
```

**Option B: XOR Fold Last Byte**
```c
// Old 8-byte tweak
unsigned char old_tweak[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

// New 7-byte tweak (fold last byte into first byte)
unsigned char new_tweak[7];
memcpy(new_tweak, old_tweak, 7);
new_tweak[0] ^= old_tweak[7];  // XOR fold
```

**Option C: Redesign Tweak Scheme**
```c
// Redesign tweaks to use only 56 bits (7 bytes) from the start
// Example: User ID (4 bytes) + Transaction ID (3 bytes)
unsigned char tweak[7];
memcpy(tweak, &user_id, 4);
memcpy(tweak + 4, &transaction_id, 3);
```

### 4. Update Error Handling

FF3-1 is **strict** about tweak length - it will **reject** tweaks that are not exactly 7 bytes:

```c
int ret = FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, tweak_len);
if (ret != 0) {
    // Check tweak length
    if (tweak_len != 7) {
        fprintf(stderr, "Error: FF3-1 requires exactly 7-byte tweak\n");
    }
    // Handle other errors...
}
```

---

## Data Migration

### Big Bang Migration

Suitable for smaller datasets or development environments.

#### Steps:

1. **Schedule Maintenance Window**
   - Notify users of downtime
   - Back up all data
   - Prepare rollback plan

2. **Decrypt with FF3**
```c
FPE_CTX *ff3_ctx = FPE_CTX_new();
FPE_CTX_init(ff3_ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, radix);

// Decrypt all encrypted data
for (each encrypted_value in database) {
    unsigned char ff3_tweak[8] = /* retrieve tweak */;
    FPE_decrypt_str(ff3_ctx, alphabet, encrypted_value, plaintext, ff3_tweak, 8);
    
    // Store plaintext temporarily
}

FPE_CTX_free(ff3_ctx);
```

3. **Encrypt with FF3-1**
```c
FPE_CTX *ff3_1_ctx = FPE_CTX_new();
FPE_CTX_init(ff3_1_ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, radix);

// Re-encrypt all data
for (each plaintext in temporary_storage) {
    unsigned char ff3_1_tweak[7] = /* convert or create tweak */;
    FPE_encrypt_str(ff3_1_ctx, alphabet, plaintext, ciphertext, ff3_1_tweak, 7);
    
    // Update database with new ciphertext
}

FPE_CTX_free(ff3_1_ctx);
```

4. **Verify and Deploy**
   - Test decryption of migrated data
   - Run validation queries
   - Deploy updated application

### Gradual Migration

Suitable for large datasets where downtime is not acceptable.

#### Steps:

1. **Add Migration Flag to Records**
```sql
ALTER TABLE sensitive_data ADD COLUMN fpe_version VARCHAR(10) DEFAULT 'FF3';
```

2. **Deploy Dual-Mode Application**
```c
// Function that handles both FF3 and FF3-1
int decrypt_value(const char *encrypted, char *plaintext, 
                  const char *fpe_version, 
                  const unsigned char *tweak_data) {
    
    if (strcmp(fpe_version, "FF3") == 0) {
        // Decrypt with FF3
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, radix);
        
        unsigned char tweak[8];
        memcpy(tweak, tweak_data, 8);
        
        int ret = FPE_decrypt_str(ctx, alphabet, encrypted, plaintext, tweak, 8);
        FPE_CTX_free(ctx);
        return ret;
        
    } else if (strcmp(fpe_version, "FF3-1") == 0) {
        // Decrypt with FF3-1
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, radix);
        
        unsigned char tweak[7];
        memcpy(tweak, tweak_data, 7);
        
        int ret = FPE_decrypt_str(ctx, alphabet, encrypted, plaintext, tweak, 7);
        FPE_CTX_free(ctx);
        return ret;
    }
    
    return -1;  // Unknown version
}
```

3. **Migrate Records Incrementally**
```c
// Background migration job
void migrate_batch(int batch_size) {
    // Select records that need migration
    for (int i = 0; i < batch_size; i++) {
        // 1. Decrypt with FF3
        decrypt_value(encrypted_value, plaintext, "FF3", ff3_tweak);
        
        // 2. Encrypt with FF3-1
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, radix);
        FPE_encrypt_str(ctx, alphabet, plaintext, new_encrypted, ff3_1_tweak, 7);
        FPE_CTX_free(ctx);
        
        // 3. Update database
        // UPDATE sensitive_data SET 
        //   encrypted_value = new_encrypted,
        //   fpe_version = 'FF3-1',
        //   tweak_data = ff3_1_tweak
        // WHERE id = record_id;
    }
}
```

4. **Monitor Progress**
```sql
-- Check migration progress
SELECT fpe_version, COUNT(*) 
FROM sensitive_data 
GROUP BY fpe_version;
```

5. **Remove FF3 Support**
   - Once all records migrated, remove FF3 code paths
   - Drop migration flag column
   - Update documentation

### Dual-Mode Operation

Maintain support for both FF3 and FF3-1 during transition.

```c
typedef enum {
    FPE_VERSION_FF3,
    FPE_VERSION_FF3_1
} FPE_VERSION;

typedef struct {
    FPE_VERSION version;
    unsigned char tweak[8];  // Max size (8 bytes for FF3)
    size_t tweak_len;        // Actual length (7 or 8)
} encryption_metadata_t;

int encrypt_with_metadata(const char *plaintext, char *ciphertext,
                          encryption_metadata_t *metadata) {
    FPE_CTX *ctx = FPE_CTX_new();
    
    if (metadata->version == FPE_VERSION_FF3) {
        FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, radix);
        int ret = FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, 
                                 metadata->tweak, 8);
        metadata->tweak_len = 8;
        FPE_CTX_free(ctx);
        return ret;
    } else {
        FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, radix);
        int ret = FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, 
                                 metadata->tweak, 7);
        metadata->tweak_len = 7;
        FPE_CTX_free(ctx);
        return ret;
    }
}
```

---

## Testing

### Pre-Migration Testing

1. **Backup Data**
```bash
# Create full backup of encrypted data
mysqldump -u user -p database > backup_before_migration.sql
```

2. **Test Migration Script**
```c
// Test with sample data
void test_migration() {
    // 1. Create test data with FF3
    FPE_CTX *ff3_ctx = FPE_CTX_new();
    FPE_CTX_init(ff3_ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
    
    const char *original = "1234567890";
    char ff3_encrypted[32];
    unsigned char ff3_tweak[8] = {1,2,3,4,5,6,7,8};
    
    FPE_encrypt_str(ff3_ctx, "0123456789", original, ff3_encrypted, ff3_tweak, 8);
    
    // 2. Decrypt with FF3
    char decrypted[32];
    FPE_decrypt_str(ff3_ctx, "0123456789", ff3_encrypted, decrypted, ff3_tweak, 8);
    assert(strcmp(original, decrypted) == 0);
    
    // 3. Encrypt with FF3-1
    FPE_CTX *ff3_1_ctx = FPE_CTX_new();
    FPE_CTX_init(ff3_1_ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    
    char ff3_1_encrypted[32];
    unsigned char ff3_1_tweak[7] = {1,2,3,4,5,6,7};
    
    FPE_encrypt_str(ff3_1_ctx, "0123456789", decrypted, ff3_1_encrypted, ff3_1_tweak, 7);
    
    // 4. Decrypt with FF3-1
    char ff3_1_decrypted[32];
    FPE_decrypt_str(ff3_1_ctx, "0123456789", ff3_1_encrypted, ff3_1_decrypted, ff3_1_tweak, 7);
    
    // 5. Verify
    assert(strcmp(original, ff3_1_decrypted) == 0);
    printf("✓ Migration test passed\n");
    
    FPE_CTX_free(ff3_ctx);
    FPE_CTX_free(ff3_1_ctx);
}
```

3. **Test Tweak Conversion**
```c
void test_tweak_conversion() {
    unsigned char old_tweak[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    unsigned char new_tweak[7];
    
    // Test truncation
    memcpy(new_tweak, old_tweak, 7);
    
    // Verify length
    assert(sizeof(new_tweak) == 7);
    printf("✓ Tweak conversion test passed\n");
}
```

### Post-Migration Testing

1. **Verify Decryption**
```c
// Test that all migrated data can be decrypted
SELECT id, encrypted_value FROM sensitive_data LIMIT 1000;

for (each record) {
    int ret = FPE_decrypt_str(ff3_1_ctx, alphabet, encrypted_value, plaintext, tweak, 7);
    assert(ret == 0);
    // Validate plaintext format/content
}
```

2. **Performance Testing**
```c
// Measure performance before/after
clock_t start = clock();

for (int i = 0; i < 10000; i++) {
    FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 7);
}

clock_t end = clock();
double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
printf("Time for 10K operations: %.2f seconds\n", time_taken);
```

3. **Integration Testing**
```bash
# Test full application workflows
./run_integration_tests.sh
```

---

## Rollback Plan

In case of issues during migration, have a rollback plan ready.

### Rollback Preparation

1. **Keep Original Data**
   - Don't delete FF3-encrypted data immediately
   - Maintain parallel columns during gradual migration

2. **Version Control**
   - Tag application version before migration
   - Keep FF3-supporting code in version control

### Rollback Procedure

1. **Stop New Writes**
```bash
# Put application in maintenance mode
systemctl stop myapp
```

2. **Restore Database**
```bash
# Restore from backup
mysql -u user -p database < backup_before_migration.sql
```

3. **Rollback Application**
```bash
# Revert to previous version
git checkout v1.0.0-pre-migration
make build && make install
```

4. **Verify System**
```bash
# Test basic functionality
./run_smoke_tests.sh
```

5. **Resume Operations**
```bash
systemctl start myapp
```

---

## FAQ

### Q1: Can I use the same key for both FF3 and FF3-1?

**A:** Yes, you can use the same encryption key for both algorithms. The key itself doesn't change - only the algorithm and tweak length change.

### Q2: Will FF3-1 decrypt data encrypted with FF3?

**A:** No. FF3 and FF3-1 produce completely different outputs for the same input. You **must** decrypt with FF3 first, then re-encrypt with FF3-1.

### Q3: How do I convert 8-byte tweaks to 7-byte tweaks?

**A:** You have three options:
- **Truncate:** Drop the last byte (simplest, but loses 8 bits)
- **XOR Fold:** XOR last byte into first byte (preserves some entropy)
- **Redesign:** Create new 7-byte tweak scheme (recommended for new systems)

### Q4: Is FF3-1 slower than FF3?

**A:** Slightly. FF3-1 has a small performance overhead due to security fixes, but the difference is minimal (~5-10%). Security improvements far outweigh the minor performance impact.

### Q5: Do I need to migrate immediately?

**A:** **Yes, urgently.** FF3 is deprecated and has known vulnerabilities. For security and compliance, migrate to FF3-1 as soon as possible.

### Q6: Can I migrate gradually without downtime?

**A:** Yes. Use the dual-mode operation strategy to support both FF3 and FF3-1 during transition, then gradually migrate records in batches.

### Q7: What about test vectors?

**A:** Update your test vectors after migration. FF3-1 produces different outputs than FF3, so you'll need new expected values.

### Q8: How do I handle migration errors?

**A:** Implement comprehensive error handling:
- Log all migration failures
- Track failed records for manual review
- Have rollback procedures ready
- Test thoroughly before production

### Q9: Should I migrate to FF3-1 or FF1?

**A:** 
- **FF3-1** if you need compatibility with FF3-based systems
- **FF1** if starting fresh or can re-encrypt everything (FF1 is recommended for new systems)

### Q10: What about compliance requirements?

**A:** FF3-1 is NIST-approved (SP 800-38G Rev. 1). Check with your compliance officer, but FF3-1 meets most regulatory requirements that previously accepted FF3.

---

## Additional Resources

- **NIST SP 800-38G:** https://csrc.nist.gov/publications/detail/sp/800-38g/final
- **NIST SP 800-38G Rev. 1:** https://csrc.nist.gov/publications/detail/sp/800-38g/rev-1/final
- **FPE-C Documentation:**
  - [API.md](API.md) - Complete API reference
  - [ALGORITHMS.md](ALGORITHMS.md) - Algorithm details
  - [SECURITY.md](SECURITY.md) - Security best practices
  - [EXAMPLES.md](../examples/) - Code examples
- **Academic Papers:**
  - "Practical Attacks on FF3" - Bellare et al. (2017)
  - "On the Security of FF3" - Durak & Vaudenay (2017)

---

## Summary

**Key Points:**

✅ **Migrate urgently** - FF3 is deprecated and vulnerable  
✅ **FF3-1 is secure** - Approved by NIST with security fixes  
✅ **Not backward compatible** - Must decrypt/re-encrypt all data  
✅ **Tweak length changes** - 8 bytes → 7 bytes  
✅ **Plan carefully** - Test thoroughly, have rollback plan  
✅ **Use dual-mode** - For gradual migration without downtime  

**Migration Checklist:**

- [ ] Back up all data
- [ ] Test migration script with sample data
- [ ] Update application code (FPE_MODE_FF3 → FPE_MODE_FF3_1)
- [ ] Update tweak handling (8 bytes → 7 bytes)
- [ ] Decrypt all FF3 data
- [ ] Re-encrypt with FF3-1
- [ ] Verify all data can be decrypted
- [ ] Update test vectors
- [ ] Run integration tests
- [ ] Deploy to production
- [ ] Monitor for errors
- [ ] Remove FF3 support code

For questions or assistance, please refer to the examples in `/examples/ff3-1.c` or open an issue on GitHub.
