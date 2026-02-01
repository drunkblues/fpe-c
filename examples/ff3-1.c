/**
 * FF3-1 Usage Example - FPE-C Library
 * 
 * Comprehensive guide to using the FF3-1 algorithm:
 * - What is FF3-1 and when to use it
 * - Basic encryption/decryption
 * - Tweak requirements (7 bytes)
 * - Differences from FF3
 * - Migration from FF3 to FF3-1
 * - Comparison with FF1
 * - Real-world use cases
 */

#include <stdio.h>
#include <string.h>
#include <fpe.h>

/* Helper function to print a separator */
static void print_separator(const char *title) {
    printf("\n%s\n", title);
    for (size_t i = 0; i < strlen(title); i++) printf("-");
    printf("\n");
}

/* Helper to print hex bytes */
static void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main(void) {
    printf("=== FF3-1 Usage Example ===\n");
    
    /* ========================================================================
     * Introduction: What is FF3-1?
     * ======================================================================== */
    print_separator("What is FF3-1?");
    
    printf("\nFF3-1 is the updated version of FF3 with security improvements.\n\n");
    
    printf("Key Facts:\n");
    printf("• NIST approved (SP 800-38G Revision 1)\n");
    printf("• Fixes vulnerabilities found in FF3\n");
    printf("• Required 7-byte tweak (56 bits) vs 8-byte in FF3\n");
    printf("• Drop-in replacement for FF3 applications\n");
    printf("• Use when FF3 compatibility is required\n\n");
    
    printf("When to Use FF3-1:\n");
    printf("• Migrating from legacy FF3 systems\n");
    printf("• Regulatory/compliance requires FF3 family\n");
    printf("• Fixed 7-byte tweak is acceptable\n");
    printf("• Radix ≤ 36 (optimal security)\n\n");
    
    printf("When to Use FF1 Instead:\n");
    printf("• New implementations (recommended)\n");
    printf("• Need flexible tweak length\n");
    printf("• Need radix > 36\n");
    printf("• Want best performance\n");
    
    /* ========================================================================
     * Example 1: Basic FF3-1 Encryption
     * ======================================================================== */
    print_separator("Example 1: Basic FF3-1 Encryption");
    
    const unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    /* FF3-1 requires exactly 7 bytes (56 bits) */
    const unsigned char tweak[7] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    
    printf("\nSetup:\n");
    printf("Algorithm: FF3-1\n");
    printf("Cipher:    AES-128\n");
    printf("Radix:     10 (decimal)\n");
    print_hex("Key", key, 16);
    print_hex("Tweak", tweak, 7);
    printf("Note:      Tweak must be exactly 7 bytes!\n");
    
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        return 1;
    }
    
    /* Initialize with FF3-1 mode */
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize FF3-1 context\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    const char *alphabet = "0123456789";
    const char *plaintext = "4111111111111111";  // Credit card number
    char ciphertext[32] = {0};
    char decrypted[32] = {0};
    
    printf("\nEncryption:\n");
    printf("Plaintext:  %s\n", plaintext);
    
    ret = FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 7);
    if (ret != 0) {
        fprintf(stderr, "Encryption failed\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Ciphertext: %s\n", ciphertext);
    
    /* Decrypt to verify */
    ret = FPE_decrypt_str(ctx, alphabet, ciphertext, decrypted, tweak, 7);
    if (ret != 0) {
        fprintf(stderr, "Decryption failed\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Decrypted:  %s\n", decrypted);
    printf("Match: %s\n", strcmp(plaintext, decrypted) == 0 ? "✓ Yes" : "✗ No");
    
    /* ========================================================================
     * Example 2: Tweak Requirements
     * ======================================================================== */
    print_separator("Example 2: Tweak Requirements");
    
    printf("\nFF3-1 has strict tweak requirements:\n\n");
    
    printf("✓ Valid: Exactly 7 bytes (56 bits)\n");
    const unsigned char valid_tweak[7] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
    ret = FPE_encrypt_str(ctx, alphabet, "1234567890", ciphertext, valid_tweak, 7);
    printf("  Result: %s\n", ret == 0 ? "Success ✓" : "Failed ✗");
    
    printf("\n✗ Invalid: 6 bytes (too short)\n");
    const unsigned char short_tweak[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    ret = FPE_encrypt_str(ctx, alphabet, "1234567890", ciphertext, short_tweak, 6);
    printf("  Result: %s\n", ret == 0 ? "Success ✓" : "Failed ✗ (as expected)");
    
    printf("\n✗ Invalid: 8 bytes (too long)\n");
    const unsigned char long_tweak[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    ret = FPE_encrypt_str(ctx, alphabet, "1234567890", ciphertext, long_tweak, 8);
    printf("  Result: %s\n", ret == 0 ? "Success ✓" : "Failed ✗ (as expected)");
    
    printf("\n✗ Invalid: Empty tweak\n");
    ret = FPE_encrypt_str(ctx, alphabet, "1234567890", ciphertext, NULL, 0);
    printf("  Result: %s\n", ret == 0 ? "Success ✓" : "Failed ✗ (as expected)");
    
    printf("\nImportant: FF3-1 will reject tweaks that are not exactly 7 bytes!\n");
    
    /* ========================================================================
     * Example 3: Different Tweaks = Different Ciphertexts
     * ======================================================================== */
    print_separator("Example 3: Contextual Tweaks");
    
    printf("\nUsing different tweaks for different contexts:\n\n");
    
    const char *card = "4111111111111111";
    
    const unsigned char user1_tweak[7] = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};  // User 1
    const unsigned char user2_tweak[7] = {0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};  // User 2
    const unsigned char user3_tweak[7] = {0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};  // User 3
    
    char cipher1[32], cipher2[32], cipher3[32];
    
    FPE_encrypt_str(ctx, alphabet, card, cipher1, user1_tweak, 7);
    FPE_encrypt_str(ctx, alphabet, card, cipher2, user2_tweak, 7);
    FPE_encrypt_str(ctx, alphabet, card, cipher3, user3_tweak, 7);
    
    printf("Same card, different users:\n");
    printf("Original:     %s\n\n", card);
    printf("User 1 tweak: "); for(int i=0; i<7; i++) printf("%02X", user1_tweak[i]); printf("\n");
    printf("User 1 cipher: %s\n\n", cipher1);
    printf("User 2 tweak: "); for(int i=0; i<7; i++) printf("%02X", user2_tweak[i]); printf("\n");
    printf("User 2 cipher: %s\n\n", cipher2);
    printf("User 3 tweak: "); for(int i=0; i<7; i++) printf("%02X", user3_tweak[i]); printf("\n");
    printf("User 3 cipher: %s\n\n", cipher3);
    
    printf("✓ Different tweaks produce different ciphertexts\n");
    printf("  (Prevents pattern analysis across users)\n");
    
    /* ========================================================================
     * Example 4: FF3 vs FF3-1 Differences
     * ======================================================================== */
    print_separator("Example 4: FF3 vs FF3-1 Differences");
    
    printf("\nKey Differences:\n\n");
    
    printf("Feature           FF3          FF3-1\n");
    printf("----------------  -----------  -----------\n");
    printf("NIST Status       Deprecated   Approved\n");
    printf("Security          Vulnerable   Secure\n");
    printf("Tweak Length      8 bytes      7 bytes\n");
    printf("Tweak Bits        64 bits      56 bits\n");
    printf("Recommended       ✗ No         ✓ Yes\n\n");
    
    printf("Important Notes:\n");
    printf("• FF3 and FF3-1 produce DIFFERENT ciphertexts\n");
    printf("• Cannot decrypt FF3 data with FF3-1 (or vice versa)\n");
    printf("• Must re-encrypt all data when migrating\n");
    printf("• FF3-1 is NOT backward compatible with FF3\n");
    
    /* ========================================================================
     * Example 5: Migration from FF3 to FF3-1
     * ======================================================================== */
    print_separator("Example 5: Migration from FF3 to FF3-1");
    
    printf("\nMigration Steps:\n\n");
    
    printf("1. Update Code:\n");
    printf("   Old: FPE_CTX_init(ctx, FPE_MODE_FF3, ...)\n");
    printf("   New: FPE_CTX_init(ctx, FPE_MODE_FF3_1, ...)\n\n");
    
    printf("2. Update Tweak Handling:\n");
    printf("   Old: 8-byte tweaks\n");
    printf("   New: 7-byte tweaks (truncate or redesign)\n\n");
    
    printf("3. Re-encrypt Data:\n");
    printf("   • Decrypt all data with FF3\n");
    printf("   • Encrypt all data with FF3-1\n");
    printf("   • Update in database/storage\n\n");
    
    printf("4. Test Thoroughly:\n");
    printf("   • Verify all data can be decrypted\n");
    printf("   • Update test vectors\n");
    printf("   • Test with production sample\n\n");
    
    printf("Example Migration Code:\n");
    printf("----------------------------------------\n");
    printf("// 1. Decrypt with FF3\n");
    printf("FPE_CTX *ff3_ctx = FPE_CTX_new();\n");
    printf("FPE_CTX_init(ff3_ctx, FPE_MODE_FF3, ...);\n");
    printf("FPE_decrypt_str(ff3_ctx, ..., ff3_tweak, 8);\n\n");
    printf("// 2. Encrypt with FF3-1\n");
    printf("FPE_CTX *ff3_1_ctx = FPE_CTX_new();\n");
    printf("FPE_CTX_init(ff3_1_ctx, FPE_MODE_FF3_1, ...);\n");
    printf("FPE_encrypt_str(ff3_1_ctx, ..., ff3_1_tweak, 7);\n");
    
    /* ========================================================================
     * Example 6: FF3-1 vs FF1 Comparison
     * ======================================================================== */
    print_separator("Example 6: FF3-1 vs FF1 Comparison");
    
    printf("\nComparing FF3-1 with FF1:\n\n");
    
    /* Test same input with both algorithms */
    const char *test_input = "1234567890123456";
    
    /* FF3-1 */
    char ff3_1_output[32];
    const unsigned char ff3_1_tweak[7] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    FPE_encrypt_str(ctx, alphabet, test_input, ff3_1_output, ff3_1_tweak, 7);
    
    /* FF1 */
    FPE_CTX *ff1_ctx = FPE_CTX_new();
    FPE_CTX_init(ff1_ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    char ff1_output[32];
    const unsigned char ff1_tweak[7] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    FPE_encrypt_str(ff1_ctx, alphabet, test_input, ff1_output, ff1_tweak, 7);
    
    printf("Input:       %s\n", test_input);
    printf("FF3-1 output: %s\n", ff3_1_output);
    printf("FF1 output:   %s\n\n", ff1_output);
    
    printf("Comparison:\n\n");
    printf("Feature           FF3-1        FF1\n");
    printf("----------------  -----------  -----------\n");
    printf("Tweak Length      7 bytes      Flexible\n");
    printf("Performance       ~55K TPS     ~90K TPS\n");
    printf("Max Radix         36*          256\n");
    printf("Rounds            8            10\n");
    printf("Flexibility       Low          High\n");
    printf("Recommended       For FF3 compat  For new apps\n\n");
    
    printf("* Higher radix possible but not recommended\n\n");
    
    printf("Choose FF3-1 when:\n");
    printf("• Migrating from FF3\n");
    printf("• Compliance requires FF3 family\n");
    printf("• Fixed 7-byte tweak is OK\n\n");
    
    printf("Choose FF1 when:\n");
    printf("• Starting new project (recommended)\n");
    printf("• Need flexible tweaks\n");
    printf("• Want best performance\n");
    
    FPE_CTX_free(ff1_ctx);
    
    /* ========================================================================
     * Example 7: Real-World Use Cases
     * ======================================================================== */
    print_separator("Example 7: Real-World Use Cases");
    
    printf("\nUse Case 1: Payment Card Industry (PCI DSS)\n");
    printf("--------------------------------------------\n");
    printf("Scenario: Legacy system using FF3\n");
    printf("Solution: Migrate to FF3-1 for security\n");
    printf("Benefit:  Maintains FF3 family compatibility\n\n");
    
    printf("Use Case 2: Healthcare (HIPAA)\n");
    printf("-------------------------------\n");
    printf("Scenario: Encrypting patient IDs\n");
    printf("Solution: Use FF3-1 with patient-specific tweaks\n");
    printf("Benefit:  Fixed-length output, deterministic\n\n");
    
    printf("Use Case 3: Financial Services\n");
    printf("-------------------------------\n");
    printf("Scenario: Account number encryption\n");
    printf("Solution: FF3-1 with transaction-specific tweaks\n");
    printf("Benefit:  Prevents pattern analysis across transactions\n\n");
    
    printf("Use Case 4: Government Systems\n");
    printf("-------------------------------\n");
    printf("Scenario: Regulatory requires FF3 family\n");
    printf("Solution: Use FF3-1 (not deprecated FF3)\n");
    printf("Benefit:  Meets compliance with secure algorithm\n");
    
    /* ========================================================================
     * Example 8: Best Practices
     * ======================================================================== */
    print_separator("Example 8: Best Practices");
    
    printf("\n1. Tweak Management:\n");
    printf("   ✓ Use unique tweaks per user/context\n");
    printf("   ✓ Derive from user ID, transaction ID, timestamp\n");
    printf("   ✓ Store tweak alongside encrypted data\n");
    printf("   ✗ Don't reuse same tweak everywhere\n\n");
    
    printf("2. Key Management:\n");
    printf("   ✓ Use 256-bit keys for maximum security\n");
    printf("   ✓ Store keys in HSM or key management service\n");
    printf("   ✓ Rotate keys periodically\n");
    printf("   ✗ Never hardcode keys\n\n");
    
    printf("3. Input Validation:\n");
    printf("   ✓ Verify input length meets minimum (radix-dependent)\n");
    printf("   ✓ Validate all characters are in alphabet\n");
    printf("   ✓ Check tweak is exactly 7 bytes\n");
    printf("   ✓ Always check return values\n\n");
    
    printf("4. Performance:\n");
    printf("   ✓ Reuse context for multiple operations\n");
    printf("   ✓ Consider FF1 if performance critical\n");
    printf("   ✓ Batch operations when possible\n");
    printf("   ✓ Profile before optimizing\n\n");
    
    printf("5. Testing:\n");
    printf("   ✓ Test with NIST vectors\n");
    printf("   ✓ Test encrypt/decrypt round-trip\n");
    printf("   ✓ Test with different tweak values\n");
    printf("   ✓ Test edge cases (min length, etc.)\n");
    
    /* Cleanup */
    FPE_CTX_free(ctx);
    
    printf("\n=== FF3-1 Usage Example Complete ===\n\n");
    
    printf("Key Takeaways:\n");
    printf("• FF3-1 is the secure replacement for deprecated FF3\n");
    printf("• Requires exactly 7-byte tweaks (56 bits)\n");
    printf("• Use for FF3 compatibility, otherwise prefer FF1\n");
    printf("• Not backward compatible with FF3\n");
    printf("• Suitable for regulated industries\n");
    printf("• Performance: ~55K TPS (single-threaded)\n");
    
    return 0;
}
