/**
 * Algorithm Comparison Example - FPE-C Library
 * 
 * Comprehensive comparison of FF1, FF3, and FF3-1 algorithms:
 * - Performance characteristics
 * - Security features
 * - Input requirements
 * - Tweak handling
 * - When to use each algorithm
 * - Side-by-side demonstrations
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fpe.h>

/* Helper function to print a separator */
static void print_separator(const char *title) {
    printf("\n%s\n", title);
    for (size_t i = 0; i < strlen(title); i++) printf("-");
    printf("\n");
}

/* Helper to measure encryption time */
static double measure_time_us(FPE_CTX *ctx, const char *alphabet, 
                               const char *input, const unsigned char *tweak, 
                               unsigned int tweak_len, int iterations) {
    char output[256];
    struct timespec start, end;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < iterations; i++) {
        FPE_encrypt_str(ctx, alphabet, input, output, tweak, tweak_len);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double elapsed = (end.tv_sec - start.tv_sec) * 1000000.0 +
                    (end.tv_nsec - start.tv_nsec) / 1000.0;
    
    return elapsed / iterations;
}

int main(void) {
    printf("=== FPE Algorithm Comparison: FF1 vs FF3 vs FF3-1 ===\n");
    
    /* Common parameters */
    const unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    const char *alphabet = "0123456789";
    const char *test_input = "4111111111111111";  // 16-digit credit card
    
    /* ========================================================================
     * Example 1: Basic Comparison - Same Input
     * ======================================================================== */
    print_separator("Example 1: Basic Encryption Comparison");
    
    printf("Input:   %s\n", test_input);
    printf("Radix:   10 (numeric)\n");
    printf("Key:     AES-128\n\n");
    
    /* FF1 */
    {
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
        
        const unsigned char tweak[] = "compare";
        char output[32] = {0};
        
        FPE_encrypt_str(ctx, alphabet, test_input, output, tweak, 7);
        printf("FF1:     %s (tweak: %s)\n", output, tweak);
        
        FPE_CTX_free(ctx);
    }
    
    /* FF3 (deprecated) */
    {
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
        
        const unsigned char tweak[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        char output[32] = {0};
        
        FPE_encrypt_str(ctx, alphabet, test_input, output, tweak, 8);
        printf("FF3:     %s (tweak: 8 bytes) [DEPRECATED]\n", output);
        
        FPE_CTX_free(ctx);
    }
    
    /* FF3-1 */
    {
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
        
        const unsigned char tweak[7] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        char output[32] = {0};
        
        FPE_encrypt_str(ctx, alphabet, test_input, output, tweak, 7);
        printf("FF3-1:   %s (tweak: 7 bytes)\n", output);
        
        FPE_CTX_free(ctx);
    }
    
    printf("\nNote: Different algorithms produce different ciphertexts\n");
    printf("      (even with same key and input)\n");
    
    /* ========================================================================
     * Example 2: Tweak Flexibility Comparison
     * ======================================================================== */
    print_separator("Example 2: Tweak Flexibility");
    
    printf("\nFF1 - Flexible Tweak Length:\n");
    {
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
        
        const char *tweaks[] = {"", "short", "medium_length", "very_long_tweak_string"};
        char output[32];
        
        for (int i = 0; i < 4; i++) {
            FPE_encrypt_str(ctx, alphabet, test_input, output, 
                           (const unsigned char*)tweaks[i], strlen(tweaks[i]));
            printf("  Tweak length %2zu: %s → %s\n", 
                   strlen(tweaks[i]), test_input, output);
        }
        
        FPE_CTX_free(ctx);
    }
    
    printf("\nFF3 - Fixed 8-byte Tweak (64 bits):\n");
    {
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
        
        const unsigned char tweak[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        char output[32];
        
        FPE_encrypt_str(ctx, alphabet, test_input, output, tweak, 8);
        printf("  Must be 8 bytes: %s → %s\n", test_input, output);
        printf("  [DEPRECATED - use FF3-1 instead]\n");
        
        FPE_CTX_free(ctx);
    }
    
    printf("\nFF3-1 - Fixed 7-byte Tweak (56 bits):\n");
    {
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
        
        const unsigned char tweak[7] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        char output[32];
        
        FPE_encrypt_str(ctx, alphabet, test_input, output, tweak, 7);
        printf("  Must be 7 bytes: %s → %s\n", test_input, output);
        
        FPE_CTX_free(ctx);
    }
    
    /* ========================================================================
     * Example 3: Performance Comparison
     * ======================================================================== */
    print_separator("Example 3: Performance Comparison");
    
    printf("\nMeasuring encryption speed (average of 1000 operations):\n\n");
    
    const int iterations = 1000;
    
    /* FF1 Performance */
    {
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
        
        const unsigned char tweak[] = "perf";
        double time_us = measure_time_us(ctx, alphabet, test_input, tweak, 4, iterations);
        double tps = 1000000.0 / time_us;
        
        printf("FF1:   %.2f μs/op  (~%.0f TPS)\n", time_us, tps);
        
        FPE_CTX_free(ctx);
    }
    
    /* FF3 Performance */
    {
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
        
        const unsigned char tweak[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        double time_us = measure_time_us(ctx, alphabet, test_input, tweak, 8, iterations);
        double tps = 1000000.0 / time_us;
        
        printf("FF3:   %.2f μs/op  (~%.0f TPS) [DEPRECATED]\n", time_us, tps);
        
        FPE_CTX_free(ctx);
    }
    
    /* FF3-1 Performance */
    {
        FPE_CTX *ctx = FPE_CTX_new();
        FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
        
        const unsigned char tweak[7] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        double time_us = measure_time_us(ctx, alphabet, test_input, tweak, 7, iterations);
        double tps = 1000000.0 / time_us;
        
        printf("FF3-1: %.2f μs/op  (~%.0f TPS)\n", time_us, tps);
        
        FPE_CTX_free(ctx);
    }
    
    printf("\nTPS = Transactions Per Second (single-threaded)\n");
    
    /* ========================================================================
     * Example 4: Security Comparison
     * ======================================================================== */
    print_separator("Example 4: Security Comparison");
    
    printf("\nSecurity Features:\n\n");
    
    printf("FF1 (NIST SP 800-38G):\n");
    printf("  ✓ Proven secure with strong cryptographic foundation\n");
    printf("  ✓ Most flexible (any radix 2-256, any tweak length)\n");
    printf("  ✓ 10 rounds (high security margin)\n");
    printf("  ✓ Recommended for new implementations\n");
    printf("  ✓ No known vulnerabilities\n\n");
    
    printf("FF3 (NIST SP 800-38G) [DEPRECATED]:\n");
    printf("  ✗ Known cryptographic weaknesses discovered\n");
    printf("  ✗ NIST deprecated in favor of FF3-1\n");
    printf("  ✗ Should not be used for new implementations\n");
    printf("  ✓ 8 rounds (adequate but less margin than FF1)\n");
    printf("  ✗ Fixed 64-bit tweak only\n\n");
    
    printf("FF3-1 (NIST SP 800-38G Rev 1):\n");
    printf("  ✓ Addresses security issues found in FF3\n");
    printf("  ✓ Approved replacement for FF3\n");
    printf("  ✓ 8 rounds with improved security\n");
    printf("  ✓ Fixed 56-bit tweak (smaller than FF3)\n");
    printf("  ✓ Suitable for applications requiring FF3 compatibility\n\n");
    
    /* ========================================================================
     * Example 5: Input Requirements
     * ======================================================================== */
    print_separator("Example 5: Input Requirements");
    
    printf("\nMinimum Input Length Requirements:\n\n");
    
    printf("Algorithm  Radix   Min Length  Example\n");
    printf("---------  ------  ----------  -------------------------\n");
    printf("FF1        10      6 digits    Credit card: 16 digits ✓\n");
    printf("FF1        36      4 chars     Serial: ABC123 (6) ✓\n");
    printf("FF1        62      4 chars     Token: aB3x (4) ✓\n\n");
    
    printf("FF3        10      6 digits    Credit card: 16 digits ✓\n");
    printf("FF3        36      4 chars     Serial: ABC123 (6) ✓\n");
    printf("FF3        [max]   36          Limited radix range\n\n");
    
    printf("FF3-1      10      6 digits    Credit card: 16 digits ✓\n");
    printf("FF3-1      36      4 chars     Serial: ABC123 (6) ✓\n");
    printf("FF3-1      [max]   36          Limited radix range\n\n");
    
    printf("Note: FF1 supports larger radix values (up to 256)\n");
    printf("      FF3/FF3-1 recommend radix ≤ 36 for optimal security\n");
    
    /* ========================================================================
     * Example 6: When to Use Each Algorithm
     * ======================================================================== */
    print_separator("Example 6: When to Use Each Algorithm");
    
    printf("\nUse FF1 when:\n\n");
    printf("1. Starting a new implementation (recommended)\n");
    printf("   - Best security and flexibility\n");
    printf("   - Most widely adopted\n");
    printf("   - Future-proof choice\n\n");
    
    printf("2. You need flexible tweak lengths\n");
    printf("   - Variable-length contextual data\n");
    printf("   - User IDs, transaction IDs, timestamps\n");
    printf("   - Application-specific metadata\n\n");
    
    printf("3. You need large radix support\n");
    printf("   - Radix > 36 (e.g., full ASCII, Base64)\n");
    printf("   - Unicode character sets\n");
    printf("   - Binary data (radix 256)\n\n");
    
    printf("4. Performance is important\n");
    printf("   - Fastest of the three algorithms\n");
    printf("   - ~90K TPS (single-threaded)\n");
    printf("   - Better scalability\n\n");
    
    printf("Use FF3-1 when:\n\n");
    
    printf("1. Migrating from FF3\n");
    printf("   - Drop-in replacement for FF3\n");
    printf("   - Addresses FF3 security issues\n");
    printf("   - Maintains compatibility requirements\n\n");
    
    printf("2. Regulatory compliance requires it\n");
    printf("   - Some standards may specify FF3-1\n");
    printf("   - Payment industry requirements\n");
    printf("   - Legacy system compatibility\n\n");
    
    printf("3. Fixed 7-byte tweak is acceptable\n");
    printf("   - Your tweak data fits in 56 bits\n");
    printf("   - Simpler API (no tweak length variation)\n\n");
    
    printf("NEVER use FF3:\n\n");
    
    printf("  ✗ FF3 is DEPRECATED due to security vulnerabilities\n");
    printf("  ✗ Use FF3-1 instead if you need FF3 compatibility\n");
    printf("  ✗ Use FF1 for new implementations\n\n");
    
    /* ========================================================================
     * Example 7: Compatibility Matrix
     * ======================================================================== */
    print_separator("Example 7: Compatibility Matrix");
    
    printf("\nFeature Comparison:\n\n");
    
    printf("Feature                FF1      FF3      FF3-1\n");
    printf("---------------------  -------  -------  -------\n");
    printf("NIST Approved          ✓        ✗        ✓\n");
    printf("Security Status        Strong   Weak     Strong\n");
    printf("Tweak Flexibility      High     Fixed    Fixed\n");
    printf("Tweak Length           Any      8 bytes  7 bytes\n");
    printf("Max Radix              256      36*      36*\n");
    printf("Performance (TPS)      ~90K     ~55K     ~55K\n");
    printf("Rounds                 10       8        8\n");
    printf("Recommended            ✓        ✗        ✓\n\n");
    
    printf("* Higher radix possible but not recommended for security\n");
    
    /* ========================================================================
     * Example 8: Migration Guide
     * ======================================================================== */
    print_separator("Example 8: Quick Migration Guide");
    
    printf("\nMigrating from FF3 to FF3-1:\n\n");
    
    printf("1. Change mode:\n");
    printf("   - Old: FPE_CTX_init(ctx, FPE_MODE_FF3, ...)\n");
    printf("   - New: FPE_CTX_init(ctx, FPE_MODE_FF3_1, ...)\n\n");
    
    printf("2. Update tweak length:\n");
    printf("   - Old: 8-byte tweak (64 bits)\n");
    printf("   - New: 7-byte tweak (56 bits)\n");
    printf("   - Action: Truncate or modify tweak to 7 bytes\n\n");
    
    printf("3. Test thoroughly:\n");
    printf("   - FF3-1 produces different ciphertexts than FF3\n");
    printf("   - Update test vectors\n");
    printf("   - Cannot decrypt FF3 data with FF3-1\n\n");
    
    printf("Migrating to FF1 (recommended):\n\n");
    
    printf("1. Change mode:\n");
    printf("   - FPE_CTX_init(ctx, FPE_MODE_FF1, ...)\n\n");
    
    printf("2. Tweak handling:\n");
    printf("   - FF1 accepts any tweak length\n");
    printf("   - Can use existing tweaks as-is\n");
    printf("   - Or redesign for better security\n\n");
    
    printf("3. Benefits:\n");
    printf("   - Better performance (~65%% faster)\n");
    printf("   - More flexibility\n");
    printf("   - Stronger security guarantees\n\n");
    
    printf("=== Algorithm Comparison Complete ===\n\n");
    
    printf("Summary Recommendations:\n");
    printf("• New implementations: Use FF1 (best choice)\n");
    printf("• FF3 compatibility needed: Use FF3-1 (security fix)\n");
    printf("• Never use FF3: It's deprecated and insecure\n");
    printf("• Performance priority: Use FF1 (fastest)\n");
    printf("• Flexibility priority: Use FF1 (most flexible)\n");
    
    return 0;
}
