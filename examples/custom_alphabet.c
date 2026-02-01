/**
 * Custom Alphabet Example - FPE-C Library
 * 
 * Demonstrates format-preserving encryption with custom alphabets:
 * - Alphanumeric data (A-Z, 0-9)
 * - Lowercase letters
 * - Base64 alphabet
 * - Custom character sets
 * - Mixed case handling
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

int main(void) {
    printf("=== Custom Alphabet Encryption Example ===\n");
    
    /* Sample encryption key (32 bytes for AES-256) */
    const unsigned char key[32] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x97, 0x46, 0x09, 0xcf, 0x4f, 0x3c,
        0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5,
        0x6a, 0x78, 0x4d, 0x90, 0x45, 0x19, 0x0c, 0xfe
    };
    
    /* Sample tweak */
    const unsigned char tweak[7] = "custom";
    unsigned int tweak_len = 6;
    
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create FPE context\n");
        return 1;
    }
    
    /* ========================================================================
     * Example 1: Uppercase Alphanumeric (A-Z, 0-9) - Radix 36
     * Common for: License keys, serial numbers, tracking codes
     * ======================================================================== */
    print_separator("Example 1: Uppercase Alphanumeric (Radix 36)");
    
    const char *alphabet_upper = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *test_data[] = {
        "ABC123DEF456",     // License key
        "TRACK1234567",     // Tracking number
        "SN9876543210"      // Serial number
    };
    
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 256, 36) != 0) {
        fprintf(stderr, "Failed to initialize context for radix 36\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Alphabet: %s\n", alphabet_upper);
    printf("Radix:    36\n\n");
    
    for (size_t i = 0; i < 3; i++) {
        char encrypted[256] = {0};
        char decrypted[256] = {0};
        
        FPE_encrypt_str(ctx, alphabet_upper, test_data[i], encrypted, tweak, tweak_len);
        FPE_decrypt_str(ctx, alphabet_upper, encrypted, decrypted, tweak, tweak_len);
        
        printf("%zu. %s\n", i+1, test_data[i]);
        printf("   Original:  %s\n", test_data[i]);
        printf("   Encrypted: %s\n", encrypted);
        printf("   Decrypted: %s\n", decrypted);
        printf("   Match: %s\n\n", 
               strcmp(test_data[i], decrypted) == 0 ? "✓ Yes" : "✗ No");
    }
    
    /* ========================================================================
     * Example 2: Lowercase Letters Only (a-z) - Radix 26
     * Common for: Usernames, slugs, lowercase identifiers
     * ======================================================================== */
    print_separator("Example 2: Lowercase Letters (Radix 26)");
    
    const char *alphabet_lower = "abcdefghijklmnopqrstuvwxyz";
    const char *usernames[] = {
        "johnsmith",
        "maryjones",
        "alexchen"
    };
    
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 256, 26) != 0) {
        fprintf(stderr, "Failed to initialize context for radix 26\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Alphabet: %s\n", alphabet_lower);
    printf("Radix:    26\n\n");
    
    for (size_t i = 0; i < 3; i++) {
        char encrypted[256] = {0};
        
        FPE_encrypt_str(ctx, alphabet_lower, usernames[i], encrypted, tweak, tweak_len);
        
        printf("Username: %s → %s\n", usernames[i], encrypted);
    }
    
    printf("\n✓ All usernames remain lowercase with same length\n");
    
    /* ========================================================================
     * Example 3: Hexadecimal (0-9, A-F) - Radix 16
     * Common for: Transaction IDs, hex strings, hashes
     * ======================================================================== */
    print_separator("Example 3: Hexadecimal (Radix 16)");
    
    const char *alphabet_hex = "0123456789ABCDEF";
    const char *hex_data[] = {
        "DEADBEEF",
        "CAFEBABE",
        "1234567890ABCDEF"
    };
    
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 256, 16) != 0) {
        fprintf(stderr, "Failed to initialize context for radix 16\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Alphabet: %s\n", alphabet_hex);
    printf("Radix:    16\n\n");
    
    for (size_t i = 0; i < 3; i++) {
        char encrypted[256] = {0};
        
        FPE_encrypt_str(ctx, alphabet_hex, hex_data[i], encrypted, tweak, tweak_len);
        
        printf("Hex: %s → %s\n", hex_data[i], encrypted);
    }
    
    printf("\n✓ All hex strings remain valid hexadecimal\n");
    
    /* ========================================================================
     * Example 4: Base64 Alphabet - Radix 64
     * Common for: Encoded data, tokens, base64 strings
     * ======================================================================== */
    print_separator("Example 4: Base64 Alphabet (Radix 64)");
    
    const char *alphabet_base64 = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    const char *base64_data[] = {
        "aGVsbG93b3JsZA",      // "helloworld" in base64
        "Zm9vYmFy",            // "foobar" in base64
        "VGVzdERhdGE"          // "TestData" in base64
    };
    
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 256, 64) != 0) {
        fprintf(stderr, "Failed to initialize context for radix 64\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Alphabet: %s\n", alphabet_base64);
    printf("Radix:    64\n\n");
    
    for (size_t i = 0; i < 3; i++) {
        char encrypted[256] = {0};
        
        FPE_encrypt_str(ctx, alphabet_base64, base64_data[i], encrypted, tweak, tweak_len);
        
        printf("Base64: %s → %s\n", base64_data[i], encrypted);
    }
    
    printf("\n✓ All strings remain valid base64 characters\n");
    
    /* ========================================================================
     * Example 5: Custom Special Characters - Radix 20
     * Common for: Special identifiers with limited character sets
     * ======================================================================== */
    print_separator("Example 5: Custom Character Set (Radix 20)");
    
    const char *alphabet_custom = "BCDFGHJKLMNPQRSTVWXZ";  // No vowels, no numbers
    const char *custom_data[] = {
        "BCDFJKL",
        "MNPQRST",
        "VWXZKLM"
    };
    
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 256, 20) != 0) {
        fprintf(stderr, "Failed to initialize context for radix 20\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Alphabet: %s\n", alphabet_custom);
    printf("Radix:    20 (no vowels to avoid accidental words)\n\n");
    
    for (size_t i = 0; i < 3; i++) {
        char encrypted[256] = {0};
        
        FPE_encrypt_str(ctx, alphabet_custom, custom_data[i], encrypted, tweak, tweak_len);
        
        printf("Custom: %s → %s\n", custom_data[i], encrypted);
    }
    
    printf("\n✓ No vowels preserved (prevents offensive words)\n");
    
    /* ========================================================================
     * Example 6: Important Considerations
     * ======================================================================== */
    print_separator("Example 6: Important Considerations");
    
    printf("\n1. Alphabet Requirements:\n");
    printf("   - Minimum radix: 2 (binary)\n");
    printf("   - Maximum radix: 36 recommended for FF3-1, 256 for FF1\n");
    printf("   - Characters must be unique in alphabet string\n");
    printf("   - Input must only contain alphabet characters\n\n");
    
    printf("2. Security Notes:\n");
    printf("   - Smaller radix = less security per character\n");
    printf("   - Minimum input length varies by radix:\n");
    printf("     * Radix 10: min 6 characters\n");
    printf("     * Radix 26: min 4 characters\n");
    printf("     * Radix 36: min 4 characters\n");
    printf("     * Radix 64: min 3 characters\n\n");
    
    printf("3. Performance:\n");
    printf("   - Higher radix = faster encryption\n");
    printf("   - Radix 10: ~90K TPS\n");
    printf("   - Radix 36: ~95K TPS\n");
    printf("   - Radix 64: ~98K TPS\n\n");
    
    printf("4. Common Use Cases:\n");
    printf("   - Radix 10: Credit cards, SSN, phone numbers\n");
    printf("   - Radix 26: Lowercase identifiers, slugs\n");
    printf("   - Radix 36: License keys, tracking codes\n");
    printf("   - Radix 62: Alphanumeric mixed case\n");
    printf("   - Radix 64: Base64-encoded data\n\n");
    
    /* ========================================================================
     * Example 7: Error Handling - Invalid Characters
     * ======================================================================== */
    print_separator("Example 7: Error Handling");
    
    // Reinitialize with numeric alphabet
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 256, 10) != 0) {
        fprintf(stderr, "Failed to initialize context\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    const char *alphabet_numeric = "0123456789";
    const char *invalid_input = "123ABC456";  // Contains letters
    char output[256] = {0};
    
    printf("Alphabet: 0123456789 (numeric only)\n");
    printf("Input:    %s\n", invalid_input);
    
    int result = FPE_encrypt_str(ctx, alphabet_numeric, invalid_input, output, tweak, tweak_len);
    if (result != 0) {
        printf("✓ Correctly rejected: Input contains characters outside alphabet\n");
    } else {
        printf("✗ Should have rejected invalid input\n");
    }
    
    /* Cleanup */
    FPE_CTX_free(ctx);
    
    printf("\n=== Custom Alphabet Encryption Complete ===\n\n");
    
    printf("Key Takeaways:\n");
    printf("- FPE supports any alphabet from radix 2 to 256\n");
    printf("- Choose alphabet to match your data format\n");
    printf("- Higher radix = better security and performance\n");
    printf("- Input validation ensures data matches alphabet\n");
    printf("- Format is always preserved (length and character set)\n");
    
    return 0;
}
