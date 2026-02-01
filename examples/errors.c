/**
 * Error Handling Example - FPE-C Library
 * 
 * Comprehensive guide to error handling in FPE-C:
 * - Common error scenarios
 * - Return value interpretation
 * - Input validation errors
 * - Recovery strategies
 * - Best practices
 * - Debugging tips
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

/* Helper to check and report errors */
static void check_error(int ret, const char *operation) {
    if (ret == 0) {
        printf("✓ %s succeeded\n", operation);
    } else {
        printf("✗ %s failed (return code: %d)\n", operation, ret);
    }
}

int main(void) {
    printf("=== Error Handling Example ===\n");
    
    const unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    const char *alphabet = "0123456789";
    const unsigned char tweak[] = "test";
    
    /* ========================================================================
     * Example 1: Context Allocation Errors
     * ======================================================================== */
    print_separator("Example 1: Context Allocation");
    
    printf("\nProper context allocation:\n");
    FPE_CTX *ctx = FPE_CTX_new();
    if (ctx == NULL) {
        printf("✗ Failed to allocate context (out of memory)\n");
        return 1;
    }
    printf("✓ Context allocated successfully\n");
    
    printf("\nAlways check for NULL before using context!\n");
    
    /* ========================================================================
     * Example 2: Invalid Key Lengths
     * ======================================================================== */
    print_separator("Example 2: Invalid Key Lengths");
    
    printf("\nTesting different key lengths:\n\n");
    
    /* Valid key lengths */
    printf("AES valid key lengths:\n");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10), 
                "AES-128 (128 bits)");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 192, 10), 
                "AES-192 (192 bits)");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 256, 10), 
                "AES-256 (256 bits)");
    
    printf("\nSM4 valid key length:\n");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10), 
                "SM4-128 (128 bits)");
    
    printf("\nInvalid key lengths:\n");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 64, 10), 
                "AES-64 (invalid)");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 512, 10), 
                "AES-512 (invalid)");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 256, 10), 
                "SM4-256 (invalid)");
    
    /* ========================================================================
     * Example 3: Invalid Radix Values
     * ======================================================================== */
    print_separator("Example 3: Invalid Radix Values");
    
    printf("\nTesting radix validation:\n\n");
    
    printf("Valid radix values:\n");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 2), 
                "Radix 2 (binary)");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10), 
                "Radix 10 (decimal)");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 36), 
                "Radix 36 (alphanumeric)");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 256), 
                "Radix 256 (FF1 max)");
    
    printf("\nInvalid radix values:\n");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 0), 
                "Radix 0 (invalid)");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 1), 
                "Radix 1 (invalid)");
    check_error(FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 65537), 
                "Radix 65537 (too large)");
    
    /* ========================================================================
     * Example 4: Invalid Input Characters
     * ======================================================================== */
    print_separator("Example 4: Invalid Input Characters");
    
    /* Initialize with valid parameters */
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    printf("\nAlphabet: 0123456789 (numeric only)\n\n");
    
    char output[32];
    
    printf("Valid inputs:\n");
    int ret = FPE_encrypt_str(ctx, alphabet, "1234567890", output, tweak, 4);
    check_error(ret, "Encrypt '1234567890'");
    
    ret = FPE_encrypt_str(ctx, alphabet, "0000000000", output, tweak, 4);
    check_error(ret, "Encrypt '0000000000'");
    
    printf("\nInvalid inputs (contain non-numeric characters):\n");
    ret = FPE_encrypt_str(ctx, alphabet, "123ABC789", output, tweak, 4);
    check_error(ret, "Encrypt '123ABC789'");
    
    ret = FPE_encrypt_str(ctx, alphabet, "12 34 56", output, tweak, 4);
    check_error(ret, "Encrypt '12 34 56'");
    
    ret = FPE_encrypt_str(ctx, alphabet, "hello123", output, tweak, 4);
    check_error(ret, "Encrypt 'hello123'");
    
    printf("\nNote: Always validate input before encryption!\n");
    
    /* ========================================================================
     * Example 5: Input Length Validation
     * ======================================================================== */
    print_separator("Example 5: Input Length Validation");
    
    printf("\nMinimum length requirements vary by radix:\n\n");
    
    printf("Radix 10 (decimal):\n");
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    check_error(FPE_encrypt_str(ctx, alphabet, "123456", output, tweak, 4), 
                "6 digits (minimum)");
    check_error(FPE_encrypt_str(ctx, alphabet, "12345", output, tweak, 4), 
                "5 digits (too short)");
    check_error(FPE_encrypt_str(ctx, alphabet, "1234", output, tweak, 4), 
                "4 digits (too short)");
    
    printf("\nRadix 36 (alphanumeric):\n");
    const char *alpha36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 36);
    
    check_error(FPE_encrypt_str(ctx, alpha36, "ABCD", output, tweak, 4), 
                "4 chars (minimum)");
    check_error(FPE_encrypt_str(ctx, alpha36, "ABC", output, tweak, 4), 
                "3 chars (too short)");
    
    /* ========================================================================
     * Example 6: Tweak Length Validation (FF3-1)
     * ======================================================================== */
    print_separator("Example 6: Tweak Length Validation");
    
    printf("\nFF1 - Flexible tweak length:\n");
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    check_error(FPE_encrypt_str(ctx, alphabet, "1234567890", output, NULL, 0), 
                "Empty tweak");
    check_error(FPE_encrypt_str(ctx, alphabet, "1234567890", output, tweak, 4), 
                "4-byte tweak");
    check_error(FPE_encrypt_str(ctx, alphabet, "1234567890", output, 
                (const unsigned char*)"verylongtweak", 13), 
                "13-byte tweak");
    
    printf("\nFF3-1 - Fixed 7-byte tweak:\n");
    FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    
    const unsigned char tweak7[7] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    const unsigned char tweak8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    check_error(FPE_encrypt_str(ctx, alphabet, "1234567890", output, tweak7, 7), 
                "7-byte tweak (required)");
    check_error(FPE_encrypt_str(ctx, alphabet, "1234567890", output, tweak, 4), 
                "4-byte tweak (invalid)");
    check_error(FPE_encrypt_str(ctx, alphabet, "1234567890", output, tweak8, 8), 
                "8-byte tweak (invalid)");
    
    /* ========================================================================
     * Example 7: NULL Pointer Handling
     * ======================================================================== */
    print_separator("Example 7: NULL Pointer Handling");
    
    printf("\nTesting NULL pointer validation:\n\n");
    
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    printf("Invalid NULL parameters:\n");
    check_error(FPE_encrypt_str(NULL, alphabet, "1234567890", output, tweak, 4), 
                "NULL context");
    check_error(FPE_encrypt_str(ctx, NULL, "1234567890", output, tweak, 4), 
                "NULL alphabet");
    check_error(FPE_encrypt_str(ctx, alphabet, NULL, output, tweak, 4), 
                "NULL input");
    check_error(FPE_encrypt_str(ctx, alphabet, "1234567890", NULL, tweak, 4), 
                "NULL output");
    
    printf("\nValid NULL tweak (FF1 only):\n");
    check_error(FPE_encrypt_str(ctx, alphabet, "1234567890", output, NULL, 0), 
                "NULL tweak with length 0");
    
    /* ========================================================================
     * Example 8: Error Recovery Strategies
     * ======================================================================== */
    print_separator("Example 8: Error Recovery Strategies");
    
    printf("\nStrategy 1: Validate Before Processing\n");
    printf("----------------------------------------\n");
    
    const char *user_input = "123ABC456";
    int is_valid = 1;
    
    /* Check if all characters are in alphabet */
    for (size_t i = 0; i < strlen(user_input); i++) {
        if (strchr(alphabet, user_input[i]) == NULL) {
            printf("✗ Invalid character '%c' at position %zu\n", user_input[i], i);
            is_valid = 0;
            break;
        }
    }
    
    if (is_valid) {
        printf("✓ Input validated, proceeding with encryption\n");
        FPE_encrypt_str(ctx, alphabet, user_input, output, tweak, 4);
    } else {
        printf("✗ Input validation failed, skipping encryption\n");
    }
    
    printf("\nStrategy 2: Graceful Degradation\n");
    printf("---------------------------------\n");
    
    ret = FPE_encrypt_str(ctx, alphabet, "1234567890", output, tweak, 4);
    if (ret == 0) {
        printf("✓ Encryption succeeded: %s\n", output);
    } else {
        printf("✗ Encryption failed, using plaintext (not recommended)\n");
        strcpy(output, "1234567890");
    }
    
    printf("\nStrategy 3: Retry with Different Parameters\n");
    printf("--------------------------------------------\n");
    
    const char *short_input = "12345";  // Too short for radix 10
    
    /* Try with radix 10 */
    ret = FPE_encrypt_str(ctx, alphabet, short_input, output, tweak, 4);
    if (ret != 0) {
        printf("✗ Failed with radix 10 (input too short)\n");
        printf("  Retrying with radix 36...\n");
        
        /* Switch to radix 36 which has lower minimum length */
        const char *alpha36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 36);
        
        ret = FPE_encrypt_str(ctx, alpha36, short_input, output, tweak, 4);
        check_error(ret, "Encryption with radix 36");
        
        /* Switch back to radix 10 */
        FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    }
    
    /* ========================================================================
     * Example 9: Best Practices
     * ======================================================================== */
    print_separator("Example 9: Best Practices");
    
    printf("\n1. Always Check Return Values:\n");
    printf("   ✓ if (FPE_encrypt_str(...) != 0) { handle_error(); }\n");
    printf("   ✗ FPE_encrypt_str(...);  // Don't ignore errors!\n\n");
    
    printf("2. Validate Input Before Encryption:\n");
    printf("   ✓ Check input length\n");
    printf("   ✓ Check characters match alphabet\n");
    printf("   ✓ Validate tweak length for FF3-1\n\n");
    
    printf("3. Initialize Context Once, Reuse Many Times:\n");
    printf("   ✓ Create context at startup\n");
    printf("   ✓ Reuse for multiple operations\n");
    printf("   ✓ Free when done\n\n");
    
    printf("4. Handle NULL Pointers:\n");
    printf("   ✓ Check ctx != NULL after FPE_CTX_new()\n");
    printf("   ✓ Never pass NULL input/output buffers\n\n");
    
    printf("5. Buffer Size Safety:\n");
    printf("   ✓ Output buffer must be >= input length + 1\n");
    printf("   ✓ Use sizeof() or explicit size constants\n");
    printf("   ✓ Never assume buffer size\n\n");
    
    printf("6. Error Logging:\n");
    printf("   ✓ Log errors with context (operation, input, parameters)\n");
    printf("   ✓ Don't log sensitive data (keys, plaintexts)\n");
    printf("   ✓ Use structured logging for production\n\n");
    
    /* ========================================================================
     * Example 10: Debugging Tips
     * ======================================================================== */
    print_separator("Example 10: Debugging Tips");
    
    printf("\nCommon Issues and Solutions:\n\n");
    
    printf("Issue: Encryption always fails\n");
    printf("  → Check: Context initialized correctly?\n");
    printf("  → Check: Input length meets minimum?\n");
    printf("  → Check: All characters in alphabet?\n\n");
    
    printf("Issue: Segmentation fault\n");
    printf("  → Check: Context is not NULL?\n");
    printf("  → Check: Output buffer allocated?\n");
    printf("  → Check: No buffer overflow?\n\n");
    
    printf("Issue: Wrong output\n");
    printf("  → Check: Same key and tweak for encrypt/decrypt?\n");
    printf("  → Check: Same algorithm (FF1/FF3-1)?\n");
    printf("  → Check: Same radix?\n\n");
    
    printf("Issue: Memory leak\n");
    printf("  → Check: FPE_CTX_free() called?\n");
    printf("  → Check: One free per context?\n");
    printf("  → Use: Valgrind or AddressSanitizer\n\n");
    
    printf("Debugging Tools:\n");
    printf("  • Valgrind: valgrind --leak-check=full ./program\n");
    printf("  • GDB: gdb ./program, then 'run', 'bt' on crash\n");
    printf("  • AddressSanitizer: compile with -fsanitize=address\n");
    
    /* Cleanup */
    FPE_CTX_free(ctx);
    
    printf("\n=== Error Handling Example Complete ===\n\n");
    
    printf("Key Takeaways:\n");
    printf("• Always check return values (0 = success, non-zero = error)\n");
    printf("• Validate input before encryption\n");
    printf("• Handle NULL pointers properly\n");
    printf("• Use appropriate error recovery strategies\n");
    printf("• Log errors with context (but not sensitive data)\n");
    printf("• Test edge cases and error conditions\n");
    
    return 0;
}
