/**
 * @file oneshot.c
 * @brief One-shot API example for FPE encryption
 * 
 * This example demonstrates the one-shot (stateless) API, which allows
 * encryption and decryption without managing FPE_CTX lifecycle.
 * Perfect for single operations or when context reuse isn't needed.
 */

#include <fpe.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== FPE-C One-Shot API Example ===\n\n");
    
    /* ========================================================================
     * Example 1: One-Shot String Encryption (Most Convenient)
     * ======================================================================== */
    
    printf("Example 1: One-Shot String API\n");
    printf("-------------------------------\n");
    
    // Setup key
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    // Define alphabet and data
    char alphabet[] = "0123456789";
    char phone[] = "5551234567";  // 10-digit phone number
    char encrypted[11] = {0};
    char decrypted[11] = {0};
    
    // Tweak (context data)
    unsigned char tweak[] = {0xAA, 0xBB, 0xCC};
    
    // Encrypt in one call (no context needed!)
    int ret = FPE_encrypt_str_oneshot(
        FPE_MODE_FF1,       // Algorithm
        FPE_ALGO_AES,       // Cipher
        key, 128,           // Key and key size
        alphabet,           // Character set
        phone,              // Input
        encrypted,          // Output
        tweak, 3            // Tweak
    );
    
    if (ret != 0) {
        fprintf(stderr, "Error: Encryption failed\n");
        return 1;
    }
    
    printf("Original phone:   %s\n", phone);
    printf("Encrypted phone:  %s\n", encrypted);
    
    // Decrypt in one call
    ret = FPE_decrypt_str_oneshot(
        FPE_MODE_FF1,
        FPE_ALGO_AES,
        key, 128,
        alphabet,
        encrypted,
        decrypted,
        tweak, 3
    );
    
    if (ret != 0) {
        fprintf(stderr, "Error: Decryption failed\n");
        return 1;
    }
    
    printf("Decrypted phone:  %s\n", decrypted);
    
    if (strcmp(phone, decrypted) == 0) {
        printf("✓ One-shot string encryption successful\n\n");
    } else {
        printf("✗ Decryption mismatch\n\n");
        return 1;
    }
    
    /* ========================================================================
     * Example 2: One-Shot Integer Array Encryption
     * ======================================================================== */
    
    printf("Example 2: One-Shot Integer Array API\n");
    printf("--------------------------------------\n");
    
    unsigned int ssn[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};  // SSN: 123-45-6789
    unsigned int encrypted_int[9];
    unsigned int decrypted_int[9];
    int length = 9;
    
    // Encrypt
    ret = FPE_encrypt_oneshot(
        FPE_MODE_FF1,
        FPE_ALGO_AES,
        key, 128,
        10,                 // Radix (decimal)
        ssn,
        encrypted_int,
        length,
        tweak, 3
    );
    
    if (ret != 0) {
        fprintf(stderr, "Error: Integer encryption failed\n");
        return 1;
    }
    
    printf("Original SSN:   ");
    for (int i = 0; i < length; i++) printf("%u", ssn[i]);
    printf("\n");
    
    printf("Encrypted SSN:  ");
    for (int i = 0; i < length; i++) printf("%u", encrypted_int[i]);
    printf("\n");
    
    // Decrypt
    ret = FPE_decrypt_oneshot(
        FPE_MODE_FF1,
        FPE_ALGO_AES,
        key, 128,
        10,
        encrypted_int,
        decrypted_int,
        length,
        tweak, 3
    );
    
    if (ret != 0) {
        fprintf(stderr, "Error: Integer decryption failed\n");
        return 1;
    }
    
    printf("Decrypted SSN:  ");
    for (int i = 0; i < length; i++) printf("%u", decrypted_int[i]);
    printf("\n");
    
    // Verify
    int match = 1;
    for (int i = 0; i < length; i++) {
        if (ssn[i] != decrypted_int[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        printf("✓ One-shot integer encryption successful\n\n");
    } else {
        printf("✗ Integer decryption mismatch\n\n");
        return 1;
    }
    
    /* ========================================================================
     * Example 3: Different Algorithms (FF1 vs FF3-1)
     * ======================================================================== */
    
    printf("Example 3: Comparing FF1 and FF3-1\n");
    printf("-----------------------------------\n");
    
    char data[] = "9876543210";
    char cipher_ff1[11] = {0};
    char cipher_ff3_1[11] = {0};
    
    unsigned char tweak_ff1[] = {0x01, 0x02, 0x03, 0x04};
    unsigned char tweak_ff3_1[7] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    
    // Encrypt with FF1
    FPE_encrypt_str_oneshot(
        FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
        alphabet, data, cipher_ff1, tweak_ff1, 4
    );
    
    // Encrypt with FF3-1 (note: different tweak length)
    FPE_encrypt_str_oneshot(
        FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128,
        alphabet, data, cipher_ff3_1, tweak_ff3_1, 7
    );
    
    printf("Original:     %s\n", data);
    printf("FF1 cipher:   %s\n", cipher_ff1);
    printf("FF3-1 cipher: %s\n", cipher_ff3_1);
    
    if (strcmp(cipher_ff1, cipher_ff3_1) != 0) {
        printf("✓ Different algorithms produce different outputs\n\n");
    }
    
    /* ========================================================================
     * Example 4: Performance Comparison (One-Shot vs Context Reuse)
     * ======================================================================== */
    
    printf("Example 4: Performance Note\n");
    printf("----------------------------\n");
    printf("One-shot API is convenient but recreates context each call.\n");
    printf("For bulk operations, use context-based API for better performance.\n\n");
    
    printf("One-shot API best for:\n");
    printf("  - Single encrypt/decrypt operations\n");
    printf("  - Simple use cases without state\n");
    printf("  - Prototyping and testing\n\n");
    
    printf("Context API best for:\n");
    printf("  - Multiple operations with same key/algorithm\n");
    printf("  - High-performance scenarios\n");
    printf("  - Long-running services\n\n");
    
    /* ========================================================================
     * Example 5: Error Handling
     * ======================================================================== */
    
    printf("Example 5: Error Handling\n");
    printf("-------------------------\n");
    
    char invalid_alphabet[] = "012345678";  // Missing '9'
    char test_input[] = "1234567890";       // Contains '9'!
    char test_output[11] = {0};
    
    ret = FPE_encrypt_str_oneshot(
        FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
        invalid_alphabet, test_input, test_output, tweak, 3
    );
    
    if (ret != 0) {
        printf("✓ Error correctly detected: character '9' not in alphabet\n");
    } else {
        printf("✗ Expected error not raised\n");
    }
    
    printf("\n=== All one-shot examples completed! ===\n");
    return 0;
}
