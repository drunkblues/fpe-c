/**
 * @file basic.c
 * @brief Basic FPE encryption/decryption example
 * 
 * This example demonstrates:
 * - Creating and initializing an FPE context
 * - Encrypting and decrypting numeric data (credit card numbers)
 * - Using the string API with a custom alphabet
 * - Proper cleanup and error handling
 */

#include <fpe.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("=== FPE-C Basic Example ===\n\n");
    
    /* ========================================================================
     * Example 1: Encrypting a Credit Card Number (FF1 + AES-128)
     * ======================================================================== */
    
    printf("Example 1: Credit Card Encryption\n");
    printf("----------------------------------\n");
    
    // Step 1: Create context
    FPE_CTX *ctx = FPE_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error: Failed to create FPE context\n");
        return 1;
    }
    
    // Step 2: Set up encryption key (16 bytes for AES-128)
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    // Step 3: Initialize context for FF1 with AES-128, radix 10 (decimal digits)
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    if (ret != 0) {
        fprintf(stderr, "Error: Failed to initialize FPE context\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    // Step 4: Define the alphabet (0-9 for credit card numbers)
    char alphabet[] = "0123456789";
    
    // Step 5: Credit card number to encrypt
    char plaintext[] = "4111111111111111";  // Test Visa card
    char ciphertext[17] = {0};  // +1 for null terminator
    
    // Step 6: Tweak (optional contextual data, e.g., user ID)
    unsigned char tweak[] = {0x01, 0x02, 0x03, 0x04};
    unsigned int tweak_len = 4;
    
    // Step 7: Encrypt
    ret = FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, tweak_len);
    if (ret != 0) {
        fprintf(stderr, "Error: Encryption failed\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Plaintext:  %s\n", plaintext);
    printf("Ciphertext: %s\n", ciphertext);
    
    // Step 8: Decrypt to verify
    char decrypted[17] = {0};
    ret = FPE_decrypt_str(ctx, alphabet, ciphertext, decrypted, tweak, tweak_len);
    if (ret != 0) {
        fprintf(stderr, "Error: Decryption failed\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Decrypted:  %s\n", decrypted);
    
    // Verify correctness
    if (strcmp(plaintext, decrypted) == 0) {
        printf("✓ Decryption successful (matches original)\n\n");
    } else {
        printf("✗ Decryption failed (mismatch)\n\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    /* ========================================================================
     * Example 2: Different Tweak = Different Ciphertext
     * ======================================================================== */
    
    printf("Example 2: Tweak Demonstration\n");
    printf("-------------------------------\n");
    
    unsigned char tweak1[] = {0x01};
    unsigned char tweak2[] = {0x02};
    char cipher1[17] = {0};
    char cipher2[17] = {0};
    
    FPE_encrypt_str(ctx, alphabet, plaintext, cipher1, tweak1, 1);
    FPE_encrypt_str(ctx, alphabet, plaintext, cipher2, tweak2, 1);
    
    printf("Same plaintext:  %s\n", plaintext);
    printf("Tweak 0x01:      %s\n", cipher1);
    printf("Tweak 0x02:      %s\n", cipher2);
    
    if (strcmp(cipher1, cipher2) != 0) {
        printf("✓ Different tweaks produce different ciphertexts\n\n");
    } else {
        printf("✗ Unexpected: tweaks should produce different outputs\n\n");
    }
    
    /* ========================================================================
     * Example 3: Using Integer Array API (Low-Level)
     * ======================================================================== */
    
    printf("Example 3: Integer Array API\n");
    printf("-----------------------------\n");
    
    unsigned int input[] = {4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    unsigned int output[16];
    unsigned int decrypted_int[16];
    int length = 16;
    
    // Encrypt using integer array API
    ret = FPE_encrypt(ctx, input, output, length, tweak, tweak_len);
    if (ret != 0) {
        fprintf(stderr, "Error: Integer array encryption failed\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Input:      ");
    for (int i = 0; i < length; i++) printf("%u", input[i]);
    printf("\n");
    
    printf("Encrypted:  ");
    for (int i = 0; i < length; i++) printf("%u", output[i]);
    printf("\n");
    
    // Decrypt
    ret = FPE_decrypt(ctx, output, decrypted_int, length, tweak, tweak_len);
    if (ret != 0) {
        fprintf(stderr, "Error: Integer array decryption failed\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Decrypted:  ");
    for (int i = 0; i < length; i++) printf("%u", decrypted_int[i]);
    printf("\n");
    
    // Verify
    int match = 1;
    for (int i = 0; i < length; i++) {
        if (input[i] != decrypted_int[i]) {
            match = 0;
            break;
        }
    }
    
    if (match) {
        printf("✓ Integer array encryption/decryption successful\n\n");
    } else {
        printf("✗ Integer array verification failed\n\n");
    }
    
    /* ========================================================================
     * Example 4: FF3-1 Algorithm (Alternative)
     * ======================================================================== */
    
    printf("Example 4: Using FF3-1 Algorithm\n");
    printf("---------------------------------\n");
    
    // Reinitialize context with FF3-1
    FPE_CTX_free(ctx);
    ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    
    // FF3-1 requires 7-byte tweak (56 bits)
    unsigned char tweak_ff3_1[7] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    char cipher_ff3_1[17] = {0};
    char decrypt_ff3_1[17] = {0};
    
    ret = FPE_encrypt_str(ctx, alphabet, plaintext, cipher_ff3_1, tweak_ff3_1, 7);
    if (ret == 0) {
        printf("FF3-1 Plaintext:  %s\n", plaintext);
        printf("FF3-1 Ciphertext: %s\n", cipher_ff3_1);
        
        FPE_decrypt_str(ctx, alphabet, cipher_ff3_1, decrypt_ff3_1, tweak_ff3_1, 7);
        printf("FF3-1 Decrypted:  %s\n", decrypt_ff3_1);
        
        if (strcmp(plaintext, decrypt_ff3_1) == 0) {
            printf("✓ FF3-1 encryption/decryption successful\n\n");
        }
    }
    
    /* ========================================================================
     * Cleanup
     * ======================================================================== */
    
    FPE_CTX_free(ctx);
    
    printf("=== All examples completed successfully! ===\n");
    return 0;
}
