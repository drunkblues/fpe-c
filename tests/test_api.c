/**
 * @file test_api.c
 * @brief Unit tests for public API functions
 * 
 * Tests for context lifecycle, unified API dispatch, string API,
 * and in-place operations.
 */

#include "../include/fpe.h"
#include "../src/utils.h"
#include "unity/src/unity.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ========================================================================= */
/*                     Context Lifecycle Tests (8.12)                        */
/* ========================================================================= */

void test_context_new_returns_valid_pointer(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_free(ctx);
}

void test_context_free_null_safe(void) {
    // Should not crash
    FPE_CTX_free(NULL);
    TEST_ASSERT_TRUE(1); // If we get here, test passed
}

void test_context_init_ff1_aes128(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_context_init_ff1_aes256(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[32] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 256, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_context_init_ff3_aes128(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_context_init_ff3_1_aes128(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

#ifdef HAVE_OPENSSL_SM4
void test_context_init_ff1_sm4(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16];
    fpe_hex_to_bytes("0123456789ABCDEFFEDCBA9876543210", key, 16);
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}
#endif

void test_context_init_invalid_key_length(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {0};
    
    // Invalid key length (should be 128, 192, or 256)
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 512, 10);
    TEST_ASSERT_NOT_EQUAL(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_context_init_invalid_radix_too_small(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {0};
    
    // Invalid radix (too small)
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 1);
    TEST_ASSERT_NOT_EQUAL(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_context_init_invalid_radix_too_large(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {0};
    
    // Invalid radix (too large)
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 65537);
    TEST_ASSERT_NOT_EQUAL(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_context_multiple_init_same_context(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    // First init
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    // Second init (should work, reinitializing context)
    ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 26);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*                  Unified API Dispatch Tests (8.13)                        */
/* ========================================================================= */

void test_unified_api_ff1_dispatch(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 10);
    
    FPE_CTX_free(ctx);
}

void test_unified_api_ff3_dispatch(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int plaintext[10] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    unsigned char tweak[8] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x00};
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 10, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 10);
    
    FPE_CTX_free(ctx);
}

void test_unified_api_ff3_1_dispatch(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int plaintext[10] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    unsigned char tweak[7] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A};
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 10);
    
    FPE_CTX_free(ctx);
}

void test_unified_api_null_context(void) {
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    int ret = FPE_encrypt(NULL, plaintext, ciphertext, 10, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
    
    ret = FPE_decrypt(NULL, plaintext, ciphertext, 10, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

void test_unified_api_null_input(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {0};
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int ciphertext[10];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    ret = FPE_encrypt(ctx, NULL, ciphertext, 10, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_unified_api_null_output(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {0};
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    ret = FPE_encrypt(ctx, plaintext, NULL, 10, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*                      String API Tests (8.14)                              */
/* ========================================================================= */

void test_string_api_numeric_alphabet(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    const char *plaintext = "1234567890";
    char ciphertext[32];
    char decrypted[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789";
    
    ret = FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_str(ctx, alphabet, ciphertext, decrypted, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
    
    FPE_CTX_free(ctx);
}

void test_string_api_lowercase_alphabet(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 26);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    const char *plaintext = "hello";
    char ciphertext[32];
    char decrypted[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "abcdefghijklmnopqrstuvwxyz";
    
    ret = FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_str(ctx, alphabet, ciphertext, decrypted, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
    
    FPE_CTX_free(ctx);
}

void test_string_api_alphanumeric_alphabet(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 36);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    const char *plaintext = "test123";
    char ciphertext[32];
    char decrypted[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
    
    ret = FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_str(ctx, alphabet, ciphertext, decrypted, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
    
    FPE_CTX_free(ctx);
}

void test_string_api_custom_alphabet(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    const char *plaintext = "ACGT";
    char ciphertext[32];
    char decrypted[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "ACGT";
    
    ret = FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_str(ctx, alphabet, ciphertext, decrypted, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
    
    FPE_CTX_free(ctx);
}

void test_string_api_null_output_buffer(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {0};
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    const char *plaintext = "1234567890";
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789";
    
    ret = FPE_encrypt_str(ctx, alphabet, plaintext, NULL, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_string_api_invalid_character(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {0};
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    const char *plaintext = "123abc"; // 'abc' not in numeric alphabet
    char ciphertext[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789";
    
    ret = FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*                   In-Place Operations Tests (8.15)                        */
/* ========================================================================= */

void test_inplace_encrypt_decrypt(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int original[10];
    memcpy(original, data, sizeof(data));
    
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    // In-place encryption
    ret = FPE_encrypt(ctx, data, data, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    // In-place decryption
    ret = FPE_decrypt(ctx, data, data, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(original, data, 10);
    
    FPE_CTX_free(ctx);
}

void test_inplace_string_encrypt_decrypt(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    char data[32] = "1234567890";
    char original[32];
    strcpy(original, data);
    
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789";
    
    // In-place encryption
    ret = FPE_encrypt_str(ctx, alphabet, data, data, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    // In-place decryption
    ret = FPE_decrypt_str(ctx, alphabet, data, data, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(original, data);
    
    FPE_CTX_free(ctx);
}

void test_inplace_ff3_encrypt_decrypt(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int data[10] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5};
    unsigned int original[10];
    memcpy(original, data, sizeof(data));
    
    unsigned char tweak[8] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x00};
    
    // In-place encryption
    ret = FPE_encrypt(ctx, data, data, 10, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    // In-place decryption
    ret = FPE_decrypt(ctx, data, data, 10, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(original, data, 10);
    
    FPE_CTX_free(ctx);
}

void test_inplace_ff3_1_encrypt_decrypt(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int data[10] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5};
    unsigned int original[10];
    memcpy(original, data, sizeof(data));
    
    unsigned char tweak[7] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A};
    
    // In-place encryption
    ret = FPE_encrypt(ctx, data, data, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    // In-place decryption
    ret = FPE_decrypt(ctx, data, data, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(original, data, 10);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*                            Main Test Runner                               */
/* ========================================================================= */

int main(void) {
    UNITY_BEGIN();
    
    // Context Lifecycle Tests (8.12)
    RUN_TEST(test_context_new_returns_valid_pointer);
    RUN_TEST(test_context_free_null_safe);
    RUN_TEST(test_context_init_ff1_aes128);
    RUN_TEST(test_context_init_ff1_aes256);
    RUN_TEST(test_context_init_ff3_aes128);
    RUN_TEST(test_context_init_ff3_1_aes128);
#ifdef HAVE_OPENSSL_SM4
    RUN_TEST(test_context_init_ff1_sm4);
#endif
    RUN_TEST(test_context_init_invalid_key_length);
    RUN_TEST(test_context_init_invalid_radix_too_small);
    RUN_TEST(test_context_init_invalid_radix_too_large);
    RUN_TEST(test_context_multiple_init_same_context);
    
    // Unified API Dispatch Tests (8.13)
    RUN_TEST(test_unified_api_ff1_dispatch);
    RUN_TEST(test_unified_api_ff3_dispatch);
    RUN_TEST(test_unified_api_ff3_1_dispatch);
    RUN_TEST(test_unified_api_null_context);
    RUN_TEST(test_unified_api_null_input);
    RUN_TEST(test_unified_api_null_output);
    
    // String API Tests (8.14)
    RUN_TEST(test_string_api_numeric_alphabet);
    RUN_TEST(test_string_api_lowercase_alphabet);
    RUN_TEST(test_string_api_alphanumeric_alphabet);
    RUN_TEST(test_string_api_custom_alphabet);
    RUN_TEST(test_string_api_null_output_buffer);
    RUN_TEST(test_string_api_invalid_character);
    
    // In-Place Operations Tests (8.15)
    RUN_TEST(test_inplace_encrypt_decrypt);
    RUN_TEST(test_inplace_string_encrypt_decrypt);
    RUN_TEST(test_inplace_ff3_encrypt_decrypt);
    RUN_TEST(test_inplace_ff3_1_encrypt_decrypt);
    
    return UNITY_END();
}
