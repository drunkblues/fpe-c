/**
 * @file test_sm4.c
 * @brief Test SM4 support in FF1 algorithm
 */

#include "../include/fpe.h"
#include "../src/utils.h"
#include "unity/src/unity.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* Test SM4 context initialization */
void test_sm4_context_init(void) {
#ifdef HAVE_OPENSSL_SM4
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
#else
    TEST_IGNORE_MESSAGE("SM4 not supported in this OpenSSL version");
#endif
}

/* Test FF1 with SM4 - basic encryption/decryption */
void test_ff1_sm4_basic(void) {
#ifdef HAVE_OPENSSL_SM4
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10));
    
    unsigned int plaintext[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    unsigned char tweak[10] = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};
    
    /* Encrypt */
    int ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Verify ciphertext is different from plaintext */
    int different = 0;
    for (int i = 0; i < 10; i++) {
        if (ciphertext[i] != plaintext[i]) different = 1;
    }
    TEST_ASSERT_TRUE(different);
    
    /* Decrypt */
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 10, tweak, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Verify decryption matches original plaintext */
    TEST_ASSERT_EQUAL_UINT_ARRAY(plaintext, decrypted, 10);
    
    FPE_CTX_free(ctx);
#else
    TEST_IGNORE_MESSAGE("SM4 not supported in this OpenSSL version");
#endif
}

/* Test FF1 SM4 test vector from tests/vectors.h */
void test_ff1_sm4_test_vector(void) {
#ifdef HAVE_OPENSSL_SM4
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    /* Test vector: SM4-128, FF1, radix=10 */
    /* Key: 0123456789ABCDEFFEDCBA9876543210 */
    /* Tweak: 39383736353433323130 (hex) */
    /* Plaintext: 1234567890 */
    /* Expected: 3805849473 */
    
    unsigned char key[16];
    int key_len = fpe_hex_to_bytes("0123456789ABCDEFFEDCBA9876543210", key, 16);
    TEST_ASSERT_EQUAL_INT(16, key_len);
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10));
    
    unsigned int plaintext[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int expected[] = {3, 8, 0, 5, 8, 4, 9, 4, 7, 3};
    unsigned int ciphertext[10];
    
    unsigned char tweak[10];
    int tweak_len = fpe_hex_to_bytes("39383736353433323130", tweak, 10);
    TEST_ASSERT_EQUAL_INT(10, tweak_len);
    
    /* Encrypt */
    int ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, tweak_len);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Verify against expected ciphertext */
    TEST_ASSERT_EQUAL_UINT_ARRAY(expected, ciphertext, 10);
    
    /* Test reversibility */
    unsigned int decrypted[10];
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 10, tweak, tweak_len);
    TEST_ASSERT_EQUAL_INT(0, ret);
    TEST_ASSERT_EQUAL_UINT_ARRAY(plaintext, decrypted, 10);
    
    FPE_CTX_free(ctx);
#else
    TEST_IGNORE_MESSAGE("SM4 not supported in this OpenSSL version");
#endif
}

/* Test SM4 with empty tweak */
void test_ff1_sm4_empty_tweak(void) {
#ifdef HAVE_OPENSSL_SM4
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16];
    fpe_hex_to_bytes("0123456789ABCDEFFEDCBA9876543210", key, 16);
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 36));
    
    /* Test vector with radix=36, empty tweak */
    /* Expected: vsxvfxa16cjf2utxvlg */
    const char *alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
    const char *plaintext_str = "0123456789abcdefghi";
    const char *expected_str = "vsxvfxa16cjf2utxvlg";
    
    unsigned int plaintext[19];
    unsigned int expected[19];
    unsigned int ciphertext[19];
    
    TEST_ASSERT_EQUAL_INT(0, fpe_str_to_array(alphabet, plaintext_str, plaintext, 19));
    TEST_ASSERT_EQUAL_INT(0, fpe_str_to_array(alphabet, expected_str, expected, 19));
    
    /* Encrypt with empty tweak */
    int ret = FPE_encrypt(ctx, plaintext, ciphertext, 19, NULL, 0);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Verify */
    TEST_ASSERT_EQUAL_UINT_ARRAY(expected, ciphertext, 19);
    
    FPE_CTX_free(ctx);
#else
    TEST_IGNORE_MESSAGE("SM4 not supported in this OpenSSL version");
#endif
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_sm4_context_init);
    RUN_TEST(test_ff1_sm4_basic);
    RUN_TEST(test_ff1_sm4_test_vector);
    RUN_TEST(test_ff1_sm4_empty_tweak);
    
    return UNITY_END();
}
