/**
 * @file test_openssl_version.c
 * @brief Tests for OpenSSL version detection and SM4 availability
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unity/src/unity.h"

#include "../include/fpe.h"

/* Unity setup/teardown */
void setUp(void) {
    /* Called before each test */
}

void tearDown(void) {
    /* Called after each test */
}

#if defined(HAVE_OPENSSL_SM4) || defined(HAVE_OPENSSL_SM4_EXPERIMENTAL)
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#endif

void test_openssl_version_detection(void) {
    printf("\n=== OpenSSL Version Detection Tests ===\n");
    
#if defined(HAVE_OPENSSL_SM4)
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    printf("HAVE_OPENSSL_SM4 defined: YES\n");
    printf("SM4 support should be available (OpenSSL 3.0+)\n");
#elif defined(HAVE_OPENSSL_SM4_EXPERIMENTAL)
    printf("OpenSSL version: %s\n", OPENSSL_VERSION_TEXT);
    printf("HAVE_OPENSSL_SM4_EXPERIMENTAL defined: YES\n");
    printf("SM4 support should be available (OpenSSL 1.1.1+)\n");
#else
    printf("HAVE_OPENSSL_SM4 not defined\n");
    printf("SM4 support should NOT be available (OpenSSL < 1.1.1)\n");
#endif
    
    printf("\n");
}

#if defined(HAVE_OPENSSL_SM4_EXPERIMENTAL) && !defined(HAVE_OPENSSL_SM4)
void test_sm4_availability_with_openssl_1_1_1(void) {
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int plaintext[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
    unsigned int ciphertext[16];
    unsigned char tweak[8] = {0};
    
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10);
    if (ret == 0) {
        printf("✓ SM4 is available (OpenSSL 1.1.1+)\n");
        
        ret = FPE_encrypt(ctx, plaintext, ciphertext, 16, tweak, 8);
        TEST_ASSERT_EQUAL(0, ret);
        printf("✓ SM4 encryption successful\n");
        
        ret = FPE_decrypt(ctx, ciphertext, plaintext, 16, tweak, 8);
        TEST_ASSERT_EQUAL(0, ret);
        printf("✓ SM4 decryption successful\n");
    } else {
        printf("✗ SM4 not available (unexpected)\n");
        TEST_FAIL();
    }
    
    FPE_CTX_free(ctx);
}
#endif

#if !defined(HAVE_OPENSSL_SM4) && !defined(HAVE_OPENSSL_SM4_EXPERIMENTAL)
void test_sm4_unavailability_with_old_openssl(void) {
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10);
    TEST_ASSERT_EQUAL(-1, ret);
    printf("✓ SM4 correctly unavailable (OpenSSL < 1.1.1)\n");
    
    FPE_CTX_free(ctx);
}
#endif

#if defined(HAVE_OPENSSL_SM4)
void test_sm4_availability_with_openssl_3_0(void) {
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int plaintext[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
    unsigned int ciphertext[16];
    unsigned char tweak[8] = {0};
    
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10);
    TEST_ASSERT_EQUAL(0, ret);
    printf("✓ SM4 is available (OpenSSL 3.0+)\n");
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext, 16, tweak, 8);
    TEST_ASSERT_EQUAL(0, ret);
    printf("✓ SM4 encryption successful\n");
    
    ret = FPE_decrypt(ctx, ciphertext, plaintext, 16, tweak, 8);
    TEST_ASSERT_EQUAL(0, ret);
    printf("✓ SM4 decryption successful\n");
    
    FPE_CTX_free(ctx);
}
#endif

#if !defined(HAVE_OPENSSL_SM4) && !defined(HAVE_OPENSSL_SM4_EXPERIMENTAL)
void test_sm4_error_handling_unavailable(void) {
    unsigned char key[16] = {0};
    
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    printf("\n=== Testing SM4 error handling when unavailable ===\n");
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10);
    TEST_ASSERT_EQUAL(-1, ret);
    printf("✓ FPE_CTX_init correctly fails for SM4 when unavailable\n");
    
    FPE_CTX_free(ctx);
    
    ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned int plaintext[] = {1, 2, 3, 4};
    unsigned int ciphertext[4];
    unsigned char tweak[8] = {0};
    
    ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL(0, ret);
    
    printf("✓ AES mode initializes correctly even when SM4 unavailable\n");
    
    FPE_CTX_free(ctx);
}
#endif

#if defined(HAVE_OPENSSL_SM4)
void test_sm4_all_modes_with_3_0(void) {
    printf("\n=== Testing all FPE modes with SM4 (OpenSSL 3.0+) ===\n");
    
    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int plaintext[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
    unsigned int ciphertext[16];
    unsigned char tweak[8] = {0};
    
    FPE_MODE modes[] = {FPE_MODE_FF1, FPE_MODE_FF3, FPE_MODE_FF3_1};
    const char *mode_names[] = {"FF1", "FF3", "FF3-1"};
    
    for (int i = 0; i < 3; i++) {
        FPE_CTX *ctx = FPE_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);
        
        int ret = FPE_CTX_init(ctx, modes[i], FPE_ALGO_SM4, key, 128, 10);
        TEST_ASSERT_EQUAL(0, ret);
        printf("✓ %s with SM4 initialized (OpenSSL 3.0+)\n", mode_names[i]);
        
        ret = FPE_encrypt(ctx, plaintext, ciphertext, 16, tweak, 8);
        TEST_ASSERT_EQUAL(0, ret);
        printf("✓ %s SM4 encryption successful\n", mode_names[i]);
        
        ret = FPE_decrypt(ctx, ciphertext, plaintext, 16, tweak, 8);
        TEST_ASSERT_EQUAL(0, ret);
        printf("✓ %s SM4 decryption successful\n", mode_names[i]);
        
        FPE_CTX_free(ctx);
    }
}
#endif

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_openssl_version_detection);
    
#if defined(HAVE_OPENSSL_SM4_EXPERIMENTAL) && !defined(HAVE_OPENSSL_SM4)
    RUN_TEST(test_sm4_availability_with_openssl_1_1_1);
#endif
    
#if !defined(HAVE_OPENSSL_SM4) && !defined(HAVE_OPENSSL_SM4_EXPERIMENTAL)
    RUN_TEST(test_sm4_unavailability_with_old_openssl);
    RUN_TEST(test_sm4_error_handling_unavailable);
#endif
    
#if defined(HAVE_OPENSSL_SM4)
    RUN_TEST(test_sm4_availability_with_openssl_3_0);
    RUN_TEST(test_sm4_all_modes_with_3_0);
#endif
    
    return UNITY_END();
}
