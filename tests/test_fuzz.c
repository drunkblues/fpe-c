/**
 * @file test_fuzz.c
 * @brief Fuzzing tests for input validation
 *
 * This file contains simple fuzzing-style tests to verify robustness
 * against malformed or edge-case inputs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "unity/src/unity.h"

#include "../include/fpe.h"

/* Unity setup/teardown */
void setUp(void) {
    /* Called before each test */
}

void tearDown(void) {
    /* Called after each test */
}

unsigned int fuzz_rand_range(unsigned int min, unsigned int max) {
    return min + (rand() % (max - min + 1));
}

void fuzz_integer_array(unsigned int *arr, unsigned int len, unsigned int radix, unsigned int invalid_rate) {
    for (unsigned int i = 0; i < len; i++) {
        if ((rand() % 100) < invalid_rate) {
            arr[i] = fuzz_rand_range(0, radix * 2);
        } else {
            arr[i] = fuzz_rand_range(0, radix - 1);
        }
    }
}

void fuzz_buffer(unsigned char *buf, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        buf[i] = (unsigned char)rand();
    }
}

void test_fuzz_null_pointers(void) {
    printf("\n=== Testing NULL pointer inputs ===\n");

    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);

    unsigned char key[16] = {0};
    unsigned int arr[16];
    char str_out[32];
    unsigned char tweak[8] = {0};

    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    TEST_ASSERT_EQUAL(-1, FPE_encrypt(ctx, NULL, arr, 16, tweak, 8));
    printf("✓ FPE_encrypt rejects NULL input\n");

    TEST_ASSERT_EQUAL(-1, FPE_encrypt(ctx, arr, NULL, 16, tweak, 8));
    printf("✓ FPE_encrypt rejects NULL output\n");

    TEST_ASSERT_EQUAL(-1, FPE_decrypt(ctx, NULL, arr, 16, tweak, 8));
    printf("✓ FPE_decrypt rejects NULL input\n");

    TEST_ASSERT_EQUAL(-1, FPE_decrypt(ctx, arr, NULL, 16, tweak, 8));
    printf("✓ FPE_decrypt rejects NULL output\n");

    TEST_ASSERT_EQUAL(-1, FPE_encrypt_str(ctx, NULL, "0123456789", str_out, tweak, 8));
    printf("✓ FPE_encrypt_str rejects NULL alphabet\n");

    TEST_ASSERT_EQUAL(-1, FPE_encrypt_str(ctx, "0123456789", NULL, str_out, tweak, 8));
    printf("✓ FPE_encrypt_str rejects NULL input string\n");

    TEST_ASSERT_EQUAL(-1, FPE_encrypt_str(ctx, "0123456789", "plaintext", NULL, tweak, 8));
    printf("✓ FPE_encrypt_str rejects NULL output string\n");

    FPE_CTX_free(ctx);
}

void test_fuzz_invalid_radix_values(void) {
    printf("\n=== Testing invalid radix values ===\n");
    
    unsigned char key[16] = {0};
    FPE_CTX *ctx;
    
    for (int r = -10; r < 0; r++) {
        ctx = FPE_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);
        TEST_ASSERT_EQUAL(-1, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, r));
        FPE_CTX_free(ctx);
    }
    printf("✓ Rejected %d negative radix values\n", 10);
    
    for (unsigned int r = 0; r < 2; r++) {
        ctx = FPE_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);
        TEST_ASSERT_EQUAL(-1, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, r));
        FPE_CTX_free(ctx);
    }
    printf("✓ Rejected radix values 0 and 1\n");
    
    for (unsigned int r = 65537; r <= 65546; r++) {
        ctx = FPE_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);
        TEST_ASSERT_EQUAL(-1, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, r));
        FPE_CTX_free(ctx);
    }
    printf("✓ Rejected 10 radix values > 65536\n");
}

void test_fuzz_invalid_key_lengths(void) {
    printf("\n=== Testing invalid key lengths ===\n");
    
    unsigned char key[256];
    FPE_CTX *ctx;
    
    for (int bits = 0; bits <= 300; bits += 16) {
        if (bits != 128 && bits != 192 && bits != 256) {
            fuzz_buffer(key, bits / 8);
            ctx = FPE_CTX_new();
            TEST_ASSERT_NOT_NULL(ctx);
            TEST_ASSERT_EQUAL(-1, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, bits, 10));
            FPE_CTX_free(ctx);
        }
    }
    printf("✓ Rejected invalid AES key lengths\n");
    
    for (int bits = 0; bits <= 300; bits += 16) {
        if (bits != 128) {
            fuzz_buffer(key, bits / 8);
            ctx = FPE_CTX_new();
            TEST_ASSERT_NOT_NULL(ctx);
            TEST_ASSERT_EQUAL(-1, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, bits, 10));
            FPE_CTX_free(ctx);
        }
    }
    printf("✓ Rejected invalid SM4 key lengths\n");
}

void test_fuzz_invalid_array_values(void) {
    printf("\n=== Testing invalid integer array values ===\n");
    
    unsigned char key[16] = {0};
    unsigned int plaintext[100];
    unsigned int ciphertext[100];
    unsigned char tweak[8] = {0};
    
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    for (int i = 0; i < 100; i++) {
        fuzz_integer_array(plaintext, 100, 10, 50);
        int ret = FPE_encrypt(ctx, plaintext, ciphertext, 100, tweak, 8);
        if (ret != -1) {
            printf("  Warning: Test %d passed with 50%% invalid values (unexpected)\n", i);
        }
    }
    printf("✓ Tested 100 fuzzed arrays with 50%% invalid values\n");
    
    FPE_CTX_free(ctx);
}

void test_fuzz_invalid_tweak_lengths(void) {
    printf("\n=== Testing invalid tweak lengths ===\n");
    
    unsigned char key[16] = {0};
    unsigned int plaintext[10] = {0};
    unsigned int ciphertext[10];
    unsigned char tweak[100];
    
    FPE_CTX *ctx;
    
    ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    fuzz_buffer(tweak, 100);
    for (unsigned int tlen = 0; tlen <= 100; tlen++) {
        FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, tlen);
    }
    printf("✓ Tested FF1 with 101 different tweak lengths\n");
    
    FPE_CTX_free(ctx);
    
    ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
    
    for (unsigned int tlen = 0; tlen <= 100; tlen++) {
        FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, tlen);
    }
    printf("✓ Tested FF3 with 101 different tweak lengths\n");
    
    FPE_CTX_free(ctx);
}

void test_fuzz_zero_length_inputs(void) {
    printf("\n=== Testing zero and minimal length inputs ===\n");

    unsigned char key[16] = {0};
    unsigned int arr[10];
    unsigned int out[10];
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    TEST_ASSERT_EQUAL(-1, FPE_encrypt(ctx, arr, out, 0, tweak, 8));
    printf("✓ FF1 rejects zero-length input\n");

    TEST_ASSERT_EQUAL(-1, FPE_encrypt(ctx, arr, out, 1, tweak, 8));
    printf("✓ FF1 rejects length 1 (below minimum)\n");

    /* FF1 allows length 2 with radix=10 (per NIST spec) */
    TEST_ASSERT_EQUAL(0, FPE_encrypt(ctx, arr, out, 2, tweak, 8));
    printf("✓ FF1 accepts length 2 (valid minimum)\n");

    FPE_CTX_free(ctx);

    ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);

    TEST_ASSERT_EQUAL(-1, FPE_encrypt(ctx, arr, out, 0, tweak, 8));
    printf("✓ FF3 rejects zero-length input\n");

    TEST_ASSERT_EQUAL(-1, FPE_encrypt(ctx, arr, out, 1, tweak, 8));
    printf("✓ FF3 rejects length 1 (below minimum)\n");

    /* FF3 minimum length is 2 (per implementation: len < 2 || len > 256) */
    TEST_ASSERT_EQUAL(0, FPE_encrypt(ctx, arr, out, 2, tweak, 8));
    printf("✓ FF3 accepts length 2 (valid minimum)\n");

    FPE_CTX_free(ctx);

    ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);

    TEST_ASSERT_EQUAL(-1, FPE_encrypt(ctx, arr, out, 0, tweak, 8));
    printf("✓ FF3-1 rejects zero-length input\n");

    TEST_ASSERT_EQUAL(-1, FPE_encrypt(ctx, arr, out, 1, tweak, 8));
    printf("✓ FF3-1 rejects length 1 (below minimum)\n");

    /* FF3-1 minimum length is also 2 (same as FF3) */
    TEST_ASSERT_EQUAL(0, FPE_encrypt(ctx, arr, out, 2, tweak, 8));
    printf("✓ FF3-1 accepts length 2 (valid minimum)\n");

    FPE_CTX_free(ctx);
}

void test_fuzz_invalid_alphabets(void) {
    printf("\n=== Testing invalid alphabets ===\n");
    
    unsigned char key[16] = {0};
    char plaintext[100];
    char ciphertext[100];
    unsigned char tweak[8] = {0};
    
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    TEST_ASSERT_EQUAL(-1, FPE_encrypt_str(ctx, NULL, "1234567890", ciphertext, tweak, 8));
    printf("✓ FPE_encrypt_str rejects NULL alphabet\n");
    
    TEST_ASSERT_EQUAL(-1, FPE_encrypt_str(ctx, "", "1234567890", ciphertext, tweak, 8));
    printf("✓ FPE_encrypt_str rejects empty alphabet\n");
    
    TEST_ASSERT_EQUAL(-1, FPE_encrypt_str(ctx, "01234556789", "1234567890", ciphertext, tweak, 8));
    printf("✓ FPE_encrypt_str rejects alphabet with duplicate '5'\n");
    
    TEST_ASSERT_EQUAL(-1, FPE_encrypt_str(ctx, "ABC", "XYZ", ciphertext, tweak, 8));
    printf("✓ FPE_encrypt_str rejects input 'XYZ' with alphabet 'ABC'\n");
    
    FPE_CTX_free(ctx);
}

void test_fuzz_context_reuse(void) {
    printf("\n=== Testing context reuse after errors ===\n");
    
    unsigned char key[16] = {0};
    unsigned int plaintext[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    unsigned int ciphertext[10];
    unsigned char tweak[8] = {0};
    
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    TEST_ASSERT_EQUAL(-1, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 64, 10));
    printf("✓ First initialization with invalid key length failed\n");
    
    TEST_ASSERT_EQUAL(0, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10));
    printf("✓ Re-initialization with valid parameters succeeded\n");
    
    TEST_ASSERT_EQUAL(0, FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8));
    printf("✓ Encryption successful after re-initialization\n");
    
    FPE_CTX_free(ctx);
}

void test_fuzz_boundary_values(void) {
    printf("\n=== Testing boundary values ===\n");

    unsigned char key[16] = {0};
    unsigned int plaintext[100];
    unsigned int ciphertext[100];
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 2);

    for (unsigned int i = 0; i < 100; i++) {
        plaintext[i] = i % 2;
    }
    TEST_ASSERT_EQUAL(0, FPE_encrypt(ctx, plaintext, ciphertext, 100, tweak, 8));
    printf("✓ Successfully encrypted 100 digits with radix=2\n");

    FPE_CTX_free(ctx);

    ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 65536);

    for (unsigned int i = 0; i < 100; i++) {
        plaintext[i] = rand() % 65536;
    }
    TEST_ASSERT_EQUAL(0, FPE_encrypt(ctx, plaintext, ciphertext, 100, tweak, 8));
    printf("✓ Successfully encrypted 100 values with radix=65536\n");

    FPE_CTX_free(ctx);

    /* Test with larger tweak size for FF1 (64 bytes) */
    ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    unsigned char large_tweak[64];
    memset(large_tweak, 0xAA, 64);
    TEST_ASSERT_EQUAL(0, FPE_encrypt(ctx, plaintext, ciphertext, 10, large_tweak, 64));
    printf("✓ Successfully encrypted with 64-byte tweak\n");

    FPE_CTX_free(ctx);

    /* Test with maximum input length for FF3/FF3-1 */
    ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);

    /* FF3/FF3-1 maximum tweak is 8 bytes */
    unsigned char small_tweak[8];
    TEST_ASSERT_EQUAL(0, FPE_encrypt(ctx, plaintext, ciphertext, 10, small_tweak, 8));
    printf("✓ Successfully encrypted with 8-byte tweak (FF3/FF3-1 maximum)\n");

    FPE_CTX_free(ctx);
}

int main(void) {
    srand(42);
    
    UNITY_BEGIN();
    
    RUN_TEST(test_fuzz_null_pointers);
    RUN_TEST(test_fuzz_invalid_radix_values);
    RUN_TEST(test_fuzz_invalid_key_lengths);
    RUN_TEST(test_fuzz_invalid_array_values);
    RUN_TEST(test_fuzz_invalid_tweak_lengths);
    RUN_TEST(test_fuzz_zero_length_inputs);
    RUN_TEST(test_fuzz_invalid_alphabets);
    RUN_TEST(test_fuzz_context_reuse);
    RUN_TEST(test_fuzz_boundary_values);
    
    return UNITY_END();
}
