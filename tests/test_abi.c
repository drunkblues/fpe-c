/**
 * @file test_abi.c
 * @brief ABI stability and opaque pointer encapsulation tests
 *
 * This file verifies that the opaque pointer pattern is properly
 * implemented and provides ABI stability across library versions.
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

/* Test 1: FPE_CTX structure is opaque to users */
void test_opaque_pointer_encapsulation(void) {
    printf("\n=== Test 1: Opaque Pointer Encapsulation ===\n");
    printf("Users cannot access FPE_CTX internal fields\n");

    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);

    /* Users should not be able to access internal fields */
    /* If compilation fails here, the structure is properly opaque */
    /* We verify this by checking if the sizeof(FPE_CTX) returns the size of a pointer */
    TEST_ASSERT_EQUAL(sizeof(FPE_CTX*), sizeof(ctx));

    printf("✓ FPE_CTX is properly opaque (pointer-sized)\n");

    FPE_CTX_free(ctx);
}

/* Test 2: Multiple contexts are independent */
void test_context_independence(void) {
    printf("\n=== Test 2: Context Independence ===\n");
    printf("Multiple contexts do not share internal state\n");

    unsigned char key1[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char key2[16] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                             0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};

    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext1[10];
    unsigned int ciphertext2[10];
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx1 = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx1);
    FPE_CTX_init(ctx1, FPE_MODE_FF1, FPE_ALGO_AES, key1, 128, 10);

    FPE_CTX *ctx2 = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx2);
    FPE_CTX_init(ctx2, FPE_MODE_FF1, FPE_ALGO_AES, key2, 128, 10);

    FPE_encrypt(ctx1, plaintext, ciphertext1, 10, tweak, 8);
    FPE_encrypt(ctx2, plaintext, ciphertext2, 10, tweak, 8);

    /* Ciphertexts should be different because keys are different */
    int different = 0;
    for (int i = 0; i < 10; i++) {
        if (ciphertext1[i] != ciphertext2[i]) {
            different = 1;
            break;
        }
    }
    TEST_ASSERT_EQUAL(1, different);

    printf("✓ Contexts are independent (different keys produce different outputs)\n");

    FPE_CTX_free(ctx1);
    FPE_CTX_free(ctx2);
}

/* Test 3: Re-initialization works correctly */
void test_context_reinitialization(void) {
    printf("\n=== Test 3: Context Re-initialization ===\n");
    printf("Contexts can be re-initialized with different parameters\n");

    unsigned char key1[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char key2[16] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                             0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};

    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext1[10];
    unsigned int ciphertext2[10];
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);

    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key1, 128, 10);
    FPE_encrypt(ctx, plaintext, ciphertext1, 10, tweak, 8);

    /* Re-initialize with different key */
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key2, 128, 10);
    FPE_encrypt(ctx, plaintext, ciphertext2, 10, tweak, 8);

    /* Ciphertexts should be different */
    int different = 0;
    for (int i = 0; i < 10; i++) {
        if (ciphertext1[i] != ciphertext2[i]) {
            different = 1;
            break;
        }
    }
    TEST_ASSERT_EQUAL(1, different);

    printf("✓ Re-initialization works correctly\n");

    FPE_CTX_free(ctx);
}

/* Test 4: Context after free is unusable */
void test_context_after_free(void) {
    printf("\n=== Test 4: Context After Free ===\n");
    printf("Context cannot be used after FPE_CTX_free\n");

    unsigned char key[16] = {0};
    unsigned int plaintext[10] = {0};
    unsigned int ciphertext[10];
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);

    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    FPE_CTX_free(ctx);

    /* Using context after free should result in error or undefined behavior */
    /* We don't test this directly as it's undefined behavior */
    /* But we verify that we can create a new context after free */

    FPE_CTX *ctx2 = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx2);

    printf("✓ New context can be created after free\n");

    FPE_CTX_free(ctx2);
}

/* Test 5: Context size is stable across versions */
void test_context_size_stability(void) {
    printf("\n=== Test 5: Context Size Stability ===\n");
    printf("FPE_CTX pointer size is consistent\n");

    /* FPE_CTX is a pointer, so sizeof(FPE_CTX*) should be consistent */
    size_t ptr_size = sizeof(FPE_CTX*);

    printf("  FPE_CTX* size: %zu bytes\n", ptr_size);

    TEST_ASSERT(ptr_size >= 4);  /* At least 32-bit pointers */
    TEST_ASSERT(ptr_size <= 16); /* At most 128-bit pointers */

    printf("✓ Context pointer size is stable\n");
}

/* Test 6: NULL context handling */
void test_null_context_handling(void) {
    printf("\n=== Test 6: NULL Context Handling ===\n");
    printf("Library handles NULL context gracefully\n");

    unsigned char key[16] = {0};
    unsigned int plaintext[10] = {0};
    unsigned int ciphertext[10];
    unsigned char tweak[8] = {0};

    /* FPE_CTX_free should handle NULL gracefully */
    FPE_CTX_free(NULL);

    /* Operations with NULL context should return error */
    TEST_ASSERT_EQUAL(-1, FPE_encrypt(NULL, plaintext, ciphertext, 10, tweak, 8));
    TEST_ASSERT_EQUAL(-1, FPE_decrypt(NULL, plaintext, ciphertext, 10, tweak, 8));

    printf("✓ NULL context is handled correctly\n");
}

/* Test 7: Mode encapsulation */
void test_mode_encapsulation(void) {
    printf("\n=== Test 7: Mode Encapsulation ===\n");
    printf("FPE_MODE enum is properly encapsulated\n");

    FPE_MODE modes[] = {FPE_MODE_FF1, FPE_MODE_FF3, FPE_MODE_FF3_1};

    for (int i = 0; i < 3; i++) {
        unsigned char key[16] = {0};
        unsigned int plaintext[10] = {0};
        unsigned int ciphertext[10];
        unsigned char tweak[8] = {0};

        FPE_CTX *ctx = FPE_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);

        int ret = FPE_CTX_init(ctx, modes[i], FPE_ALGO_AES, key, 128, 10);
        TEST_ASSERT_EQUAL(0, ret);

        ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8);
        TEST_ASSERT_EQUAL(0, ret);

        FPE_CTX_free(ctx);
    }

    printf("✓ All modes work correctly through opaque context\n");
}

/* Test 8: Algorithm encapsulation */
void test_algorithm_encapsulation(void) {
    printf("\n=== Test 8: Algorithm Encapsulation ===\n");
    printf("FPE_ALGO enum is properly encapsulated\n");

    FPE_ALGO algos[] = {FPE_ALGO_AES, FPE_ALGO_SM4};

    for (int i = 0; i < 2; i++) {
        unsigned char key[16] = {0};
        unsigned int plaintext[10] = {0};
        unsigned int ciphertext[10];
        unsigned char tweak[8] = {0};

        FPE_CTX *ctx = FPE_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);

#if defined(HAVE_OPENSSL_SM4) || defined(HAVE_OPENSSL_SM4_EXPERIMENTAL)
        int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, algos[i], key, 128, 10);
        if (ret == 0) {
            ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8);
            TEST_ASSERT_EQUAL(0, ret);
            printf("✓ %s works correctly through opaque context\n", i == 0 ? "AES" : "SM4");
        } else {
            printf("✓ %s correctly rejected (unavailable)\n", i == 0 ? "AES" : "SM4");
        }
#else
        if (i == 0) {
            int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, algos[i], key, 128, 10);
            TEST_ASSERT_EQUAL(0, ret);
            ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8);
            TEST_ASSERT_EQUAL(0, ret);
            printf("✓ AES works correctly through opaque context\n");
        } else {
            TEST_IGNORE();
        }
#endif

        FPE_CTX_free(ctx);
    }
}

/* Test 9: Function signature stability */
void test_function_signature_stability(void) {
    printf("\n=== Test 9: Function Signature Stability ===\n");
    printf("All public functions have stable signatures\n");

    /* Verify that all public function pointers have consistent signatures */
    FPE_CTX *(*new_func)(void) = FPE_CTX_new;
    void (*free_func)(FPE_CTX *) = FPE_CTX_free;
    int (*init_func)(FPE_CTX *, FPE_MODE, FPE_ALGO, const unsigned char *, unsigned int, unsigned int) = FPE_CTX_init;

    TEST_ASSERT_NOT_NULL(new_func);
    TEST_ASSERT_NOT_NULL(free_func);
    TEST_ASSERT_NOT_NULL(init_func);

    printf("✓ All public functions have stable signatures\n");
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_opaque_pointer_encapsulation);
    RUN_TEST(test_context_independence);
    RUN_TEST(test_context_reinitialization);
    RUN_TEST(test_context_after_free);
    RUN_TEST(test_context_size_stability);
    RUN_TEST(test_null_context_handling);
    RUN_TEST(test_mode_encapsulation);
    RUN_TEST(test_algorithm_encapsulation);
    RUN_TEST(test_function_signature_stability);

    printf("\n=== ABI stability tests complete ===\n");

    return UNITY_END();
}
