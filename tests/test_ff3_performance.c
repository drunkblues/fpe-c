/**
 * @file test_ff3_performance.c
 * @brief FF3 Performance Benchmarks
 * 
 * Measures:
 * - Encryption/decryption time per operation
 * - Throughput (TPS - Transactions Per Second)
 * - AES-128 vs AES-192 vs AES-256 performance
 * - AES vs SM4 performance comparison
 * 
 * Note: FF3 is deprecated by NIST but provided for compatibility.
 */

#include "../include/fpe.h"
#include "../src/utils.h"
#include "unity/src/unity.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

void setUp(void) {}
void tearDown(void) {}

/* Measure encryption/decryption time for a given number of operations */
static double measure_ff3_performance(FPE_ALGO algo, unsigned int key_bits, 
                                       int radix, int iterations) {
    /* Setup */
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = i;
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3, algo, key, key_bits, radix);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Test data - using alphabet string for FF3 */
    char alphabet[27] = "abcdefghijklmnopqrstuvwxyz";
    char plaintext[11] = "helloworld";
    char ciphertext[11], decrypted[11];
    
    unsigned char tweak[8] = {1,2,3,4,5,6,7,8};
    
    /* Warm up */
    FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 8);
    FPE_decrypt_str(ctx, alphabet, ciphertext, decrypted, tweak, 8);
    
    /* Measure */
    clock_t start = clock();
    
    for (int i = 0; i < iterations; i++) {
        FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 8);
        FPE_decrypt_str(ctx, alphabet, ciphertext, decrypted, tweak, 8);
    }
    
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    
    /* Cleanup */
    FPE_CTX_free(ctx);
    
    return elapsed;
}

/* Test FF3 AES-128 performance */
void test_ff3_aes128_performance(void) {
    int iterations = 1000;
    double elapsed = measure_ff3_performance(FPE_ALGO_AES, 128, 26, iterations);
    double ops_per_sec = (iterations * 2) / elapsed;  /* 2 ops per iteration: encrypt + decrypt */
    
    printf("\n  FF3 AES-128: %.2f TPS (%.6f sec for %d ops)\n", 
           ops_per_sec, elapsed, iterations * 2);
    
    TEST_ASSERT_TRUE(elapsed > 0);
    TEST_ASSERT_TRUE(ops_per_sec > 0);
}

/* Test FF3 AES-192 performance */
void test_ff3_aes192_performance(void) {
    int iterations = 1000;
    double elapsed = measure_ff3_performance(FPE_ALGO_AES, 192, 26, iterations);
    double ops_per_sec = (iterations * 2) / elapsed;
    
    printf("\n  FF3 AES-192: %.2f TPS (%.6f sec for %d ops)\n", 
           ops_per_sec, elapsed, iterations * 2);
    
    TEST_ASSERT_TRUE(elapsed > 0);
    TEST_ASSERT_TRUE(ops_per_sec > 0);
}

/* Test FF3 AES-256 performance */
void test_ff3_aes256_performance(void) {
    int iterations = 1000;
    double elapsed = measure_ff3_performance(FPE_ALGO_AES, 256, 26, iterations);
    double ops_per_sec = (iterations * 2) / elapsed;
    
    printf("\n  FF3 AES-256: %.2f TPS (%.6f sec for %d ops)\n", 
           ops_per_sec, elapsed, iterations * 2);
    
    TEST_ASSERT_TRUE(elapsed > 0);
    TEST_ASSERT_TRUE(ops_per_sec > 0);
}

/* Test FF3 SM4 performance */
void test_ff3_sm4_performance(void) {
#ifdef HAVE_OPENSSL_SM4
    int iterations = 1000;
    double elapsed = measure_ff3_performance(FPE_ALGO_SM4, 128, 26, iterations);
    double ops_per_sec = (iterations * 2) / elapsed;
    
    printf("\n  FF3 SM4-128: %.2f TPS (%.6f sec for %d ops)\n", 
           ops_per_sec, elapsed, iterations * 2);
    
    TEST_ASSERT_TRUE(elapsed > 0);
    TEST_ASSERT_TRUE(ops_per_sec > 0);
#else
    TEST_IGNORE_MESSAGE("SM4 not supported");
#endif
}

/* Compare AES key sizes */
void test_ff3_aes_key_size_comparison(void) {
    int iterations = 1000;
    
    double time_128 = measure_ff3_performance(FPE_ALGO_AES, 128, 26, iterations);
    double time_192 = measure_ff3_performance(FPE_ALGO_AES, 192, 26, iterations);
    double time_256 = measure_ff3_performance(FPE_ALGO_AES, 256, 26, iterations);
    
    double tps_128 = (iterations * 2) / time_128;
    double tps_192 = (iterations * 2) / time_192;
    double tps_256 = (iterations * 2) / time_256;
    
    printf("\n  FF3 AES Key Size Comparison:\n");
    printf("    AES-128: %.2f TPS\n", tps_128);
    printf("    AES-192: %.2f TPS\n", tps_192);
    printf("    AES-256: %.2f TPS\n", tps_256);
    
    /* All should have reasonable performance (timing variance is expected) */
    TEST_ASSERT_TRUE(tps_128 > 1000);
    TEST_ASSERT_TRUE(tps_192 > 1000);
    TEST_ASSERT_TRUE(tps_256 > 1000);
}

/* Compare AES vs SM4 */
void test_ff3_aes_vs_sm4_comparison(void) {
#ifdef HAVE_OPENSSL_SM4
    int iterations = 1000;
    
    double time_aes = measure_ff3_performance(FPE_ALGO_AES, 128, 26, iterations);
    double time_sm4 = measure_ff3_performance(FPE_ALGO_SM4, 128, 26, iterations);
    
    double tps_aes = (iterations * 2) / time_aes;
    double tps_sm4 = (iterations * 2) / time_sm4;
    
    printf("\n  FF3 AES vs SM4 Comparison:\n");
    printf("    AES-128: %.2f TPS\n", tps_aes);
    printf("    SM4-128: %.2f TPS\n", tps_sm4);
    printf("    Ratio: %.2fx\n", tps_aes / tps_sm4);
    
    TEST_ASSERT_TRUE(tps_aes > 0);
    TEST_ASSERT_TRUE(tps_sm4 > 0);
#else
    TEST_IGNORE_MESSAGE("SM4 not supported");
#endif
}

int main(void) {
    UNITY_BEGIN();
    
    printf("\n=== FF3 Performance Benchmarks (DEPRECATED) ===\n");
    printf("Note: FF3 is deprecated by NIST. Use FF3-1 for new implementations.\n");
    
    RUN_TEST(test_ff3_aes128_performance);
    RUN_TEST(test_ff3_aes192_performance);
    RUN_TEST(test_ff3_aes256_performance);
    RUN_TEST(test_ff3_sm4_performance);
    RUN_TEST(test_ff3_aes_key_size_comparison);
    RUN_TEST(test_ff3_aes_vs_sm4_comparison);
    
    return UNITY_END();
}
