/**
 * @file benchmark.c
 * @brief FPE Performance Benchmark Example
 * 
 * This example demonstrates how to benchmark FPE operations and measure:
 * - Throughput (TPS - Transactions Per Second)
 * - Latency (microseconds per operation)
 * - Performance comparison across algorithms (FF1, FF3, FF3-1)
 * - Performance comparison across ciphers (AES-128, AES-256, SM4)
 * - Impact of radix and input length on performance
 * 
 * Build:
 *   gcc -I../include benchmark.c -L../build -lfpe -Wl,-rpath,../build -o benchmark
 * 
 * Run:
 *   ./benchmark
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fpe.h"

/* ============================================================================
 * Timing Utilities
 * ============================================================================
 */

typedef struct {
    double elapsed_sec;
    int operations;
    double ops_per_sec;
    double usec_per_op;
} benchmark_result_t;

/**
 * Measure performance of FPE operations
 * 
 * @param mode       FPE mode (FF1, FF3, FF3-1)
 * @param algo       Cipher algorithm (AES, SM4)
 * @param key_bits   Key size in bits
 * @param radix      Radix (base)
 * @param length     Input length
 * @param iterations Number of operations to perform
 * @param result     Output benchmark result
 * @return 0 on success, -1 on error
 */
int benchmark_fpe(FPE_MODE mode, FPE_ALGO algo, int key_bits,
                  int radix, int length, int iterations,
                  benchmark_result_t* result) {
    /* Setup context */
    FPE_CTX* ctx = FPE_CTX_new();
    if (!ctx) return -1;
    
    unsigned char key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = i;
    
    int ret = FPE_CTX_init(ctx, mode, algo, key, key_bits, radix);
    if (ret != 0) {
        FPE_CTX_free(ctx);
        return -1;
    }
    
    /* Prepare test data */
    unsigned int* plaintext = malloc(length * sizeof(unsigned int));
    unsigned int* ciphertext = malloc(length * sizeof(unsigned int));
    unsigned int* decrypted = malloc(length * sizeof(unsigned int));
    
    for (int i = 0; i < length; i++) {
        plaintext[i] = i % radix;
    }
    
    /* Tweak (7 bytes for FF3-1, 8 bytes for others) */
    unsigned char tweak[8] = {1,2,3,4,5,6,7,8};
    int tweak_len = (mode == FPE_MODE_FF3_1) ? 7 : 8;
    
    /* Warm-up */
    FPE_encrypt(ctx, plaintext, ciphertext, length, tweak, tweak_len);
    FPE_decrypt(ctx, ciphertext, decrypted, length, tweak, tweak_len);
    
    /* Benchmark */
    clock_t start = clock();
    
    for (int i = 0; i < iterations; i++) {
        FPE_encrypt(ctx, plaintext, ciphertext, length, tweak, tweak_len);
        FPE_decrypt(ctx, ciphertext, decrypted, length, tweak, tweak_len);
    }
    
    clock_t end = clock();
    
    /* Calculate results */
    result->elapsed_sec = (double)(end - start) / CLOCKS_PER_SEC;
    result->operations = iterations * 2;  /* encrypt + decrypt */
    result->ops_per_sec = result->operations / result->elapsed_sec;
    result->usec_per_op = (result->elapsed_sec * 1000000.0) / result->operations;
    
    /* Cleanup */
    free(plaintext);
    free(ciphertext);
    free(decrypted);
    FPE_CTX_free(ctx);
    
    return 0;
}

/* ============================================================================
 * Example 1: Basic Performance Measurement
 * ============================================================================
 */

void example1_basic_benchmark(void) {
    printf("\n=== Example 1: Basic Performance Measurement ===\n\n");
    
    printf("Benchmarking FF1 with AES-256, radix=10, length=16, 1000 iterations\n\n");
    
    benchmark_result_t result;
    int ret = benchmark_fpe(FPE_MODE_FF1, FPE_ALGO_AES, 256, 
                            10, 16, 1000, &result);
    
    if (ret != 0) {
        printf("❌ Benchmark failed\n");
        return;
    }
    
    printf("Results:\n");
    printf("• Total operations:    %d (encrypt + decrypt pairs)\n", result.operations);
    printf("• Elapsed time:        %.3f seconds\n", result.elapsed_sec);
    printf("• Throughput (TPS):    %.0f operations/second\n", result.ops_per_sec);
    printf("• Latency:             %.2f µs/operation\n", result.usec_per_op);
    
    printf("\n✓ Basic benchmark complete\n");
}

/* ============================================================================
 * Example 2: Compare Algorithms (FF1 vs FF3 vs FF3-1)
 * ============================================================================
 */

void example2_compare_algorithms(void) {
    printf("\n=== Example 2: Algorithm Comparison ===\n\n");
    
    printf("Configuration: AES-256, radix=10, length=16\n");
    printf("%-10s %12s %15s\n", "Algorithm", "TPS", "µs/op");
    printf("%-10s %12s %15s\n", "----------", "------------", "---------------");
    
    /* Test each algorithm */
    struct {
        FPE_MODE mode;
        const char* name;
    } algorithms[] = {
        {FPE_MODE_FF1, "FF1"},
        {FPE_MODE_FF3, "FF3"},
        {FPE_MODE_FF3_1, "FF3-1"}
    };
    
    for (int i = 0; i < 3; i++) {
        benchmark_result_t result;
        int ret = benchmark_fpe(algorithms[i].mode, FPE_ALGO_AES, 256,
                                10, 16, 1000, &result);
        
        if (ret == 0) {
            printf("%-10s %12.0f %15.2f\n", 
                   algorithms[i].name, 
                   result.ops_per_sec, 
                   result.usec_per_op);
        } else {
            printf("%-10s %12s %15s\n", algorithms[i].name, "FAILED", "FAILED");
        }
    }
    
    printf("\nObservations:\n");
    printf("• FF1 typically has best throughput\n");
    printf("• FF3 and FF3-1 have similar performance (both use 8 rounds)\n");
    printf("• FF1 uses adaptive rounds (10 for most inputs)\n");
    
    printf("\n✓ Algorithm comparison complete\n");
}

/* ============================================================================
 * Example 3: Compare Cipher Algorithms (AES vs SM4)
 * ============================================================================
 */

void example3_compare_ciphers(void) {
    printf("\n=== Example 3: Cipher Comparison ===\n\n");
    
    printf("Configuration: FF1, radix=10, length=16\n");
    printf("%-15s %12s %15s\n", "Cipher", "TPS", "µs/op");
    printf("%-15s %12s %15s\n", "---------------", "------------", "---------------");
    
    /* Test AES key sizes */
    struct {
        FPE_ALGO algo;
        int key_bits;
        const char* name;
    } ciphers[] = {
        {FPE_ALGO_AES, 128, "AES-128"},
        {FPE_ALGO_AES, 192, "AES-192"},
        {FPE_ALGO_AES, 256, "AES-256"},
        {FPE_ALGO_SM4, 128, "SM4-128"}
    };
    
    for (int i = 0; i < 4; i++) {
        benchmark_result_t result;
        int ret = benchmark_fpe(FPE_MODE_FF1, ciphers[i].algo, ciphers[i].key_bits,
                                10, 16, 1000, &result);
        
        if (ret == 0) {
            printf("%-15s %12.0f %15.2f\n", 
                   ciphers[i].name, 
                   result.ops_per_sec, 
                   result.usec_per_op);
        } else {
            printf("%-15s %12s %15s\n", ciphers[i].name, "FAILED", "FAILED");
        }
    }
    
    printf("\nObservations:\n");
    printf("• AES-128 typically fastest (fewer rounds)\n");
    printf("• AES-256 slightly slower (more rounds)\n");
    printf("• SM4 performance depends on OpenSSL implementation\n");
    printf("• Performance differences usually < 20%%\n");
    
    printf("\n✓ Cipher comparison complete\n");
}

/* ============================================================================
 * Example 4: Impact of Input Length
 * ============================================================================
 */

void example4_length_impact(void) {
    printf("\n=== Example 4: Input Length Impact ===\n\n");
    
    printf("Configuration: FF1, AES-256, radix=10\n");
    printf("%-10s %12s %15s\n", "Length", "TPS", "µs/op");
    printf("%-10s %12s %15s\n", "----------", "------------", "---------------");
    
    int lengths[] = {6, 10, 16, 20, 32, 50};
    
    for (int i = 0; i < 6; i++) {
        int length = lengths[i];
        
        benchmark_result_t result;
        int ret = benchmark_fpe(FPE_MODE_FF1, FPE_ALGO_AES, 256,
                                10, length, 500, &result);
        
        if (ret == 0) {
            printf("%-10d %12.0f %15.2f\n", 
                   length, 
                   result.ops_per_sec, 
                   result.usec_per_op);
        } else {
            printf("%-10d %12s %15s\n", length, "FAILED", "FAILED");
        }
    }
    
    printf("\nObservations:\n");
    printf("• Longer inputs generally take more time\n");
    printf("• Performance impact varies by algorithm\n");
    printf("• FF1: more rounds for very long inputs\n");
    printf("• FF3/FF3-1: fixed 8 rounds regardless of length\n");
    
    printf("\n✓ Length impact analysis complete\n");
}

/* ============================================================================
 * Example 5: Impact of Radix
 * ============================================================================
 */

void example5_radix_impact(void) {
    printf("\n=== Example 5: Radix Impact ===\n\n");
    
    printf("Configuration: FF1, AES-256, length=16\n");
    printf("%-10s %12s %15s\n", "Radix", "TPS", "µs/op");
    printf("%-10s %12s %15s\n", "----------", "------------", "---------------");
    
    int radixes[] = {2, 10, 16, 36, 62};
    
    for (int i = 0; i < 5; i++) {
        int radix = radixes[i];
        
        benchmark_result_t result;
        int ret = benchmark_fpe(FPE_MODE_FF1, FPE_ALGO_AES, 256,
                                radix, 16, 500, &result);
        
        if (ret == 0) {
            printf("%-10d %12.0f %15.2f\n", 
                   radix, 
                   result.ops_per_sec, 
                   result.usec_per_op);
        } else {
            printf("%-10d %12s %15s\n", radix, "FAILED", "FAILED");
        }
    }
    
    printf("\nObservations:\n");
    printf("• Radix has moderate impact on performance\n");
    printf("• Larger radix requires more computation\n");
    printf("• Binary (radix=2) often fastest\n");
    printf("• Alphanumeric (radix=62) slightly slower\n");
    printf("• Impact typically < 30%% across radix range\n");
    
    printf("\n✓ Radix impact analysis complete\n");
}

/* ============================================================================
 * Example 6: Comprehensive Performance Report
 * ============================================================================
 */

void example6_comprehensive_report(void) {
    printf("\n=== Example 6: Comprehensive Performance Report ===\n\n");
    
    printf("Test Configuration:\n");
    printf("• Input length: 16 digits\n");
    printf("• Radix: 10 (decimal)\n");
    printf("• Iterations: 1000\n");
    printf("• Measurement: encrypt + decrypt pairs\n\n");
    
    printf("%-12s %-15s %12s %15s\n", 
           "Algorithm", "Cipher", "TPS", "µs/op");
    printf("%-12s %-15s %12s %15s\n", 
           "------------", "---------------", "------------", "---------------");
    
    struct {
        FPE_MODE mode;
        FPE_ALGO algo;
        int key_bits;
        const char* mode_name;
        const char* cipher_name;
    } configs[] = {
        {FPE_MODE_FF1, FPE_ALGO_AES, 128, "FF1", "AES-128"},
        {FPE_MODE_FF1, FPE_ALGO_AES, 256, "FF1", "AES-256"},
        {FPE_MODE_FF1, FPE_ALGO_SM4, 128, "FF1", "SM4-128"},
        {FPE_MODE_FF3, FPE_ALGO_AES, 128, "FF3", "AES-128"},
        {FPE_MODE_FF3, FPE_ALGO_AES, 256, "FF3", "AES-256"},
        {FPE_MODE_FF3_1, FPE_ALGO_AES, 128, "FF3-1", "AES-128"},
        {FPE_MODE_FF3_1, FPE_ALGO_AES, 256, "FF3-1", "AES-256"},
        {FPE_MODE_FF3_1, FPE_ALGO_SM4, 128, "FF3-1", "SM4-128"}
    };
    
    for (int i = 0; i < 8; i++) {
        benchmark_result_t result;
        int ret = benchmark_fpe(configs[i].mode, configs[i].algo, 
                                configs[i].key_bits, 10, 16, 1000, &result);
        
        if (ret == 0) {
            printf("%-12s %-15s %12.0f %15.2f\n", 
                   configs[i].mode_name,
                   configs[i].cipher_name,
                   result.ops_per_sec, 
                   result.usec_per_op);
        } else {
            printf("%-12s %-15s %12s %15s\n", 
                   configs[i].mode_name,
                   configs[i].cipher_name,
                   "FAILED", "FAILED");
        }
    }
    
    printf("\nPerformance Summary:\n");
    printf("• FF1: Best overall throughput (typically 80-95K TPS)\n");
    printf("• FF3/FF3-1: Moderate throughput (typically 50-60K TPS)\n");
    printf("• AES-128: Fastest cipher option\n");
    printf("• AES-256: Slightly slower, more secure\n");
    printf("• SM4: Comparable to AES, varies by OpenSSL version\n");
    
    printf("\n✓ Comprehensive report complete\n");
}

/* ============================================================================
 * Best Practices
 * ============================================================================
 */

void print_benchmarking_best_practices(void) {
    printf("\n=== Benchmarking Best Practices ===\n\n");
    
    printf("✓ DO:\n");
    printf("  • Run multiple iterations (1000+) for stable results\n");
    printf("  • Include warm-up phase before measurement\n");
    printf("  • Measure realistic workloads (typical input lengths)\n");
    printf("  • Test on target hardware/OS\n");
    printf("  • Account for encrypt AND decrypt operations\n");
    printf("  • Report both TPS and latency\n");
    printf("  • Compare multiple algorithms/ciphers\n");
    printf("\n");
    
    printf("✗ DON'T:\n");
    printf("  • Benchmark with too few iterations (unstable)\n");
    printf("  • Ignore warm-up (skews first measurements)\n");
    printf("  • Test only encrypt OR decrypt (test both)\n");
    printf("  • Compare different input lengths directly\n");
    printf("  • Run benchmarks on loaded systems\n");
    printf("  • Assume results apply to all configurations\n");
    printf("\n");
    
    printf("Performance Factors:\n");
    printf("  • CPU speed and architecture\n");
    printf("  • OpenSSL version and optimizations\n");
    printf("  • Hardware AES-NI support\n");
    printf("  • Compiler optimizations (-O2, -O3)\n");
    printf("  • System load and background processes\n");
    printf("  • Input length and radix\n");
    printf("\n");
    
    printf("Interpreting Results:\n");
    printf("  • TPS (Throughput):   Higher is better\n");
    printf("  • Latency (µs/op):    Lower is better\n");
    printf("  • Typical FF1 TPS:    80-95K ops/sec (single-threaded)\n");
    printf("  • Typical FF3-1 TPS:  50-60K ops/sec (single-threaded)\n");
    printf("  • Multi-threading:    Can scale near-linearly\n");
    printf("\n");
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int main(void) {
    printf("=== FPE Performance Benchmark ===\n");
    printf("\nThis example demonstrates how to benchmark FPE operations.\n");
    
    /* Run examples */
    example1_basic_benchmark();
    example2_compare_algorithms();
    example3_compare_ciphers();
    example4_length_impact();
    example5_radix_impact();
    example6_comprehensive_report();
    print_benchmarking_best_practices();
    
    printf("\n=== Performance Benchmark Complete ===\n");
    printf("\nKey Takeaways:\n");
    printf("• FF1 typically offers best performance\n");
    printf("• AES-128 is fastest cipher option\n");
    printf("• Input length and radix affect performance\n");
    printf("• Always benchmark on target hardware\n");
    printf("• Multi-threading can significantly improve throughput\n");
    
    return 0;
}
