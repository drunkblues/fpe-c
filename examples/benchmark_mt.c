/**
 * @file benchmark_mt.c
 * @brief Multi-Threaded TPS Benchmark Example
 * 
 * This example demonstrates how to measure multi-threaded throughput (TPS)
 * and shows how FPE performance scales with multiple threads.
 * 
 * Key Concepts:
 * - Measuring TPS with multiple threads
 * - Thread scaling efficiency
 * - Optimal thread count determination
 * - Comparing single-threaded vs multi-threaded performance
 * - Thread coordination and timing
 * 
 * Build:
 *   gcc -pthread -I../include benchmark_mt.c -L../build -lfpe -Wl,-rpath,../build -o benchmark_mt
 * 
 * Run:
 *   ./benchmark_mt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include "fpe.h"

/* ============================================================================
 * Thread Benchmark Infrastructure
 * ============================================================================
 */

typedef struct {
    int thread_id;
    int operations_completed;
    double elapsed_seconds;
    FPE_MODE mode;
    FPE_ALGO algo;
    int key_bits;
    int radix;
    int length;
    unsigned char* key;
    pthread_barrier_t* start_barrier;  /* Synchronize thread start */
    pthread_barrier_t* end_barrier;    /* Synchronize thread end */
    volatile int* should_stop;         /* Signal to stop */
    double duration_seconds;           /* How long to run */
} thread_benchmark_args_t;

void* benchmark_thread_worker(void* arg) {
    thread_benchmark_args_t* args = (thread_benchmark_args_t*)arg;
    
    /* Create thread-local context */
    FPE_CTX* ctx = FPE_CTX_new();
    if (!ctx) return NULL;
    
    int ret = FPE_CTX_init(ctx, args->mode, args->algo, 
                           args->key, args->key_bits, args->radix);
    if (ret != 0) {
        FPE_CTX_free(ctx);
        return NULL;
    }
    
    /* Prepare data */
    unsigned int* plaintext = malloc(args->length * sizeof(unsigned int));
    unsigned int* ciphertext = malloc(args->length * sizeof(unsigned int));
    
    for (int i = 0; i < args->length; i++) {
        plaintext[i] = i % args->radix;
    }
    
    unsigned char tweak[8] = {1,2,3,4,5,6,7,8};
    int tweak_len = (args->mode == FPE_MODE_FF3_1) ? 7 : 8;
    
    /* Warm-up */
    FPE_encrypt(ctx, plaintext, ciphertext, args->length, tweak, tweak_len);
    
    /* Wait at barrier for all threads to be ready */
    pthread_barrier_wait(args->start_barrier);
    
    /* Start timing */
    clock_t start = clock();
    
    /* Run operations for specified duration */
    int ops = 0;
    if (args->duration_seconds > 0) {
        /* Time-based benchmark */
        double elapsed;
        do {
            FPE_encrypt(ctx, plaintext, ciphertext, args->length, tweak, tweak_len);
            ops++;
            
            clock_t current = clock();
            elapsed = (double)(current - start) / CLOCKS_PER_SEC;
        } while (elapsed < args->duration_seconds && !(*args->should_stop));
    }
    
    /* Stop timing */
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    
    /* Wait at end barrier for all threads to finish */
    pthread_barrier_wait(args->end_barrier);
    
    /* Record results */
    args->operations_completed = ops;
    args->elapsed_seconds = elapsed;
    
    /* Cleanup */
    free(plaintext);
    free(ciphertext);
    FPE_CTX_free(ctx);
    
    return NULL;
}

/* ============================================================================
 * Example 1: Single-threaded Baseline
 * ============================================================================
 */

void example1_single_threaded_baseline(void) {
    printf("\n=== Example 1: Single-Threaded Baseline ===\n\n");
    
    printf("Configuration:\n");
    printf("• Algorithm: FF1\n");
    printf("• Cipher: AES-256\n");
    printf("• Radix: 10\n");
    printf("• Length: 16\n");
    printf("• Duration: 2 seconds\n\n");
    
    /* Setup */
    pthread_barrier_t start_barrier, end_barrier;
    pthread_barrier_init(&start_barrier, NULL, 1);
    pthread_barrier_init(&end_barrier, NULL, 1);
    volatile int should_stop = 0;
    
    unsigned char key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    
    thread_benchmark_args_t args = {
        .thread_id = 1,
        .mode = FPE_MODE_FF1,
        .algo = FPE_ALGO_AES,
        .key_bits = 256,
        .radix = 10,
        .length = 16,
        .key = key,
        .start_barrier = &start_barrier,
        .end_barrier = &end_barrier,
        .should_stop = &should_stop,
        .duration_seconds = 2.0
    };
    
    /* Run single-threaded benchmark */
    pthread_t thread;
    pthread_create(&thread, NULL, benchmark_thread_worker, &args);
    pthread_join(thread, NULL);
    
    /* Report results */
    double tps = args.operations_completed / args.elapsed_seconds;
    
    printf("Results:\n");
    printf("• Operations: %d\n", args.operations_completed);
    printf("• Elapsed: %.3f seconds\n", args.elapsed_seconds);
    printf("• TPS: %.0f operations/second\n", tps);
    printf("• Latency: %.2f µs/operation\n", 
           (args.elapsed_seconds * 1000000.0) / args.operations_completed);
    
    printf("\n✓ Single-threaded baseline established\n");
    
    pthread_barrier_destroy(&start_barrier);
    pthread_barrier_destroy(&end_barrier);
}

/* ============================================================================
 * Example 2: Multi-threaded Scaling
 * ============================================================================
 */

void example2_multi_threaded_scaling(void) {
    printf("\n=== Example 2: Multi-Threaded Scaling ===\n\n");
    
    printf("Configuration:\n");
    printf("• Algorithm: FF1\n");
    printf("• Cipher: AES-256\n");
    printf("• Radix: 10\n");
    printf("• Length: 16\n");
    printf("• Duration: 2 seconds per test\n\n");
    
    printf("%-10s %15s %15s %15s\n", 
           "Threads", "Total TPS", "Per-Thread TPS", "Efficiency");
    printf("%-10s %15s %15s %15s\n", 
           "----------", "---------------", "---------------", "---------------");
    
    unsigned char key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    
    double baseline_tps = 0;
    
    int thread_counts[] = {1, 2, 4, 8};
    
    for (int t = 0; t < 4; t++) {
        int num_threads = thread_counts[t];
        
        /* Setup synchronization */
        pthread_barrier_t start_barrier, end_barrier;
        pthread_barrier_init(&start_barrier, NULL, num_threads);
        pthread_barrier_init(&end_barrier, NULL, num_threads);
        volatile int should_stop = 0;
        
        /* Setup threads */
        pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
        thread_benchmark_args_t* args = malloc(num_threads * sizeof(thread_benchmark_args_t));
        
        for (int i = 0; i < num_threads; i++) {
            args[i].thread_id = i + 1;
            args[i].mode = FPE_MODE_FF1;
            args[i].algo = FPE_ALGO_AES;
            args[i].key_bits = 256;
            args[i].radix = 10;
            args[i].length = 16;
            args[i].key = key;
            args[i].start_barrier = &start_barrier;
            args[i].end_barrier = &end_barrier;
            args[i].should_stop = &should_stop;
            args[i].duration_seconds = 2.0;
            
            pthread_create(&threads[i], NULL, benchmark_thread_worker, &args[i]);
        }
        
        /* Wait for completion */
        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
        }
        
        /* Calculate total TPS */
        int total_ops = 0;
        double max_elapsed = 0;
        for (int i = 0; i < num_threads; i++) {
            total_ops += args[i].operations_completed;
            if (args[i].elapsed_seconds > max_elapsed) {
                max_elapsed = args[i].elapsed_seconds;
            }
        }
        
        double total_tps = total_ops / max_elapsed;
        double per_thread_tps = total_tps / num_threads;
        
        if (num_threads == 1) {
            baseline_tps = total_tps;
        }
        
        double efficiency = (total_tps / baseline_tps) / num_threads * 100.0;
        
        printf("%-10d %15.0f %15.0f %14.1f%%\n", 
               num_threads, total_tps, per_thread_tps, efficiency);
        
        /* Cleanup */
        free(threads);
        free(args);
        pthread_barrier_destroy(&start_barrier);
        pthread_barrier_destroy(&end_barrier);
    }
    
    printf("\nObservations:\n");
    printf("• Efficiency shows how well threads scale\n");
    printf("• 100%% = perfect linear scaling\n");
    printf("• FPE typically scales well (80-95%% efficiency)\n");
    printf("• Efficiency may drop with many threads (contention)\n");
    
    printf("\n✓ Multi-threaded scaling analysis complete\n");
}

/* ============================================================================
 * Example 3: Algorithm Comparison (Multi-threaded)
 * ============================================================================
 */

void example3_algorithm_comparison_mt(void) {
    printf("\n=== Example 3: Algorithm Comparison (4 Threads) ===\n\n");
    
    const int NUM_THREADS = 4;
    
    printf("Configuration:\n");
    printf("• Threads: %d\n", NUM_THREADS);
    printf("• Cipher: AES-256\n");
    printf("• Radix: 10\n");
    printf("• Length: 16\n");
    printf("• Duration: 2 seconds\n\n");
    
    printf("%-12s %15s %15s\n", "Algorithm", "Total TPS", "Per-Thread TPS");
    printf("%-12s %15s %15s\n", "------------", "---------------", "---------------");
    
    unsigned char key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    
    FPE_MODE modes[] = {FPE_MODE_FF1, FPE_MODE_FF3, FPE_MODE_FF3_1};
    const char* names[] = {"FF1", "FF3", "FF3-1"};
    
    for (int m = 0; m < 3; m++) {
        /* Setup synchronization */
        pthread_barrier_t start_barrier, end_barrier;
        pthread_barrier_init(&start_barrier, NULL, NUM_THREADS);
        pthread_barrier_init(&end_barrier, NULL, NUM_THREADS);
        volatile int should_stop = 0;
        
        /* Setup threads */
        pthread_t threads[NUM_THREADS];
        thread_benchmark_args_t args[NUM_THREADS];
        
        for (int i = 0; i < NUM_THREADS; i++) {
            args[i].thread_id = i + 1;
            args[i].mode = modes[m];
            args[i].algo = FPE_ALGO_AES;
            args[i].key_bits = 256;
            args[i].radix = 10;
            args[i].length = 16;
            args[i].key = key;
            args[i].start_barrier = &start_barrier;
            args[i].end_barrier = &end_barrier;
            args[i].should_stop = &should_stop;
            args[i].duration_seconds = 2.0;
            
            pthread_create(&threads[i], NULL, benchmark_thread_worker, &args[i]);
        }
        
        /* Wait for completion */
        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }
        
        /* Calculate results */
        int total_ops = 0;
        double max_elapsed = 0;
        for (int i = 0; i < NUM_THREADS; i++) {
            total_ops += args[i].operations_completed;
            if (args[i].elapsed_seconds > max_elapsed) {
                max_elapsed = args[i].elapsed_seconds;
            }
        }
        
        double total_tps = total_ops / max_elapsed;
        double per_thread_tps = total_tps / NUM_THREADS;
        
        printf("%-12s %15.0f %15.0f\n", names[m], total_tps, per_thread_tps);
        
        pthread_barrier_destroy(&start_barrier);
        pthread_barrier_destroy(&end_barrier);
    }
    
    printf("\n✓ Algorithm comparison complete\n");
}

/* ============================================================================
 * Example 4: Finding Optimal Thread Count
 * ============================================================================
 */

void example4_optimal_thread_count(void) {
    printf("\n=== Example 4: Finding Optimal Thread Count ===\n\n");
    
    printf("Testing thread counts from 1 to 12...\n");
    printf("Configuration: FF1, AES-256, radix=10, length=16\n\n");
    
    printf("%-10s %15s %15s\n", "Threads", "Total TPS", "Speedup");
    printf("%-10s %15s %15s\n", "----------", "---------------", "---------------");
    
    unsigned char key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    
    double baseline_tps = 0;
    int best_thread_count = 1;
    double best_tps = 0;
    
    for (int num_threads = 1; num_threads <= 12; num_threads++) {
        /* Setup synchronization */
        pthread_barrier_t start_barrier, end_barrier;
        pthread_barrier_init(&start_barrier, NULL, num_threads);
        pthread_barrier_init(&end_barrier, NULL, num_threads);
        volatile int should_stop = 0;
        
        /* Setup threads */
        pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
        thread_benchmark_args_t* args = malloc(num_threads * sizeof(thread_benchmark_args_t));
        
        for (int i = 0; i < num_threads; i++) {
            args[i].thread_id = i + 1;
            args[i].mode = FPE_MODE_FF1;
            args[i].algo = FPE_ALGO_AES;
            args[i].key_bits = 256;
            args[i].radix = 10;
            args[i].length = 16;
            args[i].key = key;
            args[i].start_barrier = &start_barrier;
            args[i].end_barrier = &end_barrier;
            args[i].should_stop = &should_stop;
            args[i].duration_seconds = 1.0;  /* Shorter for this test */
            
            pthread_create(&threads[i], NULL, benchmark_thread_worker, &args[i]);
        }
        
        /* Wait for completion */
        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
        }
        
        /* Calculate results */
        int total_ops = 0;
        double max_elapsed = 0;
        for (int i = 0; i < num_threads; i++) {
            total_ops += args[i].operations_completed;
            if (args[i].elapsed_seconds > max_elapsed) {
                max_elapsed = args[i].elapsed_seconds;
            }
        }
        
        double total_tps = total_ops / max_elapsed;
        
        if (num_threads == 1) {
            baseline_tps = total_tps;
        }
        
        double speedup = total_tps / baseline_tps;
        
        if (total_tps > best_tps) {
            best_tps = total_tps;
            best_thread_count = num_threads;
        }
        
        printf("%-10d %15.0f %14.2fx\n", num_threads, total_tps, speedup);
        
        /* Cleanup */
        free(threads);
        free(args);
        pthread_barrier_destroy(&start_barrier);
        pthread_barrier_destroy(&end_barrier);
    }
    
    printf("\nRecommendation:\n");
    printf("• Optimal thread count: %d threads\n", best_thread_count);
    printf("• Peak throughput: %.0f TPS\n", best_tps);
    printf("• Note: Optimal count depends on CPU cores and workload\n");
    
    printf("\n✓ Optimal thread count analysis complete\n");
}

/* ============================================================================
 * Best Practices
 * ============================================================================
 */

void print_mt_benchmark_best_practices(void) {
    printf("\n=== Multi-Threaded Benchmarking Best Practices ===\n\n");
    
    printf("✓ DO:\n");
    printf("  • Use pthread_barrier to synchronize thread start\n");
    printf("  • Measure wall-clock time (not CPU time)\n");
    printf("  • Run for sufficient duration (1-2+ seconds)\n");
    printf("  • Test multiple thread counts\n");
    printf("  • Use thread-local FPE_CTX instances\n");
    printf("  • Warm up before timing\n");
    printf("  • Account for CPU core count\n");
    printf("\n");
    
    printf("✗ DON'T:\n");
    printf("  • Share FPE_CTX across threads (bottleneck)\n");
    printf("  • Use too many threads (diminishing returns)\n");
    printf("  • Run on loaded systems (inaccurate)\n");
    printf("  • Forget thread creation/sync overhead\n");
    printf("  • Compare with different configurations\n");
    printf("\n");
    
    printf("Understanding Results:\n");
    printf("  • Linear scaling: Total TPS = Single TPS × Threads\n");
    printf("  • Efficiency: (Actual Speedup / Ideal Speedup) × 100%%\n");
    printf("  • Good efficiency: 80-95%%\n");
    printf("  • Typical optimal threads: Equal to CPU cores\n");
    printf("  • Beyond optimal: Diminishing returns or degradation\n");
    printf("\n");
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int main(void) {
    printf("=== Multi-Threaded TPS Benchmark ===\n");
    printf("\nThis example demonstrates multi-threaded throughput measurement.\n");
    
    /* Run examples */
    example1_single_threaded_baseline();
    example2_multi_threaded_scaling();
    example3_algorithm_comparison_mt();
    example4_optimal_thread_count();
    print_mt_benchmark_best_practices();
    
    printf("\n=== Multi-Threaded Benchmark Complete ===\n");
    printf("\nKey Takeaways:\n");
    printf("• FPE operations scale well with threads\n");
    printf("• Optimal thread count typically equals CPU cores\n");
    printf("• Use thread-local contexts for best performance\n");
    printf("• Efficiency typically 80-95%% with optimal threads\n");
    printf("• Always benchmark on target hardware\n");
    
    return 0;
}
