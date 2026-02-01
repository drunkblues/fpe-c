/**
 * @file threads.c
 * @brief Multi-threaded FPE Usage Example
 * 
 * This example demonstrates how to use FPE-C in multi-threaded applications.
 * 
 * Key Concepts:
 * - Thread-local FPE_CTX instances (recommended approach)
 * - Shared FPE_CTX with proper synchronization (advanced)
 * - Thread safety considerations
 * - Performance scaling with threads
 * - Common pitfalls and best practices
 * 
 * Build:
 *   gcc -pthread -I../include threads.c -L../build -lfpe -Wl,-rpath,../build -o threads
 * 
 * Run:
 *   ./threads
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include "fpe.h"

/* ============================================================================
 * Example 1: Thread-Local Context (Recommended Approach)
 * ============================================================================
 * Each thread creates its own FPE_CTX instance.
 * 
 * Advantages:
 * - No synchronization needed
 * - Best performance (no lock contention)
 * - Simple and safe
 * - Recommended for most use cases
 * 
 * Disadvantages:
 * - Higher memory usage (one context per thread)
 * - Context initialization overhead per thread
 */

typedef struct {
    int thread_id;
    int operations;
    unsigned char key[32];
    int key_bits;
} thread_local_args_t;

void* thread_local_worker(void* arg) {
    thread_local_args_t* args = (thread_local_args_t*)arg;
    
    /* Each thread creates its own context */
    FPE_CTX* ctx = FPE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Thread %d: Failed to create context\n", args->thread_id);
        return NULL;
    }
    
    /* Initialize with shared key */
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, 
                           args->key, args->key_bits, 10);
    if (ret != 0) {
        fprintf(stderr, "Thread %d: Failed to initialize context\n", args->thread_id);
        FPE_CTX_free(ctx);
        return NULL;
    }
    
    /* Perform encryptions */
    unsigned char tweak[8] = {0};
    unsigned int plaintext[16], ciphertext[16];
    
    for (int i = 0; i < args->operations; i++) {
        /* Generate thread-specific data */
        for (int j = 0; j < 16; j++) {
            plaintext[j] = (args->thread_id * 1000 + i + j) % 10;
        }
        
        /* Encrypt */
        ret = FPE_encrypt(ctx, plaintext, ciphertext, 16, tweak, 8);
        if (ret != 0) {
            fprintf(stderr, "Thread %d: Encryption failed at op %d\n", 
                    args->thread_id, i);
            break;
        }
    }
    
    /* Cleanup */
    FPE_CTX_free(ctx);
    
    printf("Thread %d: Completed %d operations\n", args->thread_id, args->operations);
    return NULL;
}

void example1_thread_local_context(void) {
    printf("\n=== Example 1: Thread-Local Context (Recommended) ===\n\n");
    
    const int NUM_THREADS = 4;
    const int OPS_PER_THREAD = 1000;
    
    pthread_t threads[NUM_THREADS];
    thread_local_args_t args[NUM_THREADS];
    
    /* Setup shared key */
    unsigned char key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    
    printf("Configuration:\n");
    printf("• Number of threads: %d\n", NUM_THREADS);
    printf("• Operations per thread: %d\n", OPS_PER_THREAD);
    printf("• Total operations: %d\n", NUM_THREADS * OPS_PER_THREAD);
    printf("• Approach: Thread-local context (no synchronization needed)\n\n");
    
    /* Start timing */
    clock_t start = clock();
    
    /* Create threads */
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i + 1;
        args[i].operations = OPS_PER_THREAD;
        memcpy(args[i].key, key, 32);
        args[i].key_bits = 256;
        
        int ret = pthread_create(&threads[i], NULL, thread_local_worker, &args[i]);
        if (ret != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i + 1);
            return;
        }
    }
    
    /* Wait for completion */
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    /* Calculate performance */
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    double total_ops = NUM_THREADS * OPS_PER_THREAD;
    double tps = total_ops / elapsed;
    
    printf("\nPerformance:\n");
    printf("• Elapsed time: %.3f seconds\n", elapsed);
    printf("• Total TPS: %.0f operations/second\n", tps);
    printf("• Per-thread TPS: %.0f operations/second\n", tps / NUM_THREADS);
    
    printf("\n✓ Thread-local approach is simple and fast!\n");
}

/* ============================================================================
 * Example 2: Shared Context with Mutex (Advanced)
 * ============================================================================
 * Multiple threads share a single FPE_CTX instance with mutex protection.
 * 
 * Advantages:
 * - Lower memory usage (one context for all threads)
 * - Single initialization
 * 
 * Disadvantages:
 * - Requires synchronization (mutex/lock)
 * - Lock contention reduces performance
 * - More complex code
 * - Only use if memory is severely constrained
 * 
 * Note: FPE_CTX is NOT thread-safe by design. You MUST use locks.
 */

typedef struct {
    int thread_id;
    int operations;
    FPE_CTX* shared_ctx;
    pthread_mutex_t* mutex;
} shared_ctx_args_t;

void* shared_ctx_worker(void* arg) {
    shared_ctx_args_t* args = (shared_ctx_args_t*)arg;
    
    /* Perform encryptions */
    unsigned char tweak[8] = {0};
    unsigned int plaintext[16], ciphertext[16];
    
    for (int i = 0; i < args->operations; i++) {
        /* Generate thread-specific data */
        for (int j = 0; j < 16; j++) {
            plaintext[j] = (args->thread_id * 1000 + i + j) % 10;
        }
        
        /* Lock mutex before using shared context */
        pthread_mutex_lock(args->mutex);
        
        /* Encrypt using shared context */
        int ret = FPE_encrypt(args->shared_ctx, plaintext, ciphertext, 16, tweak, 8);
        
        /* Unlock immediately after operation */
        pthread_mutex_unlock(args->mutex);
        
        if (ret != 0) {
            fprintf(stderr, "Thread %d: Encryption failed at op %d\n", 
                    args->thread_id, i);
            break;
        }
    }
    
    printf("Thread %d: Completed %d operations\n", args->thread_id, args->operations);
    return NULL;
}

void example2_shared_context_with_mutex(void) {
    printf("\n=== Example 2: Shared Context with Mutex (Advanced) ===\n\n");
    
    const int NUM_THREADS = 4;
    const int OPS_PER_THREAD = 1000;
    
    pthread_t threads[NUM_THREADS];
    shared_ctx_args_t args[NUM_THREADS];
    pthread_mutex_t mutex;
    
    /* Initialize mutex */
    pthread_mutex_init(&mutex, NULL);
    
    /* Create shared context */
    FPE_CTX* shared_ctx = FPE_CTX_new();
    if (!shared_ctx) {
        fprintf(stderr, "Failed to create shared context\n");
        pthread_mutex_destroy(&mutex);
        return;
    }
    
    unsigned char key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    
    int ret = FPE_CTX_init(shared_ctx, FPE_MODE_FF1, FPE_ALGO_AES, 
                           key, 256, 10);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize shared context\n");
        FPE_CTX_free(shared_ctx);
        pthread_mutex_destroy(&mutex);
        return;
    }
    
    printf("Configuration:\n");
    printf("• Number of threads: %d\n", NUM_THREADS);
    printf("• Operations per thread: %d\n", OPS_PER_THREAD);
    printf("• Total operations: %d\n", NUM_THREADS * OPS_PER_THREAD);
    printf("• Approach: Shared context with mutex (lock contention expected)\n\n");
    
    /* Start timing */
    clock_t start = clock();
    
    /* Create threads */
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i + 1;
        args[i].operations = OPS_PER_THREAD;
        args[i].shared_ctx = shared_ctx;
        args[i].mutex = &mutex;
        
        ret = pthread_create(&threads[i], NULL, shared_ctx_worker, &args[i]);
        if (ret != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i + 1);
            FPE_CTX_free(shared_ctx);
            pthread_mutex_destroy(&mutex);
            return;
        }
    }
    
    /* Wait for completion */
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    /* Calculate performance */
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    double total_ops = NUM_THREADS * OPS_PER_THREAD;
    double tps = total_ops / elapsed;
    
    printf("\nPerformance:\n");
    printf("• Elapsed time: %.3f seconds\n", elapsed);
    printf("• Total TPS: %.0f operations/second\n", tps);
    printf("• Per-thread TPS: %.0f operations/second\n", tps / NUM_THREADS);
    
    printf("\n⚠️  Note: Mutex contention reduces performance vs thread-local approach\n");
    
    /* Cleanup */
    FPE_CTX_free(shared_ctx);
    pthread_mutex_destroy(&mutex);
}

/* ============================================================================
 * Example 3: Thread Pool Pattern
 * ============================================================================
 * Demonstrates a simple thread pool for processing work items.
 * Each worker thread has its own context (thread-local approach).
 */

typedef struct {
    char data[256];
    int thread_id;
} work_item_t;

typedef struct {
    int thread_id;
    work_item_t* work_queue;
    int queue_size;
    int* next_work_index;
    pthread_mutex_t* queue_mutex;
    unsigned char* key;
    int key_bits;
} pool_worker_args_t;

void* pool_worker(void* arg) {
    pool_worker_args_t* args = (pool_worker_args_t*)arg;
    
    /* Each worker has its own context */
    FPE_CTX* ctx = FPE_CTX_new();
    if (!ctx) return NULL;
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, 
                           args->key, args->key_bits, 10);
    if (ret != 0) {
        FPE_CTX_free(ctx);
        return NULL;
    }
    
    int processed = 0;
    
    /* Process work items */
    while (1) {
        /* Get next work item */
        pthread_mutex_lock(args->queue_mutex);
        int work_index = (*args->next_work_index)++;
        pthread_mutex_unlock(args->queue_mutex);
        
        if (work_index >= args->queue_size) {
            break;  /* No more work */
        }
        
        /* Process work item */
        work_item_t* item = &args->work_queue[work_index];
        
        /* Encrypt the data (simulated work) */
        unsigned char tweak[8] = {0};
        unsigned int plaintext[16], ciphertext[16];
        for (int i = 0; i < 16; i++) {
            plaintext[i] = (work_index + i) % 10;
        }
        
        FPE_encrypt(ctx, plaintext, ciphertext, 16, tweak, 8);
        
        item->thread_id = args->thread_id;
        processed++;
    }
    
    printf("Worker thread %d: Processed %d items\n", args->thread_id, processed);
    
    /* Cleanup */
    FPE_CTX_free(ctx);
    return NULL;
}

void example3_thread_pool_pattern(void) {
    printf("\n=== Example 3: Thread Pool Pattern ===\n\n");
    
    const int NUM_WORKERS = 4;
    const int NUM_WORK_ITEMS = 1000;
    
    pthread_t workers[NUM_WORKERS];
    pool_worker_args_t args[NUM_WORKERS];
    pthread_mutex_t queue_mutex;
    int next_work_index = 0;
    
    /* Create work queue */
    work_item_t* work_queue = calloc(NUM_WORK_ITEMS, sizeof(work_item_t));
    for (int i = 0; i < NUM_WORK_ITEMS; i++) {
        snprintf(work_queue[i].data, sizeof(work_queue[i].data), 
                 "Work item %d", i);
    }
    
    /* Setup */
    unsigned char key[32];
    for (int i = 0; i < 32; i++) key[i] = i;
    
    pthread_mutex_init(&queue_mutex, NULL);
    
    printf("Configuration:\n");
    printf("• Worker threads: %d\n", NUM_WORKERS);
    printf("• Work items: %d\n", NUM_WORK_ITEMS);
    printf("• Items per worker: ~%d\n", NUM_WORK_ITEMS / NUM_WORKERS);
    printf("• Approach: Thread pool with work queue\n\n");
    
    /* Start timing */
    clock_t start = clock();
    
    /* Create worker threads */
    for (int i = 0; i < NUM_WORKERS; i++) {
        args[i].thread_id = i + 1;
        args[i].work_queue = work_queue;
        args[i].queue_size = NUM_WORK_ITEMS;
        args[i].next_work_index = &next_work_index;
        args[i].queue_mutex = &queue_mutex;
        args[i].key = key;
        args[i].key_bits = 256;
        
        pthread_create(&workers[i], NULL, pool_worker, &args[i]);
    }
    
    /* Wait for completion */
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }
    
    /* Calculate performance */
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    double tps = NUM_WORK_ITEMS / elapsed;
    
    printf("\nPerformance:\n");
    printf("• Elapsed time: %.3f seconds\n", elapsed);
    printf("• Total TPS: %.0f items/second\n", tps);
    
    printf("\n✓ Thread pool efficiently distributes work!\n");
    
    /* Cleanup */
    pthread_mutex_destroy(&queue_mutex);
    free(work_queue);
}

/* ============================================================================
 * Best Practices Summary
 * ============================================================================
 */

void print_best_practices(void) {
    printf("\n=== Multi-Threading Best Practices ===\n\n");
    
    printf("✓ DO:\n");
    printf("  • Use thread-local FPE_CTX instances (one per thread)\n");
    printf("  • Initialize context once per thread at thread start\n");
    printf("  • Clean up context at thread end\n");
    printf("  • Use thread pools for work distribution\n");
    printf("  • Profile to find optimal thread count for your system\n");
    printf("  • Consider CPU core count when choosing thread count\n");
    printf("\n");
    
    printf("✗ DON'T:\n");
    printf("  • Share FPE_CTX across threads without synchronization\n");
    printf("  • Create/destroy contexts frequently (high overhead)\n");
    printf("  • Use more threads than CPU cores (diminishing returns)\n");
    printf("  • Forget to check return values\n");
    printf("  • Assume linear scaling (Amdahl's law applies)\n");
    printf("\n");
    
    printf("Thread Safety Notes:\n");
    printf("  • FPE_CTX is NOT thread-safe by design\n");
    printf("  • Each thread should have its own FPE_CTX instance\n");
    printf("  • If sharing is required, use mutex/lock protection\n");
    printf("  • Thread-local approach has best performance\n");
    printf("\n");
    
    printf("Performance Tips:\n");
    printf("  • Thread count = CPU core count is a good starting point\n");
    printf("  • Measure actual performance with your workload\n");
    printf("  • Consider I/O vs CPU-bound workloads\n");
    printf("  • Use thread pools to avoid thread creation overhead\n");
    printf("  • Batch operations when possible\n");
    printf("\n");
}

/* ============================================================================
 * Main
 * ============================================================================
 */

int main(void) {
    printf("=== FPE-C Multi-Threading Examples ===\n");
    printf("\nThis example demonstrates how to use FPE-C in multi-threaded applications.\n");
    
    /* Run examples */
    example1_thread_local_context();
    example2_shared_context_with_mutex();
    example3_thread_pool_pattern();
    print_best_practices();
    
    printf("\n=== Multi-Threading Examples Complete ===\n");
    printf("\nKey Takeaways:\n");
    printf("• Use thread-local FPE_CTX instances (recommended)\n");
    printf("• FPE_CTX is NOT thread-safe - use locks if sharing\n");
    printf("• Thread-local approach has best performance\n");
    printf("• Thread pools efficiently distribute work\n");
    printf("• Profile to find optimal thread count\n");
    
    return 0;
}
