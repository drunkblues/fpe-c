# Thread Safety in FPE-C

This document explains thread safety guarantees, best practices, and guidelines for using FPE-C in multi-threaded applications.

## Table of Contents

- [Thread Safety Overview](#thread-safety-overview)
- [Context Thread Safety](#context-thread-safety)
- [Safe Usage Patterns](#safe-usage-patterns)
- [Unsafe Patterns to Avoid](#unsafe-patterns-to-avoid)
- [Multi-Threaded Performance](#multi-threaded-performance)
- [Examples](#examples)
- [FAQ](#faq)

---

## Thread Safety Overview

### Summary

| Component | Thread-Safe? | Notes |
|-----------|--------------|-------|
| **FPE_CTX** | ❌ No | Each context must be used by single thread |
| **Library Functions** | ✅ Yes | Functions themselves are reentrant |
| **Global State** | ✅ None | No global state in FPE-C |
| **OpenSSL** | ✅ Yes* | Modern OpenSSL (1.1.0+) is thread-safe |

**Key Rule:** Each `FPE_CTX` instance is **NOT thread-safe**. Do not share contexts between threads.

### What This Means

✅ **Safe:**
- Multiple threads each with their own `FPE_CTX`
- Concurrent operations on different contexts
- Read-only access to library constants/enums

❌ **Unsafe:**
- Sharing single `FPE_CTX` between threads without synchronization
- Concurrent calls to same context from multiple threads
- Modifying context state concurrently

---

## Context Thread Safety

### Why Contexts Are Not Thread-Safe

Each `FPE_CTX` contains mutable state:
- Cipher contexts (OpenSSL EVP structures)
- Algorithm-specific state (FF1/FF3/FF3-1)
- Temporary buffers
- Configuration parameters

Sharing these between threads without synchronization causes:
- **Data races** - Undefined behavior, crashes
- **Incorrect results** - Corrupted encryption/decryption
- **Security issues** - Potential information leakage

### Thread-Safe Design Pattern

**One Context Per Thread:**

```c
// ✅ SAFE: Each thread has its own context
void* worker_thread(void* arg) {
    // Create thread-local context
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) return NULL;
    
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    // Use context for this thread's work
    for (int i = 0; i < work_count; i++) {
        FPE_encrypt(ctx, plaintext[i], ciphertext[i], len, tweak, tweak_len);
    }
    
    FPE_CTX_free(ctx);
    return NULL;
}
```

---

## Safe Usage Patterns

### Pattern 1: Thread Pool with Thread-Local Contexts

**Use when:** Processing large batches with worker threads

```c
#include <pthread.h>

#define NUM_WORKERS 8

typedef struct {
    int thread_id;
    int start_idx;
    int end_idx;
    unsigned char *key;
    // Input/output arrays
    char **input;
    char **output;
} WorkerArgs;

void* worker(void* arg) {
    WorkerArgs *args = (WorkerArgs*)arg;
    
    // Each worker creates its own context
    FPE_CTX *ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, args->key, 128, 10);
    
    // Process assigned range
    for (int i = args->start_idx; i < args->end_idx; i++) {
        char tweak[64];
        snprintf(tweak, sizeof(tweak), "record:%d", i);
        
        FPE_encrypt_str(ctx, "0123456789", args->input[i], args->output[i],
                        (unsigned char*)tweak, strlen(tweak));
    }
    
    FPE_CTX_free(ctx);
    return NULL;
}

int process_batch(char **input, char **output, int count, unsigned char *key) {
    pthread_t threads[NUM_WORKERS];
    WorkerArgs args[NUM_WORKERS];
    
    int chunk_size = count / NUM_WORKERS;
    
    // Launch workers
    for (int i = 0; i < NUM_WORKERS; i++) {
        args[i].thread_id = i;
        args[i].start_idx = i * chunk_size;
        args[i].end_idx = (i == NUM_WORKERS - 1) ? count : (i + 1) * chunk_size;
        args[i].key = key;
        args[i].input = input;
        args[i].output = output;
        
        pthread_create(&threads[i], NULL, worker, &args[i]);
    }
    
    // Wait for completion
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    return 0;
}
```

### Pattern 2: Thread-Local Storage (TLS)

**Use when:** Long-lived threads processing ongoing requests

```c
#include <pthread.h>

// Thread-local context storage
__thread FPE_CTX *tls_ctx = NULL;

// Initialize context for current thread
int init_thread_context(unsigned char *key) {
    if (tls_ctx != NULL) {
        return 0;  // Already initialized
    }
    
    tls_ctx = FPE_CTX_new();
    if (!tls_ctx) return -1;
    
    if (FPE_CTX_init(tls_ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10) != 0) {
        FPE_CTX_free(tls_ctx);
        tls_ctx = NULL;
        return -1;
    }
    
    return 0;
}

// Cleanup thread-local context
void cleanup_thread_context(void) {
    if (tls_ctx) {
        FPE_CTX_free(tls_ctx);
        tls_ctx = NULL;
    }
}

// Use thread-local context
int encrypt_with_tls(const char *input, char *output) {
    if (!tls_ctx) return -1;
    
    unsigned char tweak[] = "user-data";
    return FPE_encrypt_str(tls_ctx, "0123456789", input, output,
                           tweak, strlen((char*)tweak));
}

// Worker thread (e.g., in thread pool)
void* request_handler(void* arg) {
    init_thread_context(global_key);
    
    while (running) {
        Request *req = get_request();
        if (req) {
            encrypt_with_tls(req->plaintext, req->ciphertext);
            send_response(req);
        }
    }
    
    cleanup_thread_context();
    return NULL;
}
```

### Pattern 3: Synchronized Shared Context (Not Recommended)

**Use when:** Absolutely necessary to share context (adds overhead)

```c
#include <pthread.h>

typedef struct {
    FPE_CTX *ctx;
    pthread_mutex_t lock;
} SharedContext;

SharedContext* create_shared_context(unsigned char *key) {
    SharedContext *shared = malloc(sizeof(SharedContext));
    
    shared->ctx = FPE_CTX_new();
    FPE_CTX_init(shared->ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    pthread_mutex_init(&shared->lock, NULL);
    
    return shared;
}

int encrypt_with_shared(SharedContext *shared, const char *input, char *output) {
    // Lock before using shared context
    pthread_mutex_lock(&shared->lock);
    
    unsigned char tweak[] = "data";
    int ret = FPE_encrypt_str(shared->ctx, "0123456789", input, output,
                              tweak, strlen((char*)tweak));
    
    pthread_mutex_unlock(&shared->lock);
    return ret;
}

void destroy_shared_context(SharedContext *shared) {
    pthread_mutex_destroy(&shared->lock);
    FPE_CTX_free(shared->ctx);
    free(shared);
}
```

**Note:** This pattern serializes all operations on the shared context, eliminating parallelism benefits. Use only when context creation overhead is extremely high and throughput requirements are low.

---

## Unsafe Patterns to Avoid

### ❌ Anti-Pattern 1: Sharing Context Without Synchronization

```c
// UNSAFE: Multiple threads using same context
FPE_CTX *global_ctx;  // Shared context

void* worker(void* arg) {
    // RACE CONDITION: Multiple threads access global_ctx concurrently
    FPE_encrypt(global_ctx, plaintext, ciphertext, len, tweak, tweak_len);
    return NULL;
}

// This will cause crashes, data corruption, incorrect results
```

**Problem:** Concurrent access to mutable state causes undefined behavior.

**Fix:** Use one context per thread (Pattern 1 or 2 above).

### ❌ Anti-Pattern 2: Context Pooling Without Protection

```c
// UNSAFE: Context pool without proper synchronization
FPE_CTX *context_pool[10];

void* worker(void* arg) {
    int id = *(int*)arg;
    FPE_CTX *ctx = context_pool[id % 10];  // Multiple threads may pick same context
    
    FPE_encrypt(ctx, plaintext, ciphertext, len, tweak, tweak_len);
    return NULL;
}
```

**Problem:** Multiple threads may select the same context from pool.

**Fix:** Use proper context allocation per thread, or add synchronization.

### ❌ Anti-Pattern 3: Concurrent Context Modification

```c
// UNSAFE: Modifying context configuration from multiple threads
void* thread1(void* arg) {
    FPE_CTX_init(shared_ctx, FPE_MODE_FF1, FPE_ALGO_AES, key1, 128, 10);
    FPE_encrypt(shared_ctx, ...);
    return NULL;
}

void* thread2(void* arg) {
    FPE_CTX_init(shared_ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key2, 128, 26);
    FPE_encrypt(shared_ctx, ...);
    return NULL;
}
```

**Problem:** Concurrent initialization/reconfiguration corrupts context state.

**Fix:** Initialize contexts once per thread, don't reconfigure shared contexts.

---

## Multi-Threaded Performance

### Performance Characteristics

FPE-C scales nearly linearly with thread count due to:
- **No shared state** - Each thread operates independently
- **No lock contention** - No synchronization required between threads
- **CPU-bound** - Workload benefits from parallel execution

**Scaling efficiency:**
```
Threads:   1      2      4      8      16
Scaling:   100%   95%    94%    90%    83%
```

### Performance Guidelines

**Optimal thread count:**
```
Optimal threads = Number of physical CPU cores
```

**Why not more threads?**
- Hyperthreading/SMT provides only ~5-10% benefit
- Too many threads increase context switching overhead
- Memory bandwidth saturation on many-core systems

**Example (16-core system):**
```c
#include <unistd.h>

int get_optimal_thread_count(void) {
    // Get CPU core count
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores <= 0) cores = 4;  // Fallback
    
    // Use physical cores (assume 2x for hyperthreading)
    return cores / 2;
}
```

### Throughput Scaling

**Expected throughput by thread count:**

| Threads | FF1-AES (TPS) | Efficiency |
|---------|---------------|------------|
| 1       | 90,000        | 100%       |
| 2       | 170,000       | 95%        |
| 4       | 340,000       | 94%        |
| 8       | 650,000       | 90%        |
| 16      | 1,200,000     | 83%        |

---

## Examples

### Complete Multi-Threaded Example

```c
#include <fpe.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_THREADS 32

typedef struct {
    int thread_id;
    int records_to_process;
    unsigned char key[16];
    char **input_data;
    char **output_data;
    int *error_count;
} ThreadData;

void* encryption_worker(void* arg) {
    ThreadData *data = (ThreadData*)arg;
    
    // Create thread-local context
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) {
        (*data->error_count)++;
        return NULL;
    }
    
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, data->key, 128, 10) != 0) {
        FPE_CTX_free(ctx);
        (*data->error_count)++;
        return NULL;
    }
    
    // Process assigned records
    for (int i = 0; i < data->records_to_process; i++) {
        int idx = data->thread_id * data->records_to_process + i;
        
        char tweak[64];
        snprintf(tweak, sizeof(tweak), "record:%d", idx);
        
        int ret = FPE_encrypt_str(ctx, "0123456789",
                                  data->input_data[idx],
                                  data->output_data[idx],
                                  (unsigned char*)tweak, strlen(tweak));
        
        if (ret != 0) {
            (*data->error_count)++;
        }
    }
    
    FPE_CTX_free(ctx);
    return NULL;
}

int main(void) {
    // Configuration
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    
    int total_records = 100000;
    int records_per_thread = total_records / num_threads;
    
    // Generate key
    unsigned char key[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                            0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
    
    // Allocate data
    char **input = malloc(total_records * sizeof(char*));
    char **output = malloc(total_records * sizeof(char*));
    for (int i = 0; i < total_records; i++) {
        input[i] = malloc(32);
        output[i] = malloc(32);
        snprintf(input[i], 32, "%016d", i);  // Generate test data
    }
    
    // Thread data
    pthread_t threads[MAX_THREADS];
    ThreadData thread_data[MAX_THREADS];
    int error_count = 0;
    
    printf("Processing %d records with %d threads...\n", total_records, num_threads);
    
    // Launch threads
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].records_to_process = records_per_thread;
        memcpy(thread_data[i].key, key, 16);
        thread_data[i].input_data = input;
        thread_data[i].output_data = output;
        thread_data[i].error_count = &error_count;
        
        pthread_create(&threads[i], NULL, encryption_worker, &thread_data[i]);
    }
    
    // Wait for completion
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("Completed! Errors: %d\n", error_count);
    
    // Cleanup
    for (int i = 0; i < total_records; i++) {
        free(input[i]);
        free(output[i]);
    }
    free(input);
    free(output);
    
    return error_count > 0 ? 1 : 0;
}
```

---

## FAQ

### Q: Can I use FPE_encrypt_oneshot in multiple threads?

**Answer:** Yes, one-shot functions are thread-safe.

```c
// SAFE: Each call creates its own temporary context
void* worker(void* arg) {
    FPE_encrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                            plaintext, alphabet, tweak, tweak_len,
                            ciphertext, bufsize);
    return NULL;
}
```

**Note:** One-shot functions are ~100x slower than reusing contexts. Use thread-local contexts for better performance.

### Q: Is OpenSSL thread-safe?

**Answer:** Yes, OpenSSL 1.1.0+ is fully thread-safe without additional setup.

For older OpenSSL (1.0.x):
```c
#include <openssl/crypto.h>

// Required for OpenSSL 1.0.x
void init_openssl_threading(void) {
    CRYPTO_set_locking_callback(locking_callback);
    CRYPTO_set_id_callback(id_callback);
}
```

FPE-C assumes OpenSSL 1.1.0+ and does not provide threading setup for older versions.

### Q: Do I need mutexes with one context per thread?

**Answer:** No, if each thread has its own context, no synchronization is needed.

### Q: Can I share keys between threads?

**Answer:** Yes, keys are read-only and safe to share.

```c
// SAFE: Key is read-only, can be shared
unsigned char shared_key[16] = { /* ... */ };

void* worker1(void* arg) {
    FPE_CTX *ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, shared_key, 128, 10);
    // ...
}

void* worker2(void* arg) {
    FPE_CTX *ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, shared_key, 128, 10);
    // ...
}
```

### Q: What about signal handlers?

**Answer:** Do NOT call FPE functions from signal handlers.

Signal handlers should only do async-signal-safe operations. FPE-C uses non-reentrant OpenSSL functions and is not async-signal-safe.

### Q: Can I fork() after initializing contexts?

**Answer:** Create contexts AFTER fork(), not before.

```c
// UNSAFE
FPE_CTX *ctx = FPE_CTX_new();
FPE_CTX_init(ctx, ...);
fork();  // Child inherits context - potential issues

// SAFE
fork();
if (child_process) {
    FPE_CTX *ctx = FPE_CTX_new();  // Create in child
    FPE_CTX_init(ctx, ...);
}
```

---

## Summary

**Thread Safety Rules:**

✅ **DO:**
- Create one `FPE_CTX` per thread
- Use thread-local storage for long-lived threads
- Use thread pools with per-thread contexts
- Share keys (read-only) between threads
- Use one-shot API if context reuse not needed

❌ **DON'T:**
- Share `FPE_CTX` between threads without synchronization
- Access same context from multiple threads
- Call FPE functions from signal handlers
- Fork after creating contexts

**Performance:**

- FPE-C scales linearly with thread count (80-95% efficiency)
- Optimal thread count = physical CPU cores
- No lock contention, no shared state
- Each context is independent

**For more information:**
- [PERFORMANCE.md](PERFORMANCE.md) - Detailed performance characteristics
- [SECURITY.md](SECURITY.md) - Security best practices
- [API.md](API.md) - Complete API reference
