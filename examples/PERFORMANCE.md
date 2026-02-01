# Performance Examples and Benchmarking

This directory contains performance-related examples and benchmarking tools for the FPE-C library. These examples help you measure, analyze, and optimize FPE performance in your applications.

## Overview

Performance is a critical aspect of FPE implementations. This collection of examples demonstrates how to:
- Measure throughput (TPS - Transactions Per Second)
- Analyze latency (microseconds per operation)
- Compare algorithms (FF1 vs FF3 vs FF3-1)
- Compare ciphers (AES vs SM4)
- Optimize with multi-threading
- Find optimal thread counts
- Benchmark various configurations

## Available Examples

### 1. `benchmark.c` - Comprehensive Performance Benchmark

**Purpose**: Single-threaded performance analysis across all algorithms and ciphers.

**What it measures**:
- Algorithm comparison (FF1, FF3, FF3-1)
- Cipher comparison (AES-128/192/256, SM4-128)
- Input length impact (6 to 50 digits)
- Radix impact (2 to 62)
- Comprehensive performance reports

**Usage**:
```bash
make benchmark
./benchmark
```

**Sample output**:
```
Algorithm    Cipher                   TPS          µs/op
------------ --------------- ------------ ---------------
FF1          AES-128                64123           15.60
FF1          AES-256                63309           15.80
FF3-1        AES-128                45480           21.99
```

**Key metrics**:
- **TPS (Throughput)**: Higher is better (operations/second)
- **Latency**: Lower is better (microseconds/operation)

### 2. `benchmark_mt.c` - Multi-Threaded TPS Benchmark

**Purpose**: Measure multi-threaded performance and scaling efficiency.

**What it measures**:
- Thread scaling (1, 2, 4, 8, 12 threads)
- Scaling efficiency (vs ideal linear scaling)
- Optimal thread count determination
- Algorithm comparison across threads

**Usage**:
```bash
make benchmark_mt
./benchmark_mt
```

**Sample output**:
```
Threads          Total TPS  Per-Thread TPS      Efficiency
---------- --------------- --------------- ---------------
1                    59190           59190          100.0%
2                   118000           59000           99.8%
4                   230000           57500           97.3%
8                   440000           55000           93.2%
```

**Key insights**:
- **Efficiency**: How well threads scale (100% = perfect linear scaling)
- **Optimal threads**: Usually equals CPU core count
- **Diminishing returns**: Beyond optimal, efficiency drops

### 3. `aes_vs_sm4.c` - AES vs SM4 Comparison

**Purpose**: Compare AES and SM4 cipher performance across all algorithms.

**What it measures**:
- AES-128 vs SM4-128 (same key length)
- Performance across FF1, FF3, FF3-1
- Throughput and latency comparison
- Percentage difference

**Usage**:
```bash
make aes_vs_sm4
./aes_vs_sm4
```

**Sample output**:
```
Algorithm: FF1
Cipher                      TPS   Latency (µs)
--------------- --------------- ---------------
AES-128                   57559           17.37
SM4-128                   50869           19.66

Performance Difference:
• AES-128 is 13.2% faster than SM4-128
```

**Key insights**:
- AES typically 5-15% faster (with AES-NI)
- SM4 comparable performance
- Choose based on compliance needs, not just speed

### 4. `threads.c` - Multi-Threading Usage Patterns

**Purpose**: Demonstrate thread-safe FPE usage patterns.

**What it shows**:
- Thread-local contexts (recommended approach)
- Shared context with mutex (advanced)
- Thread pool pattern
- Best practices for concurrency

**Usage**:
```bash
make threads
./threads
```

**Key patterns**:
1. **Thread-local contexts** (best performance, no synchronization)
2. **Shared context with mutex** (lower memory, slower)
3. **Thread pool** (efficient work distribution)

**Performance comparison**:
- Thread-local: ~46K TPS (4 threads)
- Shared mutex: ~49K TPS (4 threads, varies)
- Thread pool: ~49K TPS (4 threads)

## Performance Characteristics

### Expected Single-Threaded Performance

Based on modern x86-64 CPU (3.0 GHz, AES-NI):

| Algorithm | Cipher    | Typical TPS | Latency (µs) |
|-----------|-----------|-------------|--------------|
| FF1       | AES-128   | 80-95K      | 10-12        |
| FF1       | AES-256   | 75-90K      | 11-13        |
| FF1       | SM4-128   | 65-80K      | 12-15        |
| FF3       | AES-128   | 50-60K      | 16-20        |
| FF3-1     | AES-128   | 50-60K      | 16-20        |
| FF3-1     | SM4-128   | 45-55K      | 18-22        |

### Multi-Threaded Scaling

- **2 threads**: ~1.9-2.0x speedup (95-100% efficiency)
- **4 threads**: ~3.7-3.9x speedup (92-97% efficiency)
- **8 threads**: ~7.0-7.6x speedup (87-95% efficiency)
- **16+ threads**: Diminishing returns on most CPUs

### Factors Affecting Performance

1. **CPU Architecture**
   - AES-NI support (10-50% faster for AES)
   - Core count (affects multi-threaded performance)
   - Clock speed (linear impact)

2. **Algorithm Choice**
   - FF1: Best throughput (adaptive rounds)
   - FF3-1: Moderate throughput (fixed 8 rounds)
   - FF3: Similar to FF3-1 (deprecated)

3. **Input Parameters**
   - Input length: Longer inputs = slower
   - Radix: Higher radix = slightly slower
   - Tweak length: Minimal impact

4. **Cipher Choice**
   - AES: Typically faster with hardware support
   - SM4: Comparable, may be faster on Chinese CPUs

5. **System Load**
   - Background processes reduce performance
   - Thermal throttling affects sustained performance
   - Memory bandwidth (minimal impact for FPE)

## Benchmarking Best Practices

### Running Benchmarks

1. **Minimize system load**:
   ```bash
   # Close unnecessary applications
   # Disable background services if possible
   ```

2. **Run multiple times**:
   ```bash
   for i in {1..5}; do
       echo "Run $i:"
       ./benchmark | grep "TPS:"
   done
   ```

3. **Check CPU frequency**:
   ```bash
   # Linux
   cat /proc/cpuinfo | grep MHz
   
   # macOS
   sysctl -a | grep cpu.freq
   ```

### Interpreting Results

1. **TPS (Throughput)**:
   - Higher is better
   - Varies with CPU speed
   - Compare relative performance (ratios)

2. **Latency**:
   - Lower is better
   - Inverse of throughput
   - More relevant for real-time systems

3. **Scaling Efficiency**:
   - 100% = perfect linear scaling
   - 80-95% = good scaling
   - <80% = diminishing returns

### Benchmarking Checklist

- [ ] Run on target hardware
- [ ] Test all algorithms you'll use
- [ ] Test all key sizes you'll use
- [ ] Test typical input lengths
- [ ] Test with realistic tweaks
- [ ] Measure both single and multi-threaded
- [ ] Run multiple iterations
- [ ] Document CPU model and frequency
- [ ] Document OpenSSL version
- [ ] Check for thermal throttling

## TPS (Transactions Per Second) Calculation

### Formula

```
TPS = Total Operations / Elapsed Time (seconds)
```

Where one operation is typically:
- One encryption, OR
- One decryption, OR
- One encrypt+decrypt pair (for reversibility tests)

### Example Calculation

```c
clock_t start = clock();

for (int i = 0; i < 1000; i++) {
    FPE_encrypt(ctx, plaintext, ciphertext, len, tweak, tweak_len);
    FPE_decrypt(ctx, ciphertext, decrypted, len, tweak, tweak_len);
}

clock_t end = clock();
double elapsed = (double)(end - start) / CLOCKS_PER_SEC;

int total_ops = 1000 * 2;  // 1000 iterations × 2 ops each
double tps = total_ops / elapsed;

printf("TPS: %.0f operations/second\n", tps);
printf("Latency: %.2f µs/operation\n", (elapsed * 1000000) / total_ops);
```

### Warm-up Phase

Always include a warm-up phase before timing:

```c
// Warm-up (not timed)
for (int i = 0; i < 10; i++) {
    FPE_encrypt(ctx, plaintext, ciphertext, len, tweak, tweak_len);
}

// Now measure (timed)
clock_t start = clock();
// ... benchmark code ...
```

This ensures:
- CPU caches are populated
- Branch predictors are trained
- First-run overhead is excluded

## Multi-Threading Considerations

### Thread-Local Contexts (Recommended)

```c
void* worker(void* arg) {
    // Each thread creates its own context
    FPE_CTX* ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, mode, algo, key, key_bits, radix);
    
    // Perform operations (no synchronization needed)
    FPE_encrypt(ctx, plaintext, ciphertext, len, tweak, tweak_len);
    
    // Cleanup
    FPE_CTX_free(ctx);
    return NULL;
}
```

**Advantages**:
- No synchronization overhead
- Best performance
- Simple and safe
- **Recommended for most use cases**

### Shared Context with Mutex (Advanced)

```c
pthread_mutex_t mutex;
FPE_CTX* shared_ctx;

void* worker(void* arg) {
    pthread_mutex_lock(&mutex);
    FPE_encrypt(shared_ctx, plaintext, ciphertext, len, tweak, tweak_len);
    pthread_mutex_unlock(&mutex);
    return NULL;
}
```

**Disadvantages**:
- Lock contention reduces performance
- More complex code
- **Only use if memory is severely constrained**

### Finding Optimal Thread Count

Run `benchmark_mt.c` to find the optimal thread count for your system:

```bash
./benchmark_mt
```

Look for the thread count with:
- Highest total TPS
- Efficiency > 80%
- Usually equals CPU core count

## Comparing with Other Implementations

When comparing FPE-C with other libraries:

1. **Use identical test vectors**:
   - Same algorithm (FF1/FF3/FF3-1)
   - Same cipher and key size
   - Same input length and radix
   - Same tweak length

2. **Use identical hardware**:
   - Same CPU model
   - Same clock speed
   - Same memory configuration

3. **Use identical test methodology**:
   - Same number of iterations
   - Same warm-up approach
   - Same timing method
   - Same thread count

4. **Document differences**:
   - Compiler versions
   - Optimization flags
   - OpenSSL versions
   - OS differences

## Performance Optimization Tips

### For Application Developers

1. **Reuse contexts**:
   ```c
   // Good: Reuse context
   FPE_CTX* ctx = FPE_CTX_new();
   FPE_CTX_init(ctx, ...);
   for (int i = 0; i < 1000; i++) {
       FPE_encrypt(ctx, ...);
   }
   FPE_CTX_free(ctx);
   
   // Bad: Create/destroy every time
   for (int i = 0; i < 1000; i++) {
       FPE_CTX* ctx = FPE_CTX_new();
       FPE_CTX_init(ctx, ...);
       FPE_encrypt(ctx, ...);
       FPE_CTX_free(ctx);
   }
   ```

2. **Use thread-local contexts**:
   - One context per thread
   - No synchronization needed
   - Best multi-threaded performance

3. **Choose appropriate algorithm**:
   - FF1: Best performance, use when possible
   - FF3-1: Use for compatibility, slower
   - FF3: Don't use (deprecated)

4. **Batch operations**:
   - Encrypt multiple values with one context
   - Reduces setup overhead

### For Library Developers

(These are already implemented in FPE-C)

1. **Use hardware acceleration**:
   - AES-NI for AES operations
   - Compiler intrinsics where available

2. **Minimize allocations**:
   - Reuse buffers
   - Stack allocation for small arrays

3. **Optimize hot paths**:
   - Inline small functions
   - Reduce branching in loops

4. **Profile and measure**:
   - Use profiling tools
   - Benchmark after changes
   - Focus on bottlenecks

## Troubleshooting Performance Issues

### Low TPS (Below Expected)

**Check**:
1. CPU frequency (may be throttled)
2. System load (close other apps)
3. Thermal throttling (check temps)
4. Power management (use performance mode)
5. OpenSSL version (older = slower)
6. Compiler optimizations (use -O2 or -O3)

### Poor Multi-Threading Scaling

**Check**:
1. Using shared context? (switch to thread-local)
2. Too many threads? (try CPU core count)
3. Lock contention? (check mutex usage)
4. Cache thrashing? (reduce thread count)

### Inconsistent Results

**Check**:
1. System load varying between runs
2. CPU frequency scaling
3. Thermal throttling during long runs
4. Background processes

## Further Reading

- NIST SP 800-38G (FPE standards)
- OpenSSL documentation (cipher implementation)
- Threading and performance guides in main README
- Intel AES-NI documentation

## Examples Quick Reference

| Example         | Purpose                        | Key Metric | Build Command        |
|-----------------|--------------------------------|------------|----------------------|
| benchmark       | Algorithm/cipher comparison    | TPS        | `make benchmark`     |
| benchmark_mt    | Multi-threading analysis       | Efficiency | `make benchmark_mt`  |
| aes_vs_sm4      | AES vs SM4 comparison          | TPS diff   | `make aes_vs_sm4`    |
| threads         | Threading patterns             | Patterns   | `make threads`       |

## Summary

The performance examples in this directory provide comprehensive tools for:
- Measuring FPE performance in various configurations
- Comparing algorithms and ciphers
- Optimizing multi-threaded applications
- Understanding performance characteristics

**Key Takeaways**:
- FF1 typically fastest (80-95K TPS single-threaded)
- FF3-1 moderate speed (50-60K TPS single-threaded)
- Multi-threading scales well (80-95% efficiency up to CPU core count)
- AES-128 typically 5-15% faster than SM4 (with AES-NI)
- Always benchmark on target hardware with realistic workloads

For questions or issues, please refer to the main project README or open an issue on GitHub.
