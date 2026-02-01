# Tests CMakeLists.txt

# Add Unity testing framework
add_library(unity STATIC unity/src/unity.c)
target_include_directories(unity PUBLIC unity/src)

# Basic smoke test
add_executable(test_basic test_basic.c)
target_link_libraries(test_basic fpe)
add_test(NAME test_basic COMMAND test_basic)

# Utility functions unit tests
add_executable(test_utils test_utils.c)
target_link_libraries(test_utils fpe unity)
add_test(NAME test_utils COMMAND test_utils)

# FF1 algorithm unit tests
add_executable(test_ff1 test_ff1.c)
target_link_libraries(test_ff1 fpe unity m)
add_test(NAME test_ff1 COMMAND test_ff1)

# FF1 NIST test vectors
add_executable(test_ff1_vectors test_ff1_vectors.c)
target_link_libraries(test_ff1_vectors fpe unity m)
add_test(NAME test_ff1_vectors COMMAND test_ff1_vectors)

# FF1 performance benchmarks
add_executable(test_ff1_performance test_ff1_performance.c)
target_link_libraries(test_ff1_performance fpe unity m)
add_test(NAME test_ff1_performance COMMAND test_ff1_performance)

# FF1 multi-threading tests
find_package(Threads REQUIRED)
add_executable(test_ff1_mt test_ff1_mt.c)
target_link_libraries(test_ff1_mt fpe unity m Threads::Threads)
add_test(NAME test_ff1_mt COMMAND test_ff1_mt)

# FF3 algorithm unit tests
add_executable(test_ff3 test_ff3.c)
target_link_libraries(test_ff3 fpe unity)
add_test(NAME test_ff3 COMMAND test_ff3)

# FF3 performance benchmarks
add_executable(test_ff3_performance test_ff3_performance.c)
target_link_libraries(test_ff3_performance fpe unity m)
add_test(NAME test_ff3_performance COMMAND test_ff3_performance)

# FF3 multi-threading tests
add_executable(test_ff3_mt test_ff3_mt.c)
target_link_libraries(test_ff3_mt fpe unity m Threads::Threads)
add_test(NAME test_ff3_mt COMMAND test_ff3_mt)

# FF3-1 algorithm unit tests
add_executable(test_ff3-1 test_ff3-1.c)
target_link_libraries(test_ff3-1 fpe unity)
add_test(NAME test_ff3-1 COMMAND test_ff3-1)

# FF3-1 performance benchmarks
add_executable(test_ff3-1_performance test_ff3-1_performance.c)
target_link_libraries(test_ff3-1_performance fpe unity m)
add_test(NAME test_ff3-1_performance COMMAND test_ff3-1_performance)

# FF3-1 multi-threading tests
add_executable(test_ff3-1_mt test_ff3-1_mt.c)
target_link_libraries(test_ff3-1_mt fpe unity m Threads::Threads)
add_test(NAME test_ff3-1_mt COMMAND test_ff3-1_mt)

# SM4 support tests
add_executable(test_sm4 test_sm4.c)
target_link_libraries(test_sm4 fpe unity)
add_test(NAME test_sm4 COMMAND test_sm4)

# Public API tests (context lifecycle, dispatch, string API, in-place)
add_executable(test_api test_api.c)
target_link_libraries(test_api fpe unity)
add_test(NAME test_api COMMAND test_api)

# One-shot API tests
add_executable(test_oneshot test_oneshot.c)
target_link_libraries(test_oneshot fpe unity)
add_test(NAME test_oneshot COMMAND test_oneshot)

# One-shot vs context reuse performance benchmark
add_executable(test_oneshot_benchmark test_oneshot_benchmark.c)
target_link_libraries(test_oneshot_benchmark fpe unity m)
add_test(NAME test_oneshot_benchmark COMMAND test_oneshot_benchmark)

# Thread safety tests
add_executable(test_thread_safety test_thread_safety.c)
target_link_libraries(test_thread_safety fpe unity Threads::Threads)
add_test(NAME test_thread_safety COMMAND test_thread_safety)

# NIST test vector validation
add_executable(test_vectors test_vectors.c)
target_link_libraries(test_vectors fpe unity)
add_test(NAME test_vectors COMMAND test_vectors)

# OpenSSL version detection tests
add_executable(test_openssl_version test_openssl_version.c)
target_link_libraries(test_openssl_version fpe unity)
add_test(NAME test_openssl_version COMMAND test_openssl_version)

# Fuzzing tests for input validation
add_executable(test_fuzz test_fuzz.c)
target_link_libraries(test_fuzz fpe unity)
add_test(NAME test_fuzz COMMAND test_fuzz)

# Memory leak detection tests
add_executable(test_memory test_memory.c)
target_link_libraries(test_memory fpe unity)
add_test(NAME test_memory COMMAND test_memory)

# Property-based tests
add_executable(test_property test_property.c)
target_link_libraries(test_property fpe unity m)
add_test(NAME test_property COMMAND test_property)

# ABI stability tests
add_executable(test_abi test_abi.c)
target_link_libraries(test_abi fpe unity)
add_test(NAME test_abi COMMAND test_abi)
