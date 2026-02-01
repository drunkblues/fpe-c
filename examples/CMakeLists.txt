# Examples CMakeLists.txt

# Find pthread for multi-threaded examples
find_package(Threads REQUIRED)

# Basic examples
add_executable(basic basic.c)
target_link_libraries(basic fpe)

add_executable(oneshot oneshot.c)
target_link_libraries(oneshot fpe)

add_executable(credit_card credit_card.c)
target_link_libraries(credit_card fpe)

add_executable(custom_alphabet custom_alphabet.c)
target_link_libraries(custom_alphabet fpe)

add_executable(sm4 sm4.c)
target_link_libraries(sm4 fpe)

add_executable(inplace inplace.c)
target_link_libraries(inplace fpe)

add_executable(compare compare.c)
target_link_libraries(compare fpe)

add_executable(errors errors.c)
target_link_libraries(errors fpe)

add_executable(ff3-1 ff3-1.c)
target_link_libraries(ff3-1 fpe)

# Multi-threaded examples
add_executable(threads threads.c)
target_link_libraries(threads fpe Threads::Threads)

# Performance benchmarks
add_executable(benchmark benchmark.c)
target_link_libraries(benchmark fpe)

add_executable(benchmark_mt benchmark_mt.c)
target_include_directories(benchmark_mt PRIVATE ${CMAKE_SOURCE_DIR}/tests)
target_sources(benchmark_mt PRIVATE ../tests/pthread_barrier_compat.c)
target_link_libraries(benchmark_mt fpe Threads::Threads)

add_executable(aes_vs_sm4 aes_vs_sm4.c)
target_include_directories(aes_vs_sm4 PRIVATE ${CMAKE_SOURCE_DIR}/tests)
target_sources(aes_vs_sm4 PRIVATE ../tests/pthread_barrier_compat.c)
target_link_libraries(aes_vs_sm4 fpe Threads::Threads)
