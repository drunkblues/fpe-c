cmake_minimum_required(VERSION 3.10)
project(fpe-c VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTS "Build test suite" ON)
option(BUILD_EXAMPLES "Build examples" ON)
option(SANITIZE_ADDRESS "Enable AddressSanitizer" OFF)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Detect OpenSSL version for SM4 support
if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.0")
    message(STATUS "OpenSSL ${OPENSSL_VERSION} detected - Full SM4 support available")
    add_definitions(-DHAVE_OPENSSL_SM4)
elseif(OPENSSL_VERSION VERSION_GREATER_EQUAL "1.1.1")
    message(STATUS "OpenSSL ${OPENSSL_VERSION} detected - Experimental SM4 support")
    add_definitions(-DHAVE_OPENSSL_SM4_EXPERIMENTAL)
else()
    message(STATUS "OpenSSL ${OPENSSL_VERSION} detected - No SM4 support")
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
)

# AddressSanitizer support
if(SANITIZE_ADDRESS)
    message(STATUS "AddressSanitizer enabled")
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

# Source files
set(FPE_SOURCES
    src/fpe.c
    src/utils.c
    src/ff1.c
    src/ff3.c
    src/ff3-1.c
)

# Create library
add_library(fpe ${FPE_SOURCES})
target_link_libraries(fpe OpenSSL::Crypto m)  # Add math library

# Set library properties
set_target_properties(fpe PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER include/fpe.h
)

# Installation rules
install(TARGETS fpe
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

# pkg-config support
configure_file(
    ${CMAKE_SOURCE_DIR}/fpe.pc.in
    ${CMAKE_BINARY_DIR}/fpe.pc
    @ONLY
)
install(FILES ${CMAKE_BINARY_DIR}/fpe.pc
    DESTINATION lib/pkgconfig
)

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Examples
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
