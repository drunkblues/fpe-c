# Convenience Makefile wrapper for CMake

# Build directory
BUILD_DIR ?= build

.PHONY: all build clean install test examples help
.PHONY: debug release test-% run-example-% memcheck format

all: build

# Configure and build
build:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake .. && $(MAKE)

# Clean build artifacts
clean:
	@rm -rf $(BUILD_DIR)
	@cd examples && $(MAKE) clean 2>/dev/null || true

# Install library and headers
install: build
	@cd $(BUILD_DIR) && $(MAKE) install

# Uninstall library
uninstall:
	@cd $(BUILD_DIR) && $(MAKE) uninstall 2>/dev/null || true

# Run all tests
test: build
	@cd $(BUILD_DIR) && ctest --output-on-failure

# Run specific test (e.g., make test-ff1)
test-%: build
	@cd $(BUILD_DIR) && ./tests/test_$*

# Build examples
examples: build
	@cd examples && $(MAKE)

# Run specific example (e.g., make run-example-basic)
run-example-%: examples
	@cd examples && ./build/$*

# Build in debug mode
debug:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=Debug .. && $(MAKE)

# Build in release mode
release:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && cmake -DCMAKE_BUILD_TYPE=Release .. && $(MAKE)

# Run memory leak check with valgrind (requires valgrind)
memcheck: debug
	@cd $(BUILD_DIR) && valgrind --leak-check=full --show-leak-kinds=all \
		--track-origins=yes ./tests/test_basic

# Format code with clang-format (requires clang-format)
format:
	@find src include tests -name '*.c' -o -name '*.h' | xargs clang-format -i 2>/dev/null || \
		echo "clang-format not available"

# Show help
help:
	@echo "FPE-C Library Build System"
	@echo ""
	@echo "Common targets:"
	@echo "  make              - Build the library (default)"
	@echo "  make build        - Build library and tests"
	@echo "  make test         - Run all tests"
	@echo "  make test-<name>  - Run specific test (e.g., make test-ff1)"
	@echo "  make examples     - Build examples"
	@echo "  make run-example-<name> - Run specific example"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make install      - Install library and headers"
	@echo "  make uninstall    - Uninstall library"
	@echo ""
	@echo "Build modes:"
	@echo "  make debug        - Build in debug mode"
	@echo "  make release      - Build in release mode"
	@echo ""
	@echo "Testing and validation:"
	@echo "  make memcheck     - Run memory leak check (requires valgrind)"
	@echo "  make format       - Format code (requires clang-format)"
	@echo ""
	@echo "Configuration:"
	@echo "  BUILD_DIR=<dir>   - Set build directory (default: build)"
