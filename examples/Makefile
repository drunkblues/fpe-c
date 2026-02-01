# Makefile for FPE-C Examples
# 
# Usage:
#   make          - Build all examples
#   make basic    - Build basic.c
#   make clean    - Remove built examples
#   make install  - Build and install examples (requires library installed)

CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lfpe

# Library paths (modify if installed elsewhere)
INCLUDE_DIR = ../include
LIB_DIR = ../build

# Use installed library by default, fallback to local build
CFLAGS += -I$(INCLUDE_DIR)

# Check if library is installed system-wide
ifeq ($(shell pkg-config --exists fpe && echo yes),yes)
    CFLAGS = $(shell pkg-config --cflags fpe)
    LDFLAGS = $(shell pkg-config --libs fpe)
else
    LDFLAGS = -L$(LIB_DIR) -lfpe -Wl,-rpath,$(LIB_DIR)
endif

# Example targets
EXAMPLES = basic oneshot credit_card custom_alphabet sm4 inplace compare errors ff3-1 threads benchmark benchmark_mt aes_vs_sm4

all: $(EXAMPLES)

basic: basic.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@
	@echo "✓ Built $@"

credit_card: credit_card.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

custom_alphabet: custom_alphabet.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

oneshot: oneshot.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

sm4: sm4.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

inplace: inplace.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

compare: compare.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

errors: errors.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

ff3-1: ff3-1.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

threads: threads.c
	$(CC) $(CFLAGS) -pthread $< $(LDFLAGS) -o $@

benchmark: benchmark.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

benchmark_mt: benchmark_mt.c
	$(CC) $(CFLAGS) -pthread -I../tests $< ../tests/pthread_barrier_compat.c $(LDFLAGS) -o $@

aes_vs_sm4: aes_vs_sm4.c
	$(CC) $(CFLAGS) -pthread -I../tests $< ../tests/pthread_barrier_compat.c $(LDFLAGS) -o $@

# Clean up
clean:
	rm -f $(EXAMPLES)
	@echo "✓ Cleaned examples"

.PHONY: all run clean
