# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lcheck -lsodium -lsubunit -lm

# Directories
SRC_DIR = ../src
TEST_DIR = .
BUILD_DIR = build

# Source and object files

# NOTE EXPLICITLY: The following line excludes bogus_main.c from the list of source files.
SRC_FILES = $(filter-out $(SRC_DIR)/bogus_main.c, $(wildcard $(SRC_DIR)/*.c))

SRC_OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC_FILES))

# Test files and test binaries
TEST_FILES = $(wildcard $(TEST_DIR)/test_*.c)
TEST_BINS = $(patsubst $(TEST_DIR)/%.c, $(BUILD_DIR)/%, $(TEST_FILES))

# Default target
all: $(BUILD_DIR) $(TEST_BINS)

# Build object files from source
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Build test binaries from test sources and objects
$(BUILD_DIR)/%: $(TEST_DIR)/%.c $(SRC_OBJS)
	$(CC) $(CFLAGS) $< $(SRC_OBJS) -o $@ $(LDFLAGS)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Run tests
test: all
	@for test in $(TEST_BINS); do \
		echo "Running $$test..."; \
		$$test || exit 1; \
	done
	@echo "All tests passed!"

# Clean build directory
clean:
	rm -rf $(BUILD_DIR)

# Phony targets
.PHONY: all test clean
