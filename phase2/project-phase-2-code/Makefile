# DO NOT SUBMIT THIS FILE
#
# When submitting your project, this file will be overwritten
# by the automated build and test system.

###
# Variables
# (can be overridden from command-line)

CC = gcc

SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin

# The target executable.
# This executable is created by linking together all object files
# obtained from a .c file in the `src` directory; so exactly one
# .c file should contain a `main` function.
# Alternative implementations of main can be wrapped in #ifdefs, as
# long as exactly one is compiled; then they can be selected by
# supplying `-D` flags to `make` and thence to the compiler.
# See e.g. `alternate_main.c`
TARGET = $(BIN_DIR)/app

TS_FILES := $(shell find $(SRC_DIR) -name "*.ts")

SRC_FILES := $(shell find $(SRC_DIR) -name "*.c") $(TS_FILES:.ts=.c)

OBJ_FILES := $(SRC_FILES:.c=.o)
# we need to uniq-ify object files to stop .ts and .c versions of tests showing up twice
OBJ_FILES := $(shell echo $(subst $(SRC_DIR),$(BUILD_DIR),$(OBJ_FILES)) | tr ' ' '\n' | sort | uniq)


SRC_DIRS := $(shell find $(SRC_DIR) -type d)
INC_FLAGS := $(addprefix -I, $(SRC_DIRS))

# get compiler flags for installed libraries using pkg-config.
PKG_DEPS := $(shell cat libraries.txt | grep -v "^\#" | xargs)

# Set PKG_CFLAGS to empty if no dependencies are found, otherwise
# use pkg-config to get the compiler flags for the dependencies
PKG_CFLAGS := $(if $(strip $(PKG_DEPS)),$(shell pkg-config --cflags $(PKG_DEPS)))

# Set PKG_LDFLAGS to empty if no dependencies are found, otherwise
# use pkg-config to get the linker flags for the dependencies
PKG_LDFLAGS := $(if $(strip $(PKG_DEPS)),$(shell pkg-config --libs $(PKG_DEPS)))

# You may wish to add additional compiler flags or linker flags here
# (e.g. to change the optimization level, enable sanitizers, etc.)
# This is helpful when testing your code locally, even though we will
# not necessarily use the same flags when testing your code.
DEBUG = -g -fno-omit-frame-pointer
SECURE_FLAGS = -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2 -fno-common
SANITIZERS = -fsanitize=address,undefined
WARNINGS = -Wall -Wextra -pedantic-errors -Wshadow -Wconversion -Wformat=2 \
           -Wcast-align -Wpointer-arith -Wstrict-overflow=5 -Wswitch-enum \
           -Wunreachable-code -Winit-self -Wfloat-equal -Wundef \
           -Wbad-function-cast -Wcast-qual -Wwrite-strings \
           -Wlogical-op -Wredundant-decls -Wold-style-definition \
           -Wmissing-prototypes -Wstrict-prototypes -Wno-unused-result \
           -Werror=vla -Werror=implicit-function-declaration

CFLAGS = $(DEBUG) -std=c11 $(WARNINGS) $(SECURE_FLAGS) $(SANITIZERS) \
         $(INC_FLAGS) $(PKG_CFLAGS) -O2 # -O0 -O1 -O2 -O3 -Os

LDFLAGS = -Wl,-z,relro,-z,now -pie $(PKG_LDFLAGS)

# how to make a .c file from a .ts file
%.c: %.ts
	checkmk $< > $@

###
# Targets

all: $(TARGET)

# Link executable
$(TARGET): $(OBJ_FILES)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(OBJ_FILES) -o $(TARGET) $(LDFLAGS)

# Compile source files

# c
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	./add_banned_header.pl $<
	$(CC) $(CFLAGS) $(INC_FLAGS) -MMD -MP -c $< -o $@

# targets for each object file
$(foreach obj_file,$(OBJ_FILES),$(eval $(obj_file):))

# Install dependencies
install-dependencies:
	cat apt-packages.txt | sudo ./scripts/install-deps.sh

clean:
	rm -rf $(BUILD_DIR) $(TARGET) src/check*.c src/*.BAK src/*.NEW

.PHONY: all clean

.DELETE_ON_ERROR:

# Include automatically generated dependency files (.d)
-include $(OBJ_FILES:.o=.d)

