CC ?= cc

# Use only this repository by default.
# Build liboqs first so these files exist:
#   ./build/lib/liboqs.a
#   ./build/lib/liboqs-internal.a
OQS_BUILD_DIR ?= ./build

BUILD_DIR := build/tests
OBJ_DIR := $(OQS_BUILD_DIR)/obj
LIB_DIR := $(OQS_BUILD_DIR)/lib

CFLAGS ?= -std=gnu11 -O3 -fPIE -fvisibility=hidden -Wa,--noexecstack -Wbad-function-cast -fdata-sections -ffunction-sections
CPPFLAGS ?= -I./include -I./include/oqs -I./src -I$(OQS_BUILD_DIR)/include
LDFLAGS ?= -Wl,-z,noexecstack
LDLIBS ?= $(LIB_DIR)/liboqs.a \
          $(LIB_DIR)/liboqs-internal.a \
          -lm -lcrypto -lpthread

KAT_COMMON_OBJS := $(BUILD_DIR)/test_helpers.o
OQS_SRC_C := $(shell find src -type f -name '*.c')
OQS_SRC_C := $(filter-out src/sig_stfl/%,$(OQS_SRC_C))
OQS_SRC_C := $(filter-out src/minimal/sig_minimal.c,$(OQS_SRC_C))
OQS_SRC_C := $(filter-out src/sig/haetae/haetae_ref/benchmark/%,$(OQS_SRC_C))
OQS_SRC_C := $(filter-out src/sig/haetae/haetae_ref/kat/%,$(OQS_SRC_C))
OQS_SRC_C := $(filter-out src/sig/haetae/haetae_ref/test/%,$(OQS_SRC_C))
OQS_SRC_C := $(filter-out src/sig/haetae/haetae_ref/src/randombytes.c,$(OQS_SRC_C))
OQS_SRC_C := $(filter-out src/common/sha3/xkcp_low/KeccakP-1600times4/avx2/%,$(OQS_SRC_C))
OQS_SRC_C := $(filter-out src/common/sha3/xkcp_low/KeccakP-1600/avx2/%,$(OQS_SRC_C))
OQS_OBJ := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(OQS_SRC_C))
OQS_DEP := $(OQS_OBJ:.o=.d)
OQS_LIB := $(LIB_DIR)/liboqs.a
OQS_INTERNAL_LIB := $(LIB_DIR)/liboqs-internal.a

.PHONY: all oqs_libs kat_kem kat_sig clean

all: kat_kem kat_sig

oqs_libs: $(OQS_LIB) $(OQS_INTERNAL_LIB)

kat_kem: $(OQS_LIB) $(OQS_INTERNAL_LIB) $(BUILD_DIR)/kat_kem.o $(KAT_COMMON_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(LDFLAGS) -o $(BUILD_DIR)/$@ $^ $(LDLIBS)

kat_sig: $(OQS_LIB) $(OQS_INTERNAL_LIB) $(BUILD_DIR)/kat_sig.o $(KAT_COMMON_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(LDFLAGS) -o $(BUILD_DIR)/$@ $^ $(LDLIBS)

$(OQS_LIB): $(OQS_OBJ)
	@mkdir -p $(LIB_DIR)
	ar rcs $@ $^

# Keep internal archive local and explicit so tests can link with upstream-like shape.
$(OQS_INTERNAL_LIB):
	@mkdir -p $(LIB_DIR)
	ar rcs $@

$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(EXTRA_CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

# Per-directory config for ml-dsa-native reference implementations.
$(OBJ_DIR)/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/ml-dsa/src/%.o: EXTRA_CPPFLAGS += -DMLD_CONFIG_FILE=\"../../integration/liboqs/config_c.h\" -DMLD_CONFIG_PARAMETER_SET=44
$(OBJ_DIR)/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/ml-dsa/src/%.o: EXTRA_CPPFLAGS += -DMLD_CONFIG_FILE=\"../../integration/liboqs/config_c.h\" -DMLD_CONFIG_PARAMETER_SET=65
$(OBJ_DIR)/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/ml-dsa/src/%.o: EXTRA_CPPFLAGS += -DMLD_CONFIG_FILE=\"../../integration/liboqs/config_c.h\" -DMLD_CONFIG_PARAMETER_SET=87
$(OBJ_DIR)/sig/ml_dsa/mldsa-native_ml-dsa-44_ref/mldsa/src/%.o: EXTRA_CPPFLAGS += -DMLD_CONFIG_FILE=\"../../integration/liboqs/config_c.h\" -DMLD_CONFIG_PARAMETER_SET=44
$(OBJ_DIR)/sig/ml_dsa/mldsa-native_ml-dsa-65_ref/mldsa/src/%.o: EXTRA_CPPFLAGS += -DMLD_CONFIG_FILE=\"../../integration/liboqs/config_c.h\" -DMLD_CONFIG_PARAMETER_SET=65
$(OBJ_DIR)/sig/ml_dsa/mldsa-native_ml-dsa-87_ref/mldsa/src/%.o: EXTRA_CPPFLAGS += -DMLD_CONFIG_FILE=\"../../integration/liboqs/config_c.h\" -DMLD_CONFIG_PARAMETER_SET=87

# HAETAE reference implementation, mode 2 exposed as "HAETAE".
$(OBJ_DIR)/sig/haetae/haetae_ref/src/%.o: CPPFLAGS := -I./include -I./src/sig/haetae/haetae_ref/include -I./include/oqs -I./src -I$(OQS_BUILD_DIR)/include
$(OBJ_DIR)/sig/haetae/haetae_ref/src/%.o: EXTRA_CPPFLAGS += -DHAETAE_MODE=2
$(OBJ_DIR)/sig/haetae/sig_haetae.o: CPPFLAGS := -I./include -I./src/sig/haetae/haetae_ref/include -I./include/oqs -I./src -I$(OQS_BUILD_DIR)/include
$(OBJ_DIR)/sig/haetae/sig_haetae.o: EXTRA_CPPFLAGS += -DHAETAE_MODE=2

# Per-directory config for mlkem-native reference implementations.
$(OBJ_DIR)/kem/ml_kem/mlkem-native_ml-kem-512_ref/mlkem/src/%.o: EXTRA_CPPFLAGS += -DMLK_CONFIG_FILE=\"../../integration/liboqs/config_c.h\" -DMLK_CONFIG_PARAMETER_SET=512
$(OBJ_DIR)/kem/ml_kem/mlkem-native_ml-kem-768_ref/mlkem/src/%.o: EXTRA_CPPFLAGS += -DMLK_CONFIG_FILE=\"../../integration/liboqs/config_c.h\" -DMLK_CONFIG_PARAMETER_SET=768
$(OBJ_DIR)/kem/ml_kem/mlkem-native_ml-kem-1024_ref/mlkem/src/%.o: EXTRA_CPPFLAGS += -DMLK_CONFIG_FILE=\"../../integration/liboqs/config_c.h\" -DMLK_CONFIG_PARAMETER_SET=1024

# x86 AES-NI sources require explicit CPU feature flags.
$(OBJ_DIR)/common/aes/aes128_ni.o: CFLAGS += -maes -mssse3
$(OBJ_DIR)/common/aes/aes256_ni.o: CFLAGS += -maes -mssse3
$(OBJ_DIR)/common/sha3/xkcp_low/KeccakP-1600times4/avx2/KeccakP-1600-times4-SIMD256.o: CFLAGS += -mavx2 -maes -mssse3
$(OBJ_DIR)/common/sha3/xkcp_low/KeccakP-1600times4/avx2/KeccakP-1600-times4-SIMD256.o: EXTRA_CPPFLAGS += -I./src/common/sha3/xkcp_low/KeccakP-1600/avx2

# Force SHA3 backend to plain/serial path for local reduced build.
$(OBJ_DIR)/common/sha3/xkcp_sha3.o: EXTRA_CPPFLAGS += -DOQS_USE_SHA3_AVX512VL=0 -DOQS_ENABLE_SHA3_xkcp_low_avx2=0
$(OBJ_DIR)/common/sha3/xkcp_sha3x4.o: EXTRA_CPPFLAGS += -DOQS_USE_SHA3_AVX512VL=0 -DOQS_ENABLE_SHA3_xkcp_low_avx2=0
$(OBJ_DIR)/common/sha3/xkcp_low/KeccakP-1600/plain-64bits/KeccakP-1600-opt64.o: EXTRA_CPPFLAGS += -DADD_SYMBOL_SUFFIX
$(OBJ_DIR)/common/sha3/xkcp_low/KeccakP-1600times4/serial/KeccakP-1600-times4-on1.o: EXTRA_CPPFLAGS += -DADD_SYMBOL_SUFFIX

$(BUILD_DIR)/kat_kem.o: tests/kat_kem.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/kat_sig.o: tests/kat_sig.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/test_helpers.o: tests/test_helpers.c tests/test_helpers.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(OBJ_DIR) $(LIB_DIR)

-include $(OQS_DEP)
