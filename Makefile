# Compiler and flags
CC = gcc
CFLAGS_BASE = -Wall -Wextra -g # Base CFLAGS, -g for debugging
OMP_FLAGS = -fopenmp         # OpenMP flag for the computation program
LIBS = -ltfhe-spqlios-fma -lm # Common libraries for both

NB_BITS ?= 16
NUM_THREADS ?= 4
OPERATION_CHOICE ?= 5

CFLAGS_CLOUD = $(CFLAGS_BASE) $(OMP_FLAGS) \
               -DNB_BITS_FROM_MAKEFILE=$(NB_BITS) \
               -DNUM_THREADS_FROM_MAKEFILE=$(NUM_THREADS) \
               -DOPERATION_CHOICE_FROM_MAKEFILE=$(OPERATION_CHOICE)

# --- Configurable variables for Alice's program ---
ENC_NB_BITS ?= $(NB_BITS) # For Alice's program, defaults to cloud's NB_BITS

# CFLAGS for Alice's program
CFLAGS_ALICE = $(CFLAGS_BASE) # Alice's program takes nb_bits via argv

# --- Source Locations ---
SRC_DIR = ./src

# --- Target Definitions ---
# Cloud Program
CLOUD_SRC_FILE_BASENAME = cloud.c
CLOUD_TARGET = cloud

# Alice's Program
ALICE_SRC_FILE_BASENAME = alice.c
ALICE_TARGET = alice             # This target means "build alice executable"

# Verification Program
VERIFY_SRC_FILE_BASENAME = verif.c
VERIFY_TARGET = verif            # This target means "build verif executable"

# Default target
all: $(CLOUD_TARGET)

# --- Build Rules ---

# Rule to compile Cloud's Program
$(CLOUD_TARGET): $(SRC_DIR)/$(CLOUD_SRC_FILE_BASENAME)
	@echo "Compiling Cloud Program ($(SRC_DIR)/$(CLOUD_SRC_FILE_BASENAME)) with NB_BITS=$(NB_BITS), NUM_THREADS=$(NUM_THREADS), OPERATION_CHOICE=$(OPERATION_CHOICE)"
	$(CC) $(CFLAGS_CLOUD) $(SRC_DIR)/$(CLOUD_SRC_FILE_BASENAME) -o $@ $(LDFLAGS) $(LIBS)

# Rule to compile Alice's Program
$(ALICE_TARGET): $(SRC_DIR)/$(ALICE_SRC_FILE_BASENAME)
	@echo "Compiling Alice's Program ($(SRC_DIR)/$(ALICE_SRC_FILE_BASENAME))"
	$(CC) $(CFLAGS_ALICE) $(SRC_DIR)/$(ALICE_SRC_FILE_BASENAME) -o $@ $(LDFLAGS) $(LIBS)

# Rule to compile Verification Program
$(VERIFY_TARGET): $(SRC_DIR)/$(VERIFY_SRC_FILE_BASENAME)
	@echo "Compiling Verification Program ($(SRC_DIR)/$(VERIFY_SRC_FILE_BASENAME))"
	$(CC) $(CFLAGS_BASE) $(SRC_DIR)/$(VERIFY_SRC_FILE_BASENAME) -o $@ $(LDFLAGS) $(LIBS)

# 'compile_alice' target now just ensures Alice's executable is built
# and gives instructions. It no longer runs it automatically.
compile_alice: $(ALICE_TARGET)
	@echo "Alice's program ($(ALICE_TARGET)) is compiled."
	@echo "To generate data, run: ./$(ALICE_TARGET) <number_of_bits>"
	@echo "For example, for $(ENC_NB_BITS) bits: ./$(ALICE_TARGET) $(ENC_NB_BITS)"

# 'compile_verif' target now just ensures Verif's executable is built
# and gives instructions. It no longer runs it automatically.
# This matches the behavior you wanted for generate_data.
compile_verif: $(VERIFY_TARGET)
	@echo "Verification program ($(VERIFY_TARGET)) is compiled."
	@echo "To run verification, use: ./$(VERIFY_TARGET) <number_of_bits>"
	@echo "For example, for $(NB_BITS) bits (matching cloud computation): ./$(VERIFY_TARGET) $(NB_BITS)"

# --- Cleanup ---
clean:
	@echo "Cleaning up..."
	rm -f $(CLOUD_TARGET) $(ALICE_TARGET) $(VERIFY_TARGET)
	rm -f cloud.key secret.key cloud.data answer.data

# Phony targets
.PHONY: all clean generate_data run_verify