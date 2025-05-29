# Performance Analyses of Parallel Prefix Adders in HE Scheme

A comprehensive benchmarking tool for testing different adder algorithms in a Fully Homomorphic Encryption (FHE) environment using the TFHE library. This repository compares the performance of various parallel prefix adders operating on encrypted data.

## Overview

This benchmark evaluates six different adder implementations:

- **BKA** - Brent-Kung Adder
- **HCA** - Han-Carlson Adder  
- **KSA** - Kogge-Stone Adder
- **LFA** - Ladner-Fischer Adder
- **SKA** - Sklansky Adder
- **RCA** - Ripple Carry Adder

All adders operate on encrypted integers using TFHE (Torus Fully Homomorphic Encryption) with configurable bit widths and OpenMP parallelization.

## Build Instructions

### Using the Makefile

```bash
# Normal incremental build
make

# Clean only
make clean
```

### Manual Compilation

```bash
g++ -fopenmp -o main main.cpp adders.cpp -ltfhe-spqlios-fma -lm
```

## Usage

```bash
./main <nb_bits> <num_threads>
```

### Parameters

- `nb_bits`: Number of bits for the encrypted integers (e.g., 8, 16, 32)
- `num_threads`: Number of OpenMP threads to use for parallel operations

### Example

```bash
# Compiling files
make

# Test with 16-bit integers using 8 threads
./main 16 8

# Test with 32-bit integers using 4 threads  
./main 32 4
```

## Sample Output

```
FHE operations will use nb_bits = 8
Attempting to use 8 OpenMP threads. Actual max threads available: 8
--------------------------------------------
Generating keys...
--------------------------------------------
Original Plaintext 1 (int16_t): 15
Original Plaintext 2 (int16_t): 42
--------------------------------------------
Encrypting plaintexts to 8 bits...
--------------------------------------------
Gate Benchmark:
Gate duration: 25.30 ms
--------------------------------------------
BKA elapsed time: 726 ms, ans: 57
HCA elapsed time: 563 ms, ans: 57
KSA elapsed time: 606 ms, ans: 57
LFA elapsed time: 630 ms, ans: 57
SKA elapsed time: 522 ms, ans: 57
RCA elapsed time: 1056 ms, ans: 57
--------------------------------------------
```

## Project Structure

```
.
├── main.cpp           # Main benchmark program
├── adders.c           # Adder implementations
├── adders.h           # Adder function declarations
├── Makefile           # Build configuration
└── README.md          # This file
```

## Implementation Details

### Security Parameters

- **Minimum Lambda**: 110 (security parameter)
- **Random Seed**: Fixed seed (314, 1592, 657) for reproducible results

### Encryption Process

1. Generate TFHE parameters and keys
2. Encrypt two 16-bit plaintexts (15 and 42) bit-by-bit
3. Perform homomorphic addition using various adder algorithms
4. Decrypt and verify results

### Performance Metrics

- **Gate Benchmark**: Measures single AND gate operation time
- **Adder Timing**: End-to-end execution time for each adder type
- **Verification**: Decrypts results to ensure correctness

## Configuration

### Compile-time Options

```cpp
#define NB_BITS 16        // Default bit width
#define NUM_THREADS 8     // Default thread count
```

### Makefile Configuration

```makefile
CC = g++                          # Compiler
CFLAGS = -fopenmp                 # Compiler flags
LDFLAGS = -ltfhe-spqlios-fma -lm  # Linker flags
```
