# Performance Analyses of Parallel Prefix Adders in HE Scheme

Homomorphic implementations of the following adders using the TFHE library.

- **BKA** - Brent-Kung Adder
- **HCA** - Han-Carlson Adder  
- **KSA** - Kogge-Stone Adder
- **LFA** - Ladner-Fischer Adder
- **SKA** - Sklansky Adder
- **RCA** - Ripple Carry Adder


## Requirement
[TFHE](https://tfhe.github.io/)<br>
OpenMP

## Compile

```bash
make
```
## Run

```bash
./main <num1> <num2> <nb_bits> <num_threads>
```

- `num1` and `num2`: Integers to be added
- `nb_bits`: Bit length
- `num_threads`: Number of cores

## Sample run

```bash
# Compile
make

# Test with 16-bit integers using 8 threads
./main 15 42 16 8

## Sample Output

FHE operations will use nb_bits = 16
Using 8 OpenMP threads.Plaintext 1: 5, Plaintext 2: 8
--------------------------------------------
BKA elapsed time: 1533.7 ms, ans: 13
HCA elapsed time: 1323.3 ms, ans: 13
KSA elapsed time: 1757.3 ms, ans: 13
LFA elapsed time: 1353.9 ms, ans: 13
SKA elapsed time: 1450.0 ms, ans: 13
RCA elapsed time: 2051.5 ms, ans: 13
--------------------------------------------
```