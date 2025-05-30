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

num1 = 15
num2 = 42
nb_bits = 16
num_threads = 8
------------------------------------
BKA elapsed time: 848.4 ms, ans: 57
HCA elapsed time: 938.4 ms, ans: 57
KSA elapsed time: 1188.8 ms, ans: 57
LFA elapsed time: 844.0 ms, ans: 57
SKA elapsed time: 951.2 ms, ans: 57
RCA elapsed time: 1414.5 ms, ans: 57
------------------------------------
```