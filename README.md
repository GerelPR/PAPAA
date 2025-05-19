# PAPAA


During the build process and execution, executables (`alice`, `cloud`, `verif`) and data files (`secret.key`, `cloud.key`, `cloud.data`, `answer.data`) will be created in the project's root directory.

## Compilation Instructions

A single `Makefile` orchestrates the compilation of all necessary programs. Open your terminal in the project's root directory (where the `Makefile` is located) to run these commands.

### 1. Compiling Alice's Program (`alice`)
This program is responsible for generating cryptographic keys and encrypting the initial plaintexts.

*   **To compile `alice.c` into an executable named `alice`:**
    ```bash
    make compile_alice
    ```

### 2. Compiling the Cloud's Program (`cloud`)
This program performs the homomorphic computations. It is highly configurable at compile-time.

*   **To compile `cloud.c` into an executable named `cloud` with specific parameters:**
    ```bash
    make NB_BITS=<bits> NUM_THREADS=<threads> OPERATION_CHOICE=<choice_num>
    ```
    **Parameters:**
    *   `NB_BITS=<bits>`: Specifies the number of bits for the operands in homomorphic operations (e.g., 8, 16, 32, 64). This value **must** be consistent with the bit-width used by Alice during data encryption. *Default: 16 if not specified.*
    *   `NUM_THREADS=<threads>`: Sets the number of OpenMP threads to be used for parallel regions within the cloud computations (e.g., 1, 2, 4, 8). *Default: 4 if not specified.*
    *   `OPERATION_CHOICE=<choice_num>`: An integer selecting the specific homomorphic operation or benchmark to be performed. *Default: 11 (Han-Carlson Subtractor) if not specified.*
        The available choices are:
        *   `1`: Minimum
        *   `2`: Ripple Adder
        *   `3`: Brent-Kung Adder
        *   `4`: Kogge-Stone Adder
        *   `5`: Sklansky Adder
        *   `6`: Han-Carlson Adder
        *   `7`: Ripple Subtractor
        *   `8`: Brent-Kung Subtractor
        *   `9`: Kogge-Stone Subtractor
        *   `10`: Sklansky Subtractor
        *   `11`: Han-Carlson Subtractor
        *   `12`: Ladner-Fischer Adder
        *   `13`: Ladner-Fischer Subtractor

    **Example:** To compile the cloud program for 32-bit Kogge-Stone Addition using 8 threads:
    ```bash
    make NB_BITS=32 NUM_THREADS=8 OPERATION_CHOICE=4
    ```
    If you simply run `make`, the `cloud` program will be compiled using the default parameter values defined in the `Makefile`.

### 3. Compiling the Verification Program (`verif`)
This program is used by Alice to decrypt the encrypted results received from the cloud.

*   **To compile `verif.c` into an executable named `verif`:**
    ```bash
    make verif
    ```
*   **To compile `verif` and view instructions on how to run it:**
    ```bash
    make compile_verif
    ```
    (Note: `make compile_verif` only compiles `verif` and prints usage instructions; it does not execute `verif`.)

## Running the Programs: A Step-by-Step Workflow

This section outlines the complete workflow from Alice generating data, the Cloud processing it, and Alice verifying the result.

**Important:** The `NB_BITS` parameter used by Alice for encryption **must** match the `NB_BITS` used when compiling and running the Cloud program, and subsequently when Alice runs the verification program.

**Example Scenario:**
*   **Bit-width:** 32 bits
*   **Cloud Operation:** Brent-Kung Adder (Operation Choice: `3`)
*   **Cloud Threads:** 8

### Step 1: Clean Project (Optional)
It's good practice to start with a clean state, especially if you are changing parameters.
```bash
make clean
```

This command removes all previously compiled executables and generated data files.

### Step 2: Alice - Key Generation and Data Encryption

In this step, Alice generates her cryptographic keys and encrypts her plaintext data.

1.  **Ensure Alice's program is compiled:**
    If you haven't compiled `alice` yet, or if you made changes to `src/alice.c`, compile it:
    ```bash
    make compile_alice
    ```
    *(Alternatively, `make compile_alice` also compiles `alice` and prints usage instructions.)*

2.  **Run Alice's program to generate keys and encrypt data:**
    Execute the compiled `alice` program from your terminal. Provide the desired number of bits for encryption as a command-line argument. For our 32-bit example:
    ```bash
    ./alice 32
    ```
    When this command runs, `alice.c` will perform the following:
    *   Use 32 bits for its internal operations, including encrypting its predefined plaintext values (e.g., 55 and 15, which are currently hardcoded in `src/alice.c`).
    *   **Output Files:**
        *   `secret.key`: This file contains Alice's private secret key. **Alice must keep this file secure and private.** It is required for decrypting the final result.
        *   `cloud.key`: This file contains the public cloud key. This key allows the cloud to perform homomorphic operations but does not allow it to decrypt data. This file is intended to be sent to the Cloud.
        *   `cloud.data`: This file contains the encrypted versions of Alice's initial plaintext numbers. This is also sent to the Cloud for computation.

    After execution, you should see confirmation messages from the `alice` program, and the three files (`secret.key`, `cloud.key`, `cloud.data`) will be present in your project's root directory.

    *(At this point, in a real-world scenario, Alice would securely transmit `cloud.key` and `cloud.data` to the Cloud service.)*

### Step 3: Cloud - Homomorphic Computation

The Cloud now receives `cloud.key` and `cloud.data` from Alice and performs the requested computation homomorphically.

1.  **Compile the Cloud's program with parameters matching Alice's data and the desired operation:**
    For our example (32 bits, 8 threads, Brent-Kung Adder op 3):
    ```bash
    make NB_BITS=32 NUM_THREADS=8 OPERATION_CHOICE=3
    ```
    This command compiles `src/cloud.c` into an executable named `cloud`, embedding the specified parameters.

2.  **Run the Cloud's program:**
    Ensure `cloud.key` and `cloud.data` (generated by Alice in Step 2) are in the same directory. Then, execute the compiled `cloud` program:
    ```bash
    ./cloud
    ```
    When this command runs, the `cloud` program will:
    *   Load `cloud.key` (the public cloud key).
    *   Load `cloud.data` (the encrypted inputs from Alice).
    *   Perform the homomorphic computation specified during its compilation (e.g., Brent-Kung addition on the encrypted 32-bit inputs).
    *   **Output File:**
        *   `answer.data`: This file contains the encrypted 32-bit result of the computation.

    You should see output from the `cloud` program indicating the operation being performed and potentially timing information.

    *(In a real-world scenario, the Cloud service would then send `answer.data` back to Alice.)*

### Step 4: Alice (Verification) - Decrypt and Verify Result

Alice receives `answer.data` from the Cloud and uses her secret key to decrypt it.

1.  **Ensure Alice's verification program is compiled:**
    If you haven't compiled `verif` yet, or if you made changes to `src/verif.c`, compile it:
    ```bash
    make compile_verif
    ```
    *(Alternatively, `make compile_verif` also compiles `verif` and prints usage instructions.)*

2.  **Run the verification program to decrypt the result:**
    Execute the compiled `verif` program. Provide the number of bits that were used for the computation (which must match the `NB_BITS` used by the Cloud and Alice) as a command-line argument.
    ```bash
    ./verif 32
    ```
    When this command runs, the `verif` program will:
    *   Load `secret.key` (Alice's private key).
    *   Load `answer.data` (the encrypted result from the Cloud).
    *   Decrypt the 32-bit encrypted result.
    *   Print the final plaintext value to the console.

This completes the full cycle of homomorphic encryption, computation, and decryption. You can repeat this process with different bit-widths, operations, or plaintext values to experiment further.

## Setup Instructions

Before you can compile and run this project, you need to have the TFHE library and its dependencies installed on your system.

### 1. Prerequisites for TFHE

The TFHE library typically has the following dependencies:

*   **A C/C++ Compiler:** GCC (version 5 or newer recommended) or Clang.
*   **CMake:** Version 3.5 or newer (if compiling TFHE from source).
*   **FFTW3:** (Fastest Fourier Transform in the West) library, version 3.3 or newer. This is crucial for performance.
    *   On Debian/Ubuntu: `sudo apt-get install libfftw3-dev libfftw3-double3`
    *   On macOS (using Homebrew): `brew install fftw`
    *   On other systems, refer to FFTW3 installation guides.
*   **Boost Libraries:** (Sometimes required, depending on the TFHE version or specific modules, though often not for the core functionalities used here). Check the specific TFHE version's documentation if you encounter issues.
*   **OpenMP:** For parallel processing. Usually included with modern GCC/Clang compilers.

### 2. Installing the TFHE Library

https://tfhe.github.io/tfhe/installation.html