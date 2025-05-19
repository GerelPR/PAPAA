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

There are generally two ways to install TFHE:

**Option A: Using a Package Manager (If Available)**

Some Linux distributions or package managers (like Homebrew for macOS) might offer pre-compiled TFHE packages. This is often the easiest method.

*   **Example (Hypothetical - check your system's package manager):**
    ```bash
    # For Debian/Ubuntu - This is an EXAMPLE, TFHE might not be in default repos directly.
    # You might need to add a PPA or find a specific package name.
    # sudo apt-get install libtfhe-dev

    # For macOS with Homebrew - TFHE might be available via a custom tap.
    # brew tap <some-tfhe-tap>
    # brew install tfhe-spqlios-fma
    ```
    *You will need to research if a pre-built package is available for your specific operating system and TFHE variant (`tfhe-spqlios-fma`).*

**Option B: Compiling TFHE from Source (Most Common and Flexible)**

This method gives you the most control and ensures you have the exact version you need. The TFHE project usually provides detailed instructions on its official GitHub repository.

1.  **Clone the TFHE repository:**
    Find the official TFHE repository (e.g., on GitHub, search for "TFHE library"). The specific repository for `tfhe-spqlios-fma` might be a particular fork or version. For example:
    ```bash
    git clone https://github.com/tfhe/tfhe.git # Or the specific repo for tfhe-spqlios-fma
    cd tfhe
    ```

2.  **Checkout a stable version/tag (Recommended):**
    It's often best to use a tagged release rather than the bleeding edge of the main branch.
    ```bash
    git checkout v1.1 # Replace v1.1 with the desired stable tag
    ```

3.  **Build and Install using CMake:**
    The general CMake process is:
    ```bash
    mkdir build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release # Or RelWithDebInfo for debugging symbols
    # You might need to specify an install prefix if you don't want to install system-wide:
    # cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/path/to/your/local/install
    make -j$(nproc) # Use multiple cores for faster compilation
    sudo make install # Installs to system directories (e.g., /usr/local)
                      # Or just 'make install' if you used CMAKE_INSTALL_PREFIX for a local install
    ```

    *   **Important Flags for CMake:**
        *   `-DENABLE_SPQLIOS_FMA=ON`: Ensure this option (or similar, depending on the TFHE version) is enabled if you specifically need the `spqlios-fma` backend. It might be enabled by default in relevant TFHE forks.
        *   `-DENABLE_TESTS=ON` (optional): To build and run TFHE's own tests.
        *   `-DENABLE_BENCHMARKS=ON` (optional): To build TFHE's benchmarks.

4.  **Update Library Path (if installed locally or to a non-standard location):**
    If you installed TFHE to a custom location using `CMAKE_INSTALL_PREFIX`, you'll need to tell your system where to find the shared libraries:
    ```bash
    export LD_LIBRARY_PATH=/path/to/your/local/install/lib:$LD_LIBRARY_PATH
    ```
    And for the compiler to find headers:
    ```bash
    export CPLUS_INCLUDE_PATH=/path/to/your/local/install/include:$CPLUS_INCLUDE_PATH
    export C_INCLUDE_PATH=/path/to/your/local/install/include:$C_INCLUDE_PATH
    ```
    It's often better to add these `export` lines to your shell's configuration file (e.g., `~/.bashrc`, `~/.zshrc`) to make them permanent.
    Alternatively, when compiling your project, you can use `-I/path/to/your/local/install/include` for includes and `-L/path/to/your/local/install/lib` for linking.

### 3. Verifying TFHE Installation

After installation, you can try to compile a small TFHE example program (often provided with the TFHE library) to ensure your compiler and linker can find the library and its headers.

### 4. Project Compilation
Once TFHE is correctly installed and your environment is set up, you can proceed to the "Compilation Instructions" section of this README to build this specific project. The Makefile in this project assumes that `tfhe.h` is in a standard include path and `libtfhe-spqlios-fma` can be found by the linker (e.g., via `pkg-config` if TFHE provides a `.pc` file, or because it's in a standard library directory).

If you encounter issues during the compilation of *this* project (the one with `alice.c`, `cloud.c`), it usually means TFHE was not installed correctly or your compiler/linker cannot find it. You may need to adjust `CFLAGS` or `LDFLAGS` in this project's `Makefile` to point to your TFHE installation if it's in a non-standard location (e.g., by adding `-I/path/to/tfhe/include` and `-L/path/to/tfhe/lib`).

---