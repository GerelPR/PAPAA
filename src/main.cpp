#include "adders.h"
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <omp.h>
#include <stdlib.h> 
#include <stdint.h> 
#include <chrono>

#ifndef NB_BITS 
#define NB_BITS 16
#endif

#ifndef NUM_THREADS 
#define NUM_THREADS 8
#endif

typedef struct {
    const char* name;
    void (*function)(LweSample*, const LweSample*, const LweSample*, int, const TFheGateBootstrappingCloudKeySet*, int thread_num);
} AdderInfo;

int main(int argc, char *argv[]) {

    const int nb_bits = atoi(argv[1]);
    const int num_threads = atoi(argv[2]);

    printf("FHE operations will use nb_bits = %d\n", nb_bits);
    printf("Attempting to use %d OpenMP threads. Actual max threads available: %d\n", num_threads, omp_get_max_threads());
    printf("--------------------------------------------\n");

    printf("Generating keys...\n");
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed, 3);

    TFheGateBootstrappingSecretKeySet* sk = new_random_gate_bootstrapping_secret_keyset(params);
    const TFheGateBootstrappingCloudKeySet* bk = &sk->cloud;
    printf("--------------------------------------------\n");

    int16_t plaintext1_orig_val = 15;
    int16_t plaintext2_orig_val = 42;

    printf("Original Plaintext 1 (int16_t): %d\n", plaintext1_orig_val);
    printf("Original Plaintext 2 (int16_t): %d\n", plaintext2_orig_val);
    printf("--------------------------------------------\n");

    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(nb_bits, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(nb_bits, params);

    printf("Encrypting plaintexts to %d bits...\n", nb_bits);
    
    for (int i = 0; i < nb_bits; i++) {
        int bit1 = ((int64_t)plaintext1_orig_val >> i) & 1;
        int bit2 = ((int64_t)plaintext2_orig_val >> i) & 1;
        bootsSymEncrypt(&ciphertext1[i], bit1, sk);
        bootsSymEncrypt(&ciphertext2[i], bit2, sk);
    }
    printf("--------------------------------------------\n");

    AdderInfo adders_to_test[] = {
        {"BKA", brent_kung_adder},
        {"HCA", han_carlson_adder},
        {"KSA", kogge_stone_adder},
        {"LFA", ladner_fischer_adder},
        {"SKA", sklansky_adder},
        {"RCA", ripple_adder}
    };
    const int num_adders = sizeof(adders_to_test) / sizeof(adders_to_test[0]);

    printf("Gate Benchmark:\n");
    int gate_iterations = 10;
    LweSample* gate_result = new_gate_bootstrapping_ciphertext(params);
    
    auto gate_start = std::chrono::steady_clock::now();
    for (int i = 0; i < gate_iterations; i++) {
        bootsAND(gate_result, &ciphertext1[0], &ciphertext2[0], bk);
    }
    auto gate_end = std::chrono::steady_clock::now();
    auto gate_diff = gate_end - gate_start;
    int gate_ms = std::chrono::duration<double, std::milli>(gate_diff).count();
    printf("Gate duration: %.2f ms\n", (double)gate_ms / gate_iterations);
    printf("--------------------------------------------\n");

    for (int i = 0; i < num_adders; ++i) {
        AdderInfo adder_info = adders_to_test[i];
        LweSample* result_ciphertext = new_gate_bootstrapping_ciphertext_array(nb_bits, params);

        auto start = std::chrono::steady_clock::now();
        adder_info.function(result_ciphertext, ciphertext1, ciphertext2, nb_bits, bk, num_threads);
        auto end = std::chrono::steady_clock::now();

        auto diff = end - start;
        int sec = std::chrono::duration<double, std::milli>(diff).count();

        int64_t raw_decrypted_pattern = 0;
        for (int k = 0; k < nb_bits; k++) {
            int bit = bootsSymDecrypt(&result_ciphertext[k], sk);
            if (bit) {
                raw_decrypted_pattern |= (1ULL << k);
            }
        }

        int shift_amount = 64 - nb_bits;
        int64_t accumulated_decrypted_value = (raw_decrypted_pattern << shift_amount) >> shift_amount;

        delete_gate_bootstrapping_ciphertext_array(nb_bits, result_ciphertext);

        printf("%s elapsed time: %d ms, ans: %ld\n", adder_info.name, sec, accumulated_decrypted_value);
    }
    printf("--------------------------------------------\n");

    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext1);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext2);
    delete_gate_bootstrapping_secret_keyset(sk);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}