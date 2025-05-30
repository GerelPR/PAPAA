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

    int64_t plaintext1 = atoll(argv[1]);
    int64_t plaintext2 = atoll(argv[2]);
    const int nb_bits = atoi(argv[3]);
    const int num_threads = atoi(argv[4]);

    printf("num1 = %ld\nnum2 = %ld\nnb_bits = %d\nnum_threads = %d\n", plaintext1, plaintext2, nb_bits, num_threads);

    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed, 3);

    TFheGateBootstrappingSecretKeySet* sk = new_random_gate_bootstrapping_secret_keyset(params);
    const TFheGateBootstrappingCloudKeySet* bk = &sk->cloud;

    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(nb_bits, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(nb_bits, params);

    for (int i = 0; i < nb_bits; i++) {
        bootsSymEncrypt(&ciphertext1[i], (plaintext1>>i)&1, sk);
        bootsSymEncrypt(&ciphertext2[i], (plaintext2>>i)&1, sk);
    }

    AdderInfo adders_to_test[] = {
        {"BKA", brent_kung_adder},
        {"HCA", han_carlson_adder},
        {"KSA", kogge_stone_adder},
        {"LFA", ladner_fischer_adder},
        {"SKA", sklansky_adder},
        {"RCA", ripple_carry_adder}
    };
    const int num_adders = sizeof(adders_to_test) / sizeof(adders_to_test[0]);

    printf("------------------------------------\n");

    for (int i = 0; i < num_adders; ++i) {
        AdderInfo adder_info = adders_to_test[i];
        LweSample* result_ciphertext = new_gate_bootstrapping_ciphertext_array(nb_bits, params);
        int total_time = 0;

        auto start = std::chrono::steady_clock::now();
        adder_info.function(result_ciphertext, ciphertext1, ciphertext2, nb_bits, bk, num_threads);
        auto end = std::chrono::steady_clock::now();

        auto diff = end - start;
        double elapsed_ms = std::chrono::duration<double, std::milli>(diff).count();
        
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

        printf("%s elapsed time: %.1f ms, ans: %ld\n", adder_info.name, elapsed_ms, accumulated_decrypted_value);
    }
    printf("------------------------------------\n");

    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext1);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext2);
    delete_gate_bootstrapping_secret_keyset(sk);
    delete_gate_bootstrapping_parameters(params);

    return 0;
}