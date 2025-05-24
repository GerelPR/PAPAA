#include "adders.h"
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <omp.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

#ifndef NB_BITS_DEFAULT
#define NB_BITS_DEFAULT 16
#endif
#ifndef NUM_THREADS_DEFAULT
#define NUM_THREADS_DEFAULT 8
#endif

typedef struct {
    const char* name;
    void (*function)(LweSample*, const LweSample*, const LweSample*, int, const TFheGateBootstrappingCloudKeySet*, int);
} AdderInfo;

double get_elapsed_time(struct timeval start, struct timeval end) {
    return (double)(end.tv_sec - start.tv_sec) + (double)(end.tv_usec - start.tv_usec) / 1000000.0;
}

int main(int argc, char *argv[]) {
    int nb_bits_arg;
    int num_threads_arg;
    nb_bits_arg = atoi(argv[1]);
    num_threads_arg = atoi(argv[2]);

    const int nb_bits = nb_bits_arg;
    const int num_threads = num_threads_arg;

    printf("FHE operations will use nb_bits = %d\n", nb_bits);
    printf("Attempting to use %d OpenMP threads. Actual max threads available: %d\n", num_threads, omp_get_max_threads());
    printf("--------------------------------------------\n");

    // 1. Key Generation
    printf("Generating keys...\n");
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed, 3);

    TFheGateBootstrappingSecretKeySet* sk = new_random_gate_bootstrapping_secret_keyset(params);
    const TFheGateBootstrappingCloudKeySet* bk = &sk->cloud;
    printf("Keys generated.\n");
    printf("--------------------------------------------\n");

    // 2. Plaintexts (source int16_t) and Encryption (using nb_bits)
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
    printf("Encryption complete.\n");
    printf("--------------------------------------------\n");

    // 3. Define Adders to Test
    AdderInfo adders_to_test[] = {
        {"BKA", brent_kung_adder},
        {"HCA", han_carlson_adder},
        {"KSA", kogge_stone_adder},
        {"LFA", ladner_fischer_adder},
        {"SKA", sklansky_adder},
        {"RCA", ripple_adder}
    };
    const int num_adders = sizeof(adders_to_test) / sizeof(adders_to_test[0]);

    // 4. Execute and Time Each Adder
    for (int i = 0; i < num_adders; ++i) {
        AdderInfo adder_info = adders_to_test[i];
        LweSample* result_ciphertext = new_gate_bootstrapping_ciphertext_array(nb_bits, params);

        struct timeval start_time, end_time;
        struct rusage usage_start, usage_end;
        
        getrusage(RUSAGE_SELF, &usage_start);
        gettimeofday(&start_time, NULL);
        
        adder_info.function(result_ciphertext, ciphertext1, ciphertext2, nb_bits, bk, num_threads);
        
        gettimeofday(&end_time, NULL);
        getrusage(RUSAGE_SELF, &usage_end);

        // Calculate elapsed time (wall clock)
        double elapsed_seconds = get_elapsed_time(start_time, end_time);
        double elapsed_ms = elapsed_seconds * 1000.0;
        
        // Calculate user and system time
        double user_time = (usage_end.ru_utime.tv_sec - usage_start.ru_utime.tv_sec) + 
                          (usage_end.ru_utime.tv_usec - usage_start.ru_utime.tv_usec) / 1000000.0;
        double sys_time = (usage_end.ru_stime.tv_sec - usage_start.ru_stime.tv_sec) + 
                         (usage_end.ru_stime.tv_usec - usage_start.ru_stime.tv_usec) / 1000000.0;

        // Decrypt result
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

        double total_cpu_time = user_time + sys_time;
        double cpu_usage_percent = (total_cpu_time / elapsed_seconds) * 100.0;

        printf("%s elapsed_time: %.1f ms, CPU usage: %.1f%%, ans: %ld\n", 
               adder_info.name, elapsed_ms, cpu_usage_percent, accumulated_decrypted_value);
    }
    printf("--------------------------------------------\n");

    // 5. Cleanup
    printf("Cleaning up resources...\n");
    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext1);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext2);
    delete_gate_bootstrapping_secret_keyset(sk);
    delete_gate_bootstrapping_parameters(params);
    printf("Cleanup complete. Exiting.\n");

    return 0;
}