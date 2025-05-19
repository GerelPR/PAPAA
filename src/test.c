#include <tfhe/tfhe.h>
#include <omp.h>    // For omp_get_wtime()
#include <stdio.h>
#include <string.h> // For strcmp

// Function to benchmark a gate, including input copying in each iteration
void benchmark_gate_with_per_iteration_copy(
    const char* gate_name,
    // Function pointer for 2-input gates (AND, OR, XOR, etc.)
    void (*gate_function_2_inputs)(LweSample*, const LweSample*, const LweSample*, const TFheGateBootstrappingCloudKeySet*),
    // Function pointer for 1-input gates (NOT)
    void (*gate_function_1_input)(LweSample*, const LweSample*, const TFheGateBootstrappingCloudKeySet*),
    const LweSample* source_ct1, // Source ciphertext to copy from (e.g., &ciphertext1[0])
    const LweSample* source_ct2, // Source ciphertext to copy from (e.g., &ciphertext2[0]), can be NULL
    const TFheGateBootstrappingCloudKeySet* bk,
    int iterations) {

    printf("Benchmarking %s gate WITH PER-ITERATION INPUT COPY (%d iterations)...\n", gate_name, iterations);

    LweSample* res_bit    = new_gate_bootstrapping_ciphertext(bk->params);
    LweSample* input1_for_gate = new_gate_bootstrapping_ciphertext(bk->params); // Destination for copy
    LweSample* input2_for_gate = NULL;                                       // Destination for copy

    // Input validation
    if (source_ct1 == NULL) {
        printf("ERROR: source_ct1 cannot be NULL for %s. Skipping benchmark.\n", gate_name);
        delete_gate_bootstrapping_ciphertext(res_bit);
        delete_gate_bootstrapping_ciphertext(input1_for_gate);
        return;
    }
    if (gate_function_2_inputs != NULL) {
        input2_for_gate = new_gate_bootstrapping_ciphertext(bk->params);
        if (source_ct2 == NULL) {
            printf("ERROR: source_ct2 cannot be NULL for 2-input gate %s. Skipping benchmark.\n", gate_name);
            delete_gate_bootstrapping_ciphertext(res_bit);
            delete_gate_bootstrapping_ciphertext(input1_for_gate);
            delete_gate_bootstrapping_ciphertext(input2_for_gate);
            return;
        }
    }

    // Warm-up (optional, includes copy + gate)
    bootsCOPY(input1_for_gate, source_ct1, bk);
    if (gate_function_2_inputs != NULL) {
        bootsCOPY(input2_for_gate, source_ct2, bk);
        gate_function_2_inputs(res_bit, input1_for_gate, input2_for_gate, bk);
    } else if (gate_function_1_input != NULL) {
        gate_function_1_input(res_bit, input1_for_gate, bk);
    }

    double total_duration_seconds = 0.0;
    double start_time = omp_get_wtime();

    for (int i = 0; i < iterations; ++i) {
        // Copy inputs for THIS iteration
        bootsCOPY(input1_for_gate, source_ct1, bk);

        if (gate_function_2_inputs != NULL) {
            bootsCOPY(input2_for_gate, source_ct2, bk);
            gate_function_2_inputs(res_bit, input1_for_gate, input2_for_gate, bk);
        } else if (gate_function_1_input != NULL) {
            // For NOT, only one input copy is needed
            gate_function_1_input(res_bit, input1_for_gate, bk);
        }
    }

    double end_time = omp_get_wtime();
    total_duration_seconds = end_time - start_time;

    if (iterations > 0) {
        double avg_duration_ms = (total_duration_seconds / iterations) * 1000.0;
        printf("Total time for %d (Copy+Copy+Op or Copy+Op) iterations: %.4f seconds.\n", iterations, total_duration_seconds);
        printf("Average time per (Copy(s)+%s operation): %.4f ms.\n", gate_name, avg_duration_ms);
    } else {
        printf("No iterations performed for %s.\n", gate_name);
    }

    // Cleanup
    delete_gate_bootstrapping_ciphertext(res_bit);
    delete_gate_bootstrapping_ciphertext(input1_for_gate);
    if (input2_for_gate != NULL) {
        delete_gate_bootstrapping_ciphertext(input2_for_gate);
    }
    printf("--------------------------------------------\n");
}


int main() {
    int nb_bits = 16;
    printf("Setting up TFHE (nb_bits = %d)...\n", nb_bits);

    FILE* cloud_key = fopen("cloud.key", "rb");
    if (!cloud_key) { perror("Error opening cloud.key"); return 1; }
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
    printf("Cloud key loaded.\n");

    const TFheGateBootstrappingParameterSet* params = bk->params;

    // Your existing code to load ciphertexts
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(nb_bits, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(nb_bits, params);

    FILE* cloud_data = fopen("cloud.data", "rb");
    if (!cloud_data) {
        perror("Error opening cloud.data");
        delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext1);
        delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext2);
        delete_gate_bootstrapping_cloud_keyset(bk);
        return 1;
    }
    printf("Loading ciphertexts from cloud.data...\n");
    for (int i = 0; i < nb_bits; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext1[i], params);
    for (int i = 0; i < nb_bits; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext2[i], params);
    fclose(cloud_data);
    printf("Ciphertexts loaded and ready for benchmarking.\n");


    int iterations_for_benchmark = 100;

    // --- Benchmark individual gates WITH PER-ITERATION INPUT COPY ---
    // We'll use the 0-th bit of your loaded ciphertexts as the source for copies.

    benchmark_gate_with_per_iteration_copy("bootsAND",  bootsAND, NULL,     &ciphertext1[0], &ciphertext2[0], bk, iterations_for_benchmark);
    benchmark_gate_with_per_iteration_copy("bootsOR",   bootsOR,  NULL,     &ciphertext1[0], &ciphertext2[0], bk, iterations_for_benchmark);
    benchmark_gate_with_per_iteration_copy("bootsXOR",  bootsXOR, NULL,     &ciphertext1[0], &ciphertext2[0], bk, iterations_for_benchmark);
    benchmark_gate_with_per_iteration_copy("bootsNOT",  NULL,     bootsNOT, &ciphertext1[0], NULL,            bk, iterations_for_benchmark);
    benchmark_gate_with_per_iteration_copy("bootsNAND", bootsNAND,NULL,     &ciphertext1[0], &ciphertext2[0], bk, iterations_for_benchmark);
    benchmark_gate_with_per_iteration_copy("bootsNOR",  bootsNOR, NULL,     &ciphertext1[0], &ciphertext2[0], bk, iterations_for_benchmark);
    benchmark_gate_with_per_iteration_copy("bootsXNOR", bootsXNOR,NULL,     &ciphertext1[0], &ciphertext2[0], bk, iterations_for_benchmark);


    // Benchmark for bootsMUX with per-iteration copy
    if (nb_bits >= 1) {
        printf("Benchmarking bootsMUX gate WITH PER-ITERATION INPUT COPY (%d iterations)...\n", iterations_for_benchmark);
        LweSample* res_mux           = new_gate_bootstrapping_ciphertext(bk->params);
        LweSample* mux_cond_for_gate  = new_gate_bootstrapping_ciphertext(bk->params);
        LweSample* mux_true_for_gate  = new_gate_bootstrapping_ciphertext(bk->params);
        LweSample* mux_false_for_gate = new_gate_bootstrapping_ciphertext(bk->params);

        // Source ciphertexts for MUX inputs (pointers to your loaded data)
        const LweSample* source_mux_cond    = &ciphertext1[0];
        const LweSample* source_mux_true_val= &ciphertext1[0]; // or another bit, e.g., &ciphertext1[1]
        const LweSample* source_mux_false_val= &ciphertext2[0]; // or another bit, e.g., &ciphertext2[1]

        // Warm-up for MUX
        bootsCOPY(mux_cond_for_gate,  source_mux_cond,    bk);
        bootsCOPY(mux_true_for_gate,  source_mux_true_val,bk);
        bootsCOPY(mux_false_for_gate, source_mux_false_val,bk);
        bootsMUX(res_mux, mux_cond_for_gate, mux_true_for_gate, mux_false_for_gate, bk);

        double mux_total_duration_seconds = 0.0;
        double mux_start_time = omp_get_wtime();
        for (int i = 0; i < iterations_for_benchmark; ++i) {
            bootsCOPY(mux_cond_for_gate,  source_mux_cond,    bk);
            bootsCOPY(mux_true_for_gate,  source_mux_true_val,bk);
            bootsCOPY(mux_false_for_gate, source_mux_false_val,bk);
            bootsMUX(res_mux, mux_cond_for_gate, mux_true_for_gate, mux_false_for_gate, bk);
        }
        double mux_end_time = omp_get_wtime();
        mux_total_duration_seconds = mux_end_time - mux_start_time;

        if (iterations_for_benchmark > 0) {
            double mux_avg_duration_ms = (mux_total_duration_seconds / iterations_for_benchmark) * 1000.0;
            printf("Total time for %d (3xCopy+MUX) iterations: %.4f seconds.\n", iterations_for_benchmark, mux_total_duration_seconds);
            printf("Average time per (3xCopy+bootsMUX operation): %.4f ms.\n", mux_avg_duration_ms);
        }
        printf("--------------------------------------------\n");
        delete_gate_bootstrapping_ciphertext(res_mux);
        delete_gate_bootstrapping_ciphertext(mux_cond_for_gate);
        delete_gate_bootstrapping_ciphertext(mux_true_for_gate);
        delete_gate_bootstrapping_ciphertext(mux_false_for_gate);
    } else {
        printf("Skipping MUX benchmark as nb_bits < 1 (or adjust sample indices for MUX).\n");
    }

    // --- Cleanup ---
    printf("\nCleaning up...\n");
    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext1);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext2);
    delete_gate_bootstrapping_cloud_keyset(bk);
    printf("Cleanup complete. Program finished.\n");

    return 0;
}