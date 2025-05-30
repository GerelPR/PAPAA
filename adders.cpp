#include "adders.h" 
#include <tfhe/tfhe.h> 
#include <omp.h>       

// General Parameter Guide for Prefix Adders:
//
// - LweSample* result:
//   Pointer to an LWE ciphertext where the output of the
//   homomorphic adder is stored.
//
// - LweSample* a, b:
//   Pointers to LWE ciphertext arrays representing the input integers to be added.
//
// - const TFheGateBootstrappingCloudKeySet* bk:
//   Pointer to the TFHE bootstrapping cloud key set. This key is essential for
//   performing homomorphic gate operations.
//
// - int nb_bits:
//   An integer specifying the number of bits for the operands 'a', 'b', and the 'result'.
//   This determines the size of the LweSample arrays used for multi-bit numbers.
//
// - int thread_num:
//   An integer indicating the number of threads to be used for parallelizing
//   computations with OpenMP.

// Half adder: computes result = a XOR b and carry = a AND b
void half_adder(LweSample* result, LweSample* carry, const LweSample* a, const LweSample* b, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXOR(result, a, b, bk);  // result bit is a XOR b
    bootsAND(carry, a, b, bk);  // Carry occurs when a AND b
}

// A full adder takes three single bit inputs: 'a', 'b', and 'carry_in' (previous carry_out).
// It produces two outputs: a result bit ('result') and a carry_out bit ('carry_out').
// - The result bit is 'a' XOR 'b' XOR 'carry_in'.
// - The carry_out bit is '(a AND b) OR (carry_in AND (a XOR b))'.
void full_adder(LweSample* result, LweSample* carry_out, const LweSample* a, const LweSample* b, const LweSample* carry_in, const TFheGateBootstrappingCloudKeySet* bk) {
    // Temporary ciphertext for a XOR b
    LweSample* axorb = new_gate_bootstrapping_ciphertext(bk->params);
    LweSample* aandb = new_gate_bootstrapping_ciphertext(bk->params);
    half_adder(axorb, aandb, a, b, bk);  // First half adder with a and b

    LweSample* axorb_and_carry = new_gate_bootstrapping_ciphertext(bk->params);
    half_adder(result, axorb_and_carry, axorb, carry_in, bk);  // Second half adder with (a XOR b) and carry_in
    bootsOR(carry_out, aandb, axorb_and_carry, bk);  // OR the two carries to get final carry_out

    // Free temporary ciphertexts
    delete_gate_bootstrapping_ciphertext(axorb);
    delete_gate_bootstrapping_ciphertext(aandb);
    delete_gate_bootstrapping_ciphertext(axorb_and_carry);
}

// The addition is done bit by bit, from the LSB to the MSB.
// A half_adder is used for the LSB, and full_adders are used for the remaining bits.
// The carry out of one stage is rippled (fed as carry_in) to the next stage.
void ripple_carry_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num) {

    // Allocate a ciphertext for the carry and initialize it to 0
    LweSample* carry = new_gate_bootstrapping_ciphertext(bk->params);
    bootsCONSTANT(carry, 0, bk);  // Start with no carry

    // Use a half-adder for the least significant bit
    half_adder(&result[0], carry, &a[0], &b[0], bk);

    // Process the remaining bits using the full adder
    for (int i = 1; i < nb_bits; i++) {
        LweSample* new_carry = new_gate_bootstrapping_ciphertext(bk->params);
        full_adder(&result[i], new_carry, &a[i], &b[i], carry, bk);
        
        // Update carry for the next bit
        bootsCOPY(carry, new_carry, bk);
        delete_gate_bootstrapping_ciphertext(new_carry);
    }
    delete_gate_bootstrapping_ciphertext(carry);
}

// The process involves:
// 1. Initial computation of Propagate (P_i = a_i XOR b_i) and Generate (G_i = a_i AND b_i) signals for each bit.
// 2. A "prefix tree" to compute group P and G signals.
// 3. A "carry generation" phase to compute all carries C_i from the group signals.
// 4. Final sum computation: S_i = P_i XOR G_{i-1}.
void brent_kung_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num) {
    omp_set_num_threads(thread_num);
    LweSample* temp_G = new_gate_bootstrapping_ciphertext_array(nb_bits+1, bk->params); // Stores Generate signals
    LweSample* temp_P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);   // Stores Propagate signals

    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsXOR(&result[i], &a[i], &b[i], bk); // Compute P[i] = a[i] XOR b[i]
        bootsAND(&temp_G[i], &a[i], &b[i], bk); // Compute G[i] = a[i] AND b[i]
        bootsCOPY(&temp_P[i], &result[i], bk);  // Copy P[i] to temp_P[i]
    }

    // Phase 1: Prefix computation
    // Computes group (G,P) signals: (G_new, P_new) = (G_left, P_left) . (G_right, P_right)
    // where '.' is (G_l OR (P_l AND G_r), P_l AND P_r)
    // step = right - left
    // step << 1 is the distance between 2 black processors
    for (int step = 1; (step) < nb_bits; (step <<= 1)) {  // Log n iterations
        #pragma omp parallel for
        for (int i = (step << 1) - 1; i < nb_bits; i+=(step << 1)) {
            LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
            bootsAND(temp, &temp_P[i], &temp_G[i - (step)], bk);
            bootsOR(&temp_G[i], &temp_G[i], temp, bk);
            bootsAND(&temp_P[i], &temp_P[i], &temp_P[i - (step)], bk);
            delete_gate_bootstrapping_ciphertext(temp);
        }
    }

    // step is distance between black processors
    // step >> 1 is the distance between right and left
    // i is the index of right node
    for(int step = (nb_bits >> 1); step > 1; step >>=1){
        int diff = step >> 1;
        #pragma omp parallel for
        for (int i = step - 1; i < nb_bits - diff; i=i+step){
            int left = i + diff; // left node index
            // Calculating (G_l OR (P_l AND G_r), P_l AND P_r)
            LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
            bootsAND(temp, &temp_P[left], &temp_G[i], bk);
            bootsOR(&temp_G[left], &temp_G[left], temp, bk);
            bootsAND(&temp_P[left], &temp_P[left], &temp_P[i], bk);
            delete_gate_bootstrapping_ciphertext(temp);
        }
    }

    // Phase 3: Compute sum bits: result[i] = P_initial[i] XOR C[i-1]
    // P_initial[i] is already in result[i]. C[i-1] is effectively temp_G[i-1] after all computations.
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&result[i], &result[i], &temp_G[i-1], bk);
    }

    // Free allocated arrays.
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits+1, temp_G);
}

// 1. Initial P (a XOR b) and G (a AND b) signals.
// Computes group (G,P) signals: (G_new, P_new) = (G_left, P_left) . (G_right, P_right)
// where '.' is (G_l OR (P_l AND G_r), P_l AND P_r)
// 3. Final sum: S_i = P_initial_i XOR G_{i-1}.
void kogge_stone_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num) {
    omp_set_num_threads(thread_num);
    
    // Allocate memory for initial and current P and G arrays
    LweSample* current_P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* current_G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    // Compute initial propagate (P) and generate (G) signals
    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsXOR(&result[i], &a[i], &b[i], bk);
        bootsAND(&current_G[i], &a[i], &b[i], bk);
        bootsCOPY(&current_P[i], &result[i], bk);
    }

    // Perform the Kogge-Stone prefix computation
    // step = right - left
    // step is the distance between 2 black processors
    for (int step = 1; (step) < nb_bits; (step <<= 1)) {
        #pragma omp parallel for
        for (int i = step; i < nb_bits; i++) {
            LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
            bootsAND(temp, &current_P[i], &current_G[i - (step)], bk);
            bootsOR(&current_G[i], &current_G[i], temp, bk);
            bootsAND(&current_P[i], &current_P[i], &current_P[i - (step)], bk);
            delete_gate_bootstrapping_ciphertext(temp);
        }

    }

    // Compute the sum bits
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&result[i], &result[i], &current_G[i-1], bk);
    }

    // Cleanup
    delete_gate_bootstrapping_ciphertext_array(nb_bits, current_P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, current_G);
}


// 1. Initial P (a XOR b) and G (a AND b) signals.
// 2. Sklansky parallel prefix computation: Uses a specific tree structure to combine (G,P) pairs.
//    The condition `i % (step << 1) >= step` selects specific nodes in the Sklansky tree for computation.
//    The G signals after this are the carries C_i.
// 3. Final sum: S_i = P_initial_i XOR C_{i-1}.
void sklansky_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num) {
    omp_set_num_threads(thread_num);

    // Allocate arrays for propagate (P) and generate (G)
    LweSample* P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsXOR(&P[i], &a[i], &b[i], bk);   // P[i] = a[i] XOR b[i]
        bootsAND(&G[i], &a[i], &b[i], bk);     // G[i] = a[i] AND b[i]
        bootsCOPY(&result[i], &P[i], bk);        // Save original P for the sum calculation
    }

    // Sklansky parallel prefix computation:
    // step is fan out number from last node of sequential of nodes
    for (int step = 1; step < nb_bits; step <<= 1) {
        #pragma omp parallel for
        // i is the index of black nodes if i % (step << 1) >= step
        for (int i = step; i < nb_bits; i++) {     
            if(i % (step << 1) >= step) {
                // j is the index of the right node
                int j = i - (i % step) - 1;
                LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);

                bootsAND(temp, &P[i], &G[j], bk);
                bootsOR(&G[i], &G[i], temp, bk);
                bootsAND(&P[i], &P[i], &P[j], bk);

                delete_gate_bootstrapping_ciphertext(temp);
            }      
        }
    }
    
    // Compute the sum bits: result[i] = P[i] XOR G[i-1]
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&result[i], &result[i], &G[i-1], bk);
    }

    delete_gate_bootstrapping_ciphertext_array(nb_bits, P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, G);
}

// 1. Initial P (a XOR b) and G (a AND b) signals.
// 2. Computes group (G,P) signals: (G_new, P_new) = (G_left, P_left) . (G_right, P_right)
// 3. Parallel Prefix Tree: A Kogge-Stone-like prefix computation is run on these odd-indexed (G,P) pairs.
// 4. Post-computation: Carries for even-indexed bits are computed using results from their odd-indexed neighbors.
void han_carlson_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num) {
    omp_set_num_threads(thread_num);
    
    // Allocate memory for propagate (P) and generate (G) signals
    LweSample* P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    // Compute initial P and G values
    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsXOR(&result[i], &a[i], &b[i], bk); // P[i] = a[i] XOR b[i]
        bootsAND(&G[i], &a[i], &b[i], bk);      // G[i] = a[i] AND b[i]
        bootsCOPY(&P[i], &result[i], bk);       // Copy P to separate array
    }

    // Temporary arrays for the parallel prefix computation
    LweSample* temp_P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* temp_G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    // Pre-processing: compute (G,P) for odd-indexed bits
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i += 2) {
        bootsAND(&temp_G[i], &P[i], &G[i-1], bk);
        bootsOR(&G[i], &G[i], &temp_G[i], bk);
        bootsAND(&P[i], &P[i], &P[i-1], bk);
    }

    // Parallel prefix tree computation (similar to Kogge-Stone but only on odd indices)
    // step + 1 is the first black processor of the level
    for (int step = 2; step < nb_bits; step <<= 1) {
        #pragma omp parallel for
        for (int i = step + 1; i < nb_bits; i += 2) {
            bootsAND(&temp_G[i], &P[i], &G[i-step], bk);
            bootsOR(&G[i], &G[i], &temp_G[i], bk);
            bootsAND(&P[i], &P[i], &P[i-step], bk);
        }
    }

    // Post-processing: compute all even-indexed bits
    #pragma omp parallel for
    for (int i = 2; i < nb_bits; i += 2) {
        bootsAND(&temp_G[i], &P[i], &G[i-1], bk);
        bootsOR(&G[i], &G[i], &temp_G[i], bk);
        bootsAND(&P[i], &P[i], &P[i-1], bk);
    }

    // Compute the sum bits: result[i] = P[i] XOR C[i-1]
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&result[i], &result[i], &G[i-1], bk);
    }

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(nb_bits, P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, G);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_G);
}

// 1. Initial P (a XOR b) and G (a AND b) signals.
// 2. Ladner-Fischer prefix computation: Consists of stages where (G,P) pairs are combined.
//    The first loop computes prefix values for odd-indexed positions.
//    The second loop computes prefix values for even-indexed positions using results from odd ones.
//    G[k-1] after this process represents carry C[k].
// 3. Final sum: S_i = P_initial_i XOR G_{i-1}.
void ladner_fischer_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num) {
    omp_set_num_threads(thread_num);
    
    // Allocate memory for propagate (P) and generate (G) signals
    LweSample* P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    // Compute initial P and G values
    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsXOR(&result[i], &a[i], &b[i], bk); // P[i] = a[i] XOR b[i]
        bootsAND(&G[i], &a[i], &b[i], bk);      // G[i] = a[i] AND b[i]
        bootsCOPY(&P[i], &result[i], bk);       // Copy P to separate array
    }

    for (int step = 1; step < nb_bits; step <<= 1) {
        #pragma omp parallel for
        for (int i = step; i < nb_bits; i++) {     
            // Same as Sklansky adder, but only for odd indices
            if(i % (step << 1) >= step && i % 2 == 1) {
                int j = i - (i % step) - 1;
                LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);

                bootsAND(temp, &P[i], &G[j], bk);
                bootsOR(&G[i], &G[i], temp, bk);
                bootsAND(&P[i], &P[i], &P[j], bk);

                delete_gate_bootstrapping_ciphertext(temp);
            }      
        }
    }

    // For even-indexed bits computes (G,P) pairs
    #pragma omp parallel for
    for (int i = 2; i < nb_bits; i+=2) {
        LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);

        bootsAND(temp, &P[i], &G[i-1], bk);
        bootsOR(&G[i], &G[i], temp, bk);
        bootsAND(&P[i], &P[i], &P[i-1], bk);

        delete_gate_bootstrapping_ciphertext(temp);
                 
    }

    // Calculate sum bits from carries
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&result[i], &result[i], &G[i-1], bk);
    }

    // Cleanup
    delete_gate_bootstrapping_ciphertext_array(nb_bits, P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, G);
}
