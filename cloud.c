#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <omp.h>
#include <stdlib.h>
#include <time.h>

#ifndef NB_BITS_FROM_MAKEFILE
#define NB_BITS_FROM_MAKEFILE 16
#endif

#ifndef NUM_THREADS_FROM_MAKEFILE
#define NUM_THREADS_FROM_MAKEFILE 8 // Default to 4 threads if not specified
#endif

#ifndef OPERATION_CHOICE_FROM_MAKEFILE
#define OPERATION_CHOICE_FROM_MAKEFILE 2 // Default to Han-Carlson Subtractor
#endif

void print_operation_name(int choice, int nb_bits) {
    printf("Executing with NB_BITS = %d\n", nb_bits);
    switch (choice) {
        case 1: printf("Operation: Minimum\n"); break;
        case 2: printf("Operation: Ripple Adder\n"); break;
        case 3: printf("Operation: Brent-Kung Adder\n"); break;
        case 4: printf("Operation: Kogge-Stone Adder\n"); break;
        case 5: printf("Operation: Sklansky Adder\n"); break;
        case 6: printf("Operation: Han-Carlson Adder\n"); break;
        case 7: printf("Operation: Ripple Subtractor\n"); break;
        case 8: printf("Operation: Brent-Kung Subtractor\n"); break;
        case 9: printf("Operation: Kogge-Stone Subtractor\n"); break;
        case 10: printf("Operation: Sklansky Subtractor\n"); break;
        case 11: printf("Operation: Han-Carlson Subtractor\n"); break;
        case 12: printf("Operation: Ladner-Fischer Adder\n"); break;
        case 13: printf("Operation: Ladner-Fischer Subtractor\n"); break;
        case 14: printf("Operation: Benchmark Basic Gates\n"); break;
        default: printf("Operation: Unknown/Default (Choice %d)\n", choice); break;
    }
}

// elementary full comparator gate that is used to compare the i-th bit:
//   input: ai and bi the i-th bit of a and b
//          lsb_carry: the result of the comparison on the lowest bits
//   algo: if (a==b) return lsb_carry else return b 
void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, a, bk);
}

// Half subtractor: computes sum = a XOR b and carry = not(a) AND b
void half_subtractor(LweSample* diff, LweSample* borrow, const LweSample* a, const LweSample* b, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXOR(diff, a, b, bk);  // Difference bit is a XOR b
    LweSample* nota = new_gate_bootstrapping_ciphertext(bk->params);
    bootsNOT(nota, a, bk);  // Compute NOT a
    bootsAND(borrow, nota, b, bk);  // Borrow occurs when NOT a AND b

    delete_gate_bootstrapping_ciphertext(nota);  // Free memory
}

// Half adder: computes sum = a XOR b and carry = a AND b
void half_adder(LweSample* sum, LweSample* carry, const LweSample* a, const LweSample* b, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXOR(sum, a, b, bk);  // Sum bit is a XOR b
    bootsAND(carry, a, b, bk);  // Carry occurs when a AND b
}

// Full adder: computes sum and carry_out from a, b and carry_in
void full_adder(LweSample* sum, LweSample* carry_out, const LweSample* a, const LweSample* b, const LweSample* carry_in, const TFheGateBootstrappingCloudKeySet* bk) {
    // Temporary ciphertext for a XOR b
    LweSample* axorb = new_gate_bootstrapping_ciphertext(bk->params);
    LweSample* aandb = new_gate_bootstrapping_ciphertext(bk->params);
    half_adder(axorb, aandb, a, b, bk);  // First half adder with a and b

    LweSample* axorb_and_carry = new_gate_bootstrapping_ciphertext(bk->params);
    half_adder(sum, axorb_and_carry, axorb, carry_in, bk);  // Second half adder with (a XOR b) and carry_in
    bootsOR(carry_out, aandb, axorb_and_carry, bk);  // OR the two carries to get final carry_out

    // Free temporary ciphertexts
    delete_gate_bootstrapping_ciphertext(axorb);
    delete_gate_bootstrapping_ciphertext(aandb);
    delete_gate_bootstrapping_ciphertext(axorb_and_carry);
}

// Full subtractor: computes sum and carry_out from a, b and carry_in
void full_subtractor(LweSample* diff, LweSample* borrow_out, const LweSample* a, const LweSample* b, const LweSample* borrow_in, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* axorb = new_gate_bootstrapping_ciphertext(bk->params);
    LweSample* notaandb = new_gate_bootstrapping_ciphertext(bk->params);
    half_subtractor(axorb, notaandb, a, b, bk);  // First half subtractor with a and b

    // Process with borrow_in
    LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
    half_subtractor(diff, temp, axorb, borrow_in, bk);  // Second half subtractor with (a XOR b) and borrow_in

    bootsOR(borrow_out, notaandb, temp, bk);  // OR the two borrows to get final borrow_out

    delete_gate_bootstrapping_ciphertext(axorb);
    delete_gate_bootstrapping_ciphertext(notaandb);
    delete_gate_bootstrapping_ciphertext(temp);
}

// Ripple subtractor: subtracts b from a (a - b) for nb_bits words.
// The result is stored in the 'result' array.
void ripple_subtractor(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    // Initialize the borrow to 0.
    LweSample* borrow = new_gate_bootstrapping_ciphertext(bk->params);
    bootsCONSTANT(borrow, 0, bk);  // Start with no borrow

    // Use the half subtractor for the least significant bit.
    half_subtractor(&result[0], borrow, &a[0], &b[0], bk);

    // Process the remaining bits with the full subtractor.
    for (int i = 1; i < nb_bits; i++) {
        LweSample* new_borrow = new_gate_bootstrapping_ciphertext(bk->params);
        full_subtractor(&result[i], new_borrow, &a[i], &b[i], borrow, bk);
        bootsCOPY(borrow, new_borrow, bk);  // Update borrow for next iteration
        delete_gate_bootstrapping_ciphertext(new_borrow);
    }
    delete_gate_bootstrapping_ciphertext(borrow);
}

void ripple_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    printf("ripple_adder\n");

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

// this function compares two multibit words, and puts the max in result
void minimum(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    
    //initialize the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);
    //run the elementary comparator gate n times
    for (int i=0; i<nb_bits; i++) {
        compare_bit(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);  // Compare each bit from MSB to LSB
    }
    //tmps[0] is the result of the comparaison: 0 if a is larger, 1 if b is larger
    //select the max and copy it to the result
    for (int i=0; i<nb_bits; i++) {
        bootsMUX(&result[i], &tmps[0], &b[i], &a[i], bk);  // If a>b, select a; else select b
    }

    delete_gate_bootstrapping_ciphertext_array(2, tmps);    
}

void brent_kung_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    printf("Brent kung adder\n");
    LweSample* temp_G = new_gate_bootstrapping_ciphertext_array(nb_bits+1, bk->params);
    LweSample* temp_P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsXOR(&result[i], &a[i], &b[i], bk); // Compute P[i] = a[i] XOR b[i]
        bootsAND(&temp_G[i], &a[i], &b[i], bk); // Compute G[i] = a[i] AND b[i]
        bootsCOPY(&temp_P[i], &result[i], bk);
    }

    // Compute carry signals for bits 1..nb_bits-1 in parallel.
    for (int step = 1; (step) <= nb_bits; (step <<= 1)) {  // Log n iterations
        #pragma omp parallel for
        for (int i = (step << 1) - 1; i < nb_bits; i+=(step << 1)) {
            LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
            bootsAND(temp, &temp_P[i], &temp_G[i - (step)], bk);
            bootsOR(&temp_G[i], &temp_G[i], temp, bk);
            bootsAND(&temp_P[i], &temp_P[i], &temp_P[i - (step)], bk);
            delete_gate_bootstrapping_ciphertext(temp);
        }
    }

    // Compute carry signals for bits nb_bits-1..1 in parallel.
    LweSample* temp_G_odtoi = new_gate_bootstrapping_ciphertext_array(nb_bits+1, bk->params);
    LweSample* temp_P_odtoi = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    
    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsCOPY(&temp_G_odtoi[i], &temp_G[i], bk);
        bootsCOPY(&temp_P_odtoi[i], &temp_P[i], bk);
    }

    int j = 0;
    int n_huwaah_2 = (nb_bits >> 1);
    // Compute carry signals for bits nb_bits-1..1 in parallel.
    for (int step = n_huwaah_2; step > 1; (step = step >> 1), j++) {
        #pragma omp parallel for
        for (int i = step - 1; i < nb_bits; i=i+step) {
            if (((i - (step - 1)) % (step << 1) == 0) && (j != 0)){ 
                LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
                bootsAND(temp, &temp_P[i], &temp_G_odtoi[i], bk);
                bootsOR(&temp_G[i], &temp_G[i], temp, bk);
                bootsAND(&temp_P[i], &temp_P[i], &temp_P_odtoi[i], bk);
                delete_gate_bootstrapping_ciphertext(temp);
            }
            if (i + (step >> 1) < nb_bits){
                bootsCOPY(&temp_G_odtoi[i + (step >> 1)], &temp_G[i], bk);
                bootsCOPY(&temp_P_odtoi[i + (step >> 1)], &temp_P[i], bk);
            }
        }
    }
    
    // Compute carry signals for bits nb_bits-1..1 in parallel.
    #pragma omp parallel for 
    for (int i = 2; i < nb_bits; i+=2) {
        LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
        bootsAND(temp, &temp_P[i], &temp_G_odtoi[i], bk);
        bootsOR(&temp_G[i], &temp_G[i], temp, bk);
        bootsAND(&temp_P[i], &temp_P[i], &temp_P_odtoi[i], bk);
        delete_gate_bootstrapping_ciphertext(temp);
    }

    // // Compute the sum bits: result[i] = P[i] XOR C[i]
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&result[i], &result[i], &temp_G[i-1], bk);
    }

    // Free allocated arrays.
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits+1, temp_G);
    delete_gate_bootstrapping_ciphertext_array(nb_bits+1, temp_G_odtoi);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_P_odtoi);
}

void brent_kung_subtractor(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    printf("Brent kung subtructor\n");
    LweSample* temp_G = new_gate_bootstrapping_ciphertext_array(nb_bits+1, bk->params);
    LweSample* temp_P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* not_b = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsNOT(&not_b[i], &b[i], bk);
        bootsXNOR(&result[i], &a[i], &b[i], bk); // Compute P[i] = a[i] XOR b[i]
        bootsAND(&temp_G[i], &a[i], &not_b[i], bk); // Compute G[i] = a[i] AND b[i]
        bootsCOPY(&temp_P[i], &result[i], bk);
    }

    delete_gate_bootstrapping_ciphertext_array(nb_bits, not_b);
    // Compute carry signals for bits 1..nb_bits-1 in parallel.
    for (int step = 1; (step) <= nb_bits; (step <<= 1)) {  // Log n iterations
        #pragma omp parallel for
        for (int i = (step << 1) - 1; i < nb_bits; i+=(step << 1)) {
            LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
            bootsAND(temp, &temp_P[i], &temp_G[i - (step)], bk);
            bootsOR(&temp_G[i], &temp_G[i], temp, bk);
            bootsAND(&temp_P[i], &temp_P[i], &temp_P[i - (step)], bk);
            delete_gate_bootstrapping_ciphertext(temp);
        }
    }

    // Compute carry signals for bits nb_bits-1..1 in parallel.
    LweSample* temp_G_odtoi = new_gate_bootstrapping_ciphertext_array(nb_bits+1, bk->params);
    LweSample* temp_P_odtoi = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    
    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsCOPY(&temp_G_odtoi[i], &temp_G[i], bk);
        bootsCOPY(&temp_P_odtoi[i], &temp_P[i], bk);
    }

    int j = 0;
    int n_huwaah_2 = (nb_bits >> 1);
    // Compute carry signals for bits nb_bits-1..1 in parallel.
    for (int step = n_huwaah_2; step > 1; (step = step >> 1), j++) {
        #pragma omp parallel for
        for (int i = step - 1; i < nb_bits; i=i+step) {
            if (((i - (step - 1)) % (step << 1) == 0) && (j != 0)){ 
                LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
                bootsAND(temp, &temp_P[i], &temp_G_odtoi[i], bk);
                bootsOR(&temp_G[i], &temp_G[i], temp, bk);
                bootsAND(&temp_P[i], &temp_P[i], &temp_P_odtoi[i], bk);
                delete_gate_bootstrapping_ciphertext(temp);
            }
            if (i + (step >> 1) < nb_bits){
                bootsCOPY(&temp_G_odtoi[i + (step >> 1)], &temp_G[i], bk);
                bootsCOPY(&temp_P_odtoi[i + (step >> 1)], &temp_P[i], bk);
            }
        }
    }
    
    // Compute carry signals for bits nb_bits-1..1 in parallel.
    #pragma omp parallel for 
    for (int i = 2; i < nb_bits; i+=2) {
        LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
        bootsAND(temp, &temp_P[i], &temp_G_odtoi[i], bk);
        bootsOR(&temp_G[i], &temp_G[i], temp, bk);
        bootsAND(&temp_P[i], &temp_P[i], &temp_P_odtoi[i], bk);
        delete_gate_bootstrapping_ciphertext(temp);
    }

    LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
    bootsNOT(temp, &result[0], bk);
    bootsCOPY(&result[0], temp, bk);
    delete_gate_bootstrapping_ciphertext(temp);

    // // Compute the sum bits: result[i] = P[i] XOR C[i]
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&temp_G[i-1], &temp_G[i-1], &temp_P[i-1], bk);
        bootsXOR(&result[i], &result[i], &temp_G[i-1], bk);
    }

    // Free allocated arrays.
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits+1, temp_G);
    delete_gate_bootstrapping_ciphertext_array(nb_bits+1, temp_G_odtoi);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_P_odtoi);
}

void kogge_stone_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    printf("Kogge-Stone adder\n");
    
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

    LweSample* temp_P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);   
    LweSample* temp_G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    // Perform the Kogge-Stone prefix computation
    for (int step = 1; (step) <= nb_bits; (step <<= 1)) {
        #pragma omp parallel for
        for (int i = step; i < nb_bits; i++) {
                bootsAND(&temp_G[i], &current_P[i], &current_G[i - step], bk);
                bootsOR(&temp_G[i], &current_G[i], &temp_G[i], bk);
                bootsAND(&temp_P[i], &current_P[i], &current_P[i - step], bk);
        }

        #pragma omp parallel for
        for (int i = step; i < nb_bits; i++) {
            bootsCOPY(&current_G[i], &temp_G[i], bk);
            bootsCOPY(&current_P[i], &temp_P[i], bk);
        }
    }

    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_G);

    // Compute the sum bits
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&result[i], &result[i], &current_G[i-1], bk);
    }

    // Cleanup
    delete_gate_bootstrapping_ciphertext_array(nb_bits, current_P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, current_G);
}

void sklansky_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    printf("Sklansky adder\n");

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
    for (int step = 1; step < nb_bits; step <<= 1) {
        #pragma omp parallel for
        for (int i = step; i < nb_bits; i++) {     
            if(i % (step << 1) >= step) {
                int j = i - (i % step) - 1;
                LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);

                bootsAND(temp, &P[i], &G[j], bk);
                bootsOR(&G[i], &G[i], temp, bk);
                bootsAND(&P[i], &P[i], &P[j], bk);

                delete_gate_bootstrapping_ciphertext(temp);
            }      
        }
    }
    
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&result[i], &result[i], &G[i-1], bk);
    }

    delete_gate_bootstrapping_ciphertext_array(nb_bits, P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, G);
}

void kogge_stone_subtractor(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    printf("Kogge-Stone subtractor\n");
    
    // Allocate memory for initial and current P and G arrays
    LweSample* current_P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* current_G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* not_b = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    // Compute initial propagate (P) and generate (G) signals
    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsNOT(&not_b[i], &b[i], bk);
        bootsXNOR(&result[i], &a[i], &b[i], bk);
        bootsAND(&current_G[i], &a[i], &not_b[i], bk);
        bootsCOPY(&current_P[i], &result[i], bk);
    }

    delete_gate_bootstrapping_ciphertext_array(nb_bits, not_b);
    LweSample* temp_P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);   
    LweSample* temp_G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    // Perform the Kogge-Stone prefix computation
    for (int step = 1; (step) <= nb_bits; (step <<= 1)) {
        #pragma omp parallel for
        for (int i = step; i < nb_bits; i++) {
                bootsAND(&temp_G[i], &current_P[i], &current_G[i - step], bk);
                bootsOR(&temp_G[i], &current_G[i], &temp_G[i], bk);
                bootsAND(&temp_P[i], &current_P[i], &current_P[i - step], bk);
        }

        #pragma omp parallel for
        for (int i = step; i < nb_bits; i++) {
            bootsCOPY(&current_G[i], &temp_G[i], bk);
            bootsCOPY(&current_P[i], &temp_P[i], bk);
        }
    }

    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_G);

    LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
    bootsNOT(temp, &result[0], bk);
    bootsCOPY(&result[0], temp, bk);
    delete_gate_bootstrapping_ciphertext(temp);

    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&current_G[i-1], &current_P[i-1], &current_G[i-1], bk);
        bootsXOR(&result[i], &result[i], &current_G[i-1], bk);
    }

    // Cleanup
    delete_gate_bootstrapping_ciphertext_array(nb_bits, current_P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, current_G);
}

void sklansky_subtractor(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    printf("Sklansky subtractor\n");

    // Allocate arrays for propagate (P) and generate (G)
    LweSample* P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* not_b = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsXNOR(&P[i], &a[i], &b[i], bk);   // P[i] = XNOR(a[i], b[i])
        bootsNOT(&not_b[i], &b[i], bk);
        bootsAND(&G[i], &a[i], &not_b[i], bk);       // G[i] = a[i] AND (NOT b[i])
        bootsCOPY(&result[i], &P[i], bk);          // Save original propagate in result for final computation
    }

    delete_gate_bootstrapping_ciphertext_array(nb_bits, not_b);

    // LweSample* temp_P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* temp_G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    // Sklansky parallel prefix computation:
    for (int step = 1; step < nb_bits; step <<= 1) {
        #pragma omp parallel for
        for (int i = step; i < nb_bits; i++) {     
            if(i % (step << 1) >= step) {
                int j = i - (i % step) - 1;

                bootsAND(&temp_G[i], &P[i], &G[j], bk);
                bootsOR(&G[i], &G[i], &temp_G[i], bk);
                bootsAND(&P[i], &P[i], &P[j], bk);
            }      
        }
    }

    // delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_G);

    LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
    bootsNOT(temp, &result[0], bk);
    bootsCOPY(&result[0], temp, bk);
    delete_gate_bootstrapping_ciphertext(temp);

    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&G[i-1], &G[i-1], &P[i-1], bk);
        bootsXOR(&result[i], &result[i], &G[i-1], bk);
    }

    delete_gate_bootstrapping_ciphertext_array(nb_bits, P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, G);
}


void han_carlson_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    printf("Han-Carlson adder\n");
    
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
        if (i > 0) {
            bootsAND(&temp_G[i], &P[i], &G[i-1], bk);
            bootsOR(&G[i], &G[i], &temp_G[i], bk);
            bootsAND(&P[i], &P[i], &P[i-1], bk);
        }
    }

    // Parallel prefix tree computation (similar to Kogge-Stone but only on odd indices)
    for (int step = 2; step < nb_bits; step <<= 1) {
        #pragma omp parallel for
        for (int i = step + 1; i < nb_bits; i += 2) {
            if (i - step >= 0) {
                bootsAND(&temp_G[i], &P[i], &G[i-step], bk);
                bootsOR(&G[i], &G[i], &temp_G[i], bk);
                bootsAND(&P[i], &P[i], &P[i-step], bk);
            }
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

void han_carlson_subtractor(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    printf("Han-Carlson subtractor\n");
    
    // Allocate memory for propagate (P) and generate (G) signals
    LweSample* P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* not_b = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    // Compute initial P and G values for subtraction
    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsNOT(&not_b[i], &b[i], bk);           // NOT b[i]
        bootsXNOR(&result[i], &a[i], &b[i], bk);  // P[i] = a[i] XNOR b[i]
        bootsAND(&G[i], &a[i], &not_b[i], bk);    // G[i] = a[i] AND NOT b[i]
        bootsCOPY(&P[i], &result[i], bk);         // Copy P to separate array
    }

    delete_gate_bootstrapping_ciphertext_array(nb_bits, not_b);

    // Temporary arrays for the parallel prefix computation
    LweSample* temp_P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* temp_G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    // Pre-processing: compute (G,P) for odd-indexed bits
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i += 2) {
        if (i > 0) {
            bootsAND(&temp_G[i], &P[i], &G[i-1], bk);
            bootsOR(&G[i], &G[i], &temp_G[i], bk);
            bootsAND(&P[i], &P[i], &P[i-1], bk);
        }
    }

    // Parallel prefix tree computation (similar to Kogge-Stone but only on odd indices)
    for (int step = 2; step < nb_bits; step <<= 1) {
        #pragma omp parallel for
        for (int i = step + 1; i < nb_bits; i += 2) {
            if (i - step >= 0) {
                bootsAND(&temp_G[i], &P[i], &G[i-step], bk);
                bootsOR(&G[i], &G[i], &temp_G[i], bk);
                bootsAND(&P[i], &P[i], &P[i-step], bk);
            }
        }
    }

    // Post-processing: compute all even-indexed bits
    #pragma omp parallel for
    for (int i = 2; i < nb_bits; i += 2) {
        bootsAND(&temp_G[i], &P[i], &G[i-1], bk);
        bootsOR(&G[i], &G[i], &temp_G[i], bk);
        bootsAND(&P[i], &P[i], &P[i-1], bk);
    }

    // Invert the LSB for proper subtraction
    LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);
    bootsNOT(temp, &result[0], bk);
    bootsCOPY(&result[0], temp, bk);
    delete_gate_bootstrapping_ciphertext(temp);

    // Compute the difference bits: result[i] = P[i] XOR C'[i-1]
    // where C'[i-1] = P[i-1] XOR G[i-1] for subtraction
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        bootsXOR(&temp_G[i-1], &P[i-1], &G[i-1], bk);
        bootsXOR(&result[i], &result[i], &temp_G[i-1], bk);
    }

    // Clean up
    delete_gate_bootstrapping_ciphertext_array(nb_bits, P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, G);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, temp_G);
}


void ladner_fischer_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    printf("Ladner-Fischer adder\n");
    
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

void ladner_fischer_subtractor(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    printf("Ladner-Fischer subtractor\n");
    
    // Allocate memory for propagate (P) and generate (G) signals and negated b
    LweSample* P = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* G = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);
    LweSample* not_b = new_gate_bootstrapping_ciphertext_array(nb_bits, bk->params);

    // Compute initial P and G values for subtraction (using XNOR for subtraction)
    #pragma omp parallel for
    for (int i = 0; i < nb_bits; i++) {
        bootsNOT(&not_b[i], &b[i], bk);           // NOT b[i]
        bootsXNOR(&result[i], &a[i], &b[i], bk);  // P[i] = a[i] XNOR b[i]
        bootsAND(&G[i], &a[i], &not_b[i], bk);    // G[i] = a[i] AND NOT b[i]
        bootsCOPY(&P[i], &result[i], bk);         // Copy P to separate array
    }

    delete_gate_bootstrapping_ciphertext_array(nb_bits, not_b);

    for (int step = 1; step < nb_bits; step <<= 1) {
        #pragma omp parallel for
        for (int i = step; i < nb_bits; i++) {     
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

    #pragma omp parallel for
    for (int i = 2; i < nb_bits; i+=2) {
        LweSample* temp = new_gate_bootstrapping_ciphertext(bk->params);

        bootsAND(temp, &P[i], &G[i-1], bk);
        bootsOR(&G[i], &G[i], temp, bk);
        bootsAND(&P[i], &P[i], &P[i-1], bk);

        delete_gate_bootstrapping_ciphertext(temp);
                 
    }

    // Invert the LSB for proper subtraction
    LweSample* temp_bit = new_gate_bootstrapping_ciphertext(bk->params);
    bootsNOT(temp_bit, &result[0], bk);
    bootsCOPY(&result[0], temp_bit, bk);
    delete_gate_bootstrapping_ciphertext(temp_bit);

    // Calculate difference bits from carries
    #pragma omp parallel for
    for (int i = 1; i < nb_bits; i++) {
        // For subtraction, we need to XOR with (P[i-1] XOR G[i-1])
        LweSample* adjusted_carry = new_gate_bootstrapping_ciphertext(bk->params);
        bootsXOR(adjusted_carry, &P[i-1], &G[i-1], bk);
        bootsXOR(&result[i], &result[i], adjusted_carry, bk);
        delete_gate_bootstrapping_ciphertext(adjusted_carry);
    }

    // Cleanup
    delete_gate_bootstrapping_ciphertext_array(nb_bits, P);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, G);
}


void benchmark_single_gate(
    const char* gate_name,
    void (*gate_function_2_inputs)(LweSample*, const LweSample*, const LweSample*, const TFheGateBootstrappingCloudKeySet*), // For AND, OR, XOR etc.
    void (*gate_function_1_input)(LweSample*, const LweSample*, const TFheGateBootstrappingCloudKeySet*),                 // For NOT
    const TFheGateBootstrappingCloudKeySet* bk,
    int iterations) {

    printf("Benchmarking %s gate (%d iterations)...\n", gate_name, iterations);

    LweSample* res_bit = new_gate_bootstrapping_ciphertext(bk->params);
    LweSample* input1_bit = new_gate_bootstrapping_ciphertext(bk->params);
    LweSample* input2_bit = NULL; // Only needed for 2-input gates

    // Initialize inputs (can be constant or varied if needed for testing)
    bootsCONSTANT(input1_bit, 0, bk); // Encrypt(0)

    if (gate_function_2_inputs != NULL) { // If it's a 2-input gate
        input2_bit = new_gate_bootstrapping_ciphertext(bk->params);
        bootsCONSTANT(input2_bit, 1, bk); // Encrypt(1)
    }

    // Warm-up (optional, can help stabilize timings by running once before measurement)
    if (gate_function_2_inputs != NULL) {
        gate_function_2_inputs(res_bit, input1_bit, input2_bit, bk);
    } else if (gate_function_1_input != NULL) {
        gate_function_1_input(res_bit, input1_bit, bk);
    }

    double total_duration_seconds = 0.0;
    double start_time = omp_get_wtime();

    for (int i = 0; i < iterations; ++i) {
        if (gate_function_2_inputs != NULL) {
            gate_function_2_inputs(res_bit, input1_bit, input2_bit, bk);
        } else if (gate_function_1_input != NULL) {
            gate_function_1_input(res_bit, input1_bit, bk);
        }
    }

    double end_time = omp_get_wtime();
    total_duration_seconds = end_time - start_time;

    if (iterations > 0) {
        double avg_duration_ms = (total_duration_seconds / iterations) * 1000.0;
        printf("Total time for %d %s operations: %.4f seconds.\n", iterations, gate_name, total_duration_seconds);
        printf("Average time per %s operation: %.4f ms.\n", gate_name, avg_duration_ms);
    } else {
        printf("No iterations performed for %s.\n", gate_name);
    }

    // Cleanup
    delete_gate_bootstrapping_ciphertext(res_bit);
    delete_gate_bootstrapping_ciphertext(input1_bit);
    if (input2_bit != NULL) {
        delete_gate_bootstrapping_ciphertext(input2_bit);
    }
    printf("--------------------------------------------\n");
}


int main() {
    // int nb_bits = 16;

    int nb_bits = NB_BITS_FROM_MAKEFILE;
    int num_threads_to_set = NUM_THREADS_FROM_MAKEFILE;
    int choice = OPERATION_CHOICE_FROM_MAKEFILE;

    omp_set_num_threads(num_threads_to_set);
    printf("Attempting to use %d OpenMP threads. Actual max threads available: %d\n", num_threads_to_set, omp_get_max_threads());

    //reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key", "rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
 
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;

    //read the 2x16 ciphertexts
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(nb_bits, params);
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(nb_bits, params);

    //reads the 2x16 ciphertexts from the cloud file
    FILE* cloud_data = fopen("cloud.data", "rb");
    for (int i = 0; i < nb_bits; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext1[i], params);
    for (int i = 0; i < nb_bits; i++) import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertext2[i], params);
    fclose(cloud_data);

    // Allocate result array
    LweSample* result = new_gate_bootstrapping_ciphertext_array(nb_bits, params);

    print_operation_name(choice, nb_bits); // Print the chosen operation

    double start_time = omp_get_wtime();

    // Execute the selected operation
    switch (choice) {
        case 1:
            minimum(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 2:
            ripple_adder(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 3:
            brent_kung_adder(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 4:
            kogge_stone_adder(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 5:
            sklansky_adder(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 6:
            han_carlson_adder(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 7:
            ripple_subtractor(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 8:
            brent_kung_subtractor(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 9:
            kogge_stone_subtractor(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 10:
            sklansky_subtractor(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 11:
            han_carlson_subtractor(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 12:
            ladner_fischer_adder(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        case 13:
            ladner_fischer_subtractor(result, ciphertext1, ciphertext2, nb_bits, bk);
            break;
        default:
            printf("Invalid choice. Using Han-Carlson subtractor as default.\n");
            han_carlson_subtractor(result, ciphertext1, ciphertext2, nb_bits, bk);
    }    

    double end_time = omp_get_wtime();
    printf("Selected operation execution time: %.4f seconds.\n", end_time - start_time);

    // Export the result to a file
    FILE* answer_data = fopen("answer.data", "wb");
    for (int i = 0; i < nb_bits; i++) export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);
    fclose(answer_data);

    printf("Operation completed and result saved to answer.data\n");

    // Clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(nb_bits, result);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext2);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext1);
    delete_gate_bootstrapping_cloud_keyset(bk);

    return 0;
}

