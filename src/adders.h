    #ifndef ADDERS_H
    #define ADDERS_H

    #include <tfhe/tfhe.h> 
    #include <omp.h>

    // --- Gate Function Declarations ---
    void half_adder(LweSample* sum, LweSample* carry, const LweSample* a, const LweSample* b, const TFheGateBootstrappingCloudKeySet* bk);
    void full_adder(LweSample* sum, LweSample* carry_out, const LweSample* a, const LweSample* b, const LweSample* carry_in, const TFheGateBootstrappingCloudKeySet* bk);

    // --- Adder Circuit Function Declarations ---
    void ripple_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num);
    void brent_kung_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num);
    void kogge_stone_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num);
    void sklansky_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num);
    void han_carlson_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num);
    void ladner_fischer_adder(LweSample* result, const LweSample* a, const LweSample* b, int nb_bits, const TFheGateBootstrappingCloudKeySet* bk, int thread_num);

    #endif 