#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <stdlib.h> 

int main(int argc, char *argv[]) {

    //reads the cloud key from file
    int nb_bits = 16;

    if (argc > 1){ nb_bits = atoi(argv[1]); }
    FILE* secret_key = fopen("secret.key","rb");
    TFheGateBootstrappingSecretKeySet* key = new_tfheGateBootstrappingSecretKeySet_fromFile(secret_key);
    fclose(secret_key);
 
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = key->params;

    //read the 16 ciphertexts of the result
    LweSample* answer = new_gate_bootstrapping_ciphertext_array(nb_bits, params);

    //import the 32 ciphertexts from the answer file
    FILE* answer_data = fopen("answer.data","rb");
    for (int i=0; i<nb_bits; i++) 
        import_gate_bootstrapping_ciphertext_fromFile(answer_data, &answer[i], params);
    fclose(answer_data);

    //decrypt and rebuild the 16-bit plaintext answer
    int8_t int_answer = 0;
    for (int i=0; i<nb_bits; i++) {
        int ai = bootsSymDecrypt(&answer[i], key);
        int_answer |= (ai<<i);
    }

    printf("And the result is: %d\n",int_answer);
    printf("I hope you remember what was the question!\n");

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(nb_bits, answer);
    delete_gate_bootstrapping_secret_keyset(key);
}