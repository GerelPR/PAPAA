#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    //generate a keyset
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = { 314, 1592, 657 };
    tfhe_random_generator_setSeed(seed,3);
    TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

    //export the secret key to file for later use
    FILE* secret_key = fopen("secret.key","wb");
    export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
    fclose(secret_key);

    //export the cloud key to a file (for the cloud)
    FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);
   
    //...................................................................................
    int nb_bits ;

    if (argc > 1){ nb_bits = atoi(argv[1]); }
    else { nb_bits = 16; }

    printf("Using NB_BITS = %d for encryption.\n", nb_bits);    

    int16_t plaintext1 = 55;
    int16_t plaintext2 = 15;

    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext_array(nb_bits, params);
    for (int i=0; i<nb_bits; i++) {
        bootsSymEncrypt(&ciphertext1[i], (plaintext1>>i)&1, key);
    }

    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext_array(nb_bits, params);
    for (int i=0; i<nb_bits; i++) {
        bootsSymEncrypt(&ciphertext2[i], (plaintext2>>i)&1, key);
    }

    printf("Hi there! Today, I will ask the cloud what is the minimum between %d and %d\n",plaintext1, plaintext2);
    
    //export the 2x16 ciphertexts to a file (for the cloud)
    FILE* cloud_data = fopen("cloud.data","wb");
    for (int i=0; i<nb_bits; i++) 
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext1[i], params);
    for (int i=0; i<nb_bits; i++) 
        export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertext2[i], params);
    fclose(cloud_data);

    //clean up all pointers
    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext2);
    delete_gate_bootstrapping_ciphertext_array(nb_bits, ciphertext1);

    //.......................................................................................

    //clean up all pointers
    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);

    printf("Keys generated successfully!\n");

}

