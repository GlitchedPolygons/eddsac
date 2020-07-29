#include <string.h>
#include <stdio.h>
#include <decaf.h>
#include <decaf/spongerng.h>
#include <decaf/point_255.h>
#include <decaf/ed255.h>
#include <decaf/point_448.h>
#include <decaf/ed448.h>
#include <decaf/shake.h>

int main(){

    /* buffer for the private key */
    uint8_t privatekey[DECAF_EDDSA_448_PRIVATE_BYTES]; 

    /* buffer for the public key */
    uint8_t publickey[DECAF_EDDSA_448_PUBLIC_BYTES]; 

    /* buffer for the signature */
    uint8_t signature[DECAF_EDDSA_448_SIGNATURE_BYTES]; 

    /* the message to sign */
    uint8_t message[2] = {0x04, 0x48}; 

    /* set the size of the message*/
    size_t messageSize = 2; 

    /* Set the context */
    uint8_t *contextData = NULL; 

    /* set the size of the context */
    size_t contextSize = 0;

    /* Create pseudo random number generator object. */
    decaf_keccak_prng_t rng; 

    /* Set an initial value for the pseudo random number generator */
    uint8_t buf[] = "bench_cfrg_crypto"; 

    printf("Initializing a sponge-based CSPRNG from a buffer...\n");
    decaf_spongerng_init_from_buffer( 
    rng, /* The PRNG object. */
    buf, /*  The initialization data. */
    17, /* The length of the initialization data. */
    1 /* Make it deterministic */
    );

    /* Create output buffer for the sponge-based CSPRNG. */
    uint8_t CSPRNGbuffer[DECAF_EDDSA_448_PRIVATE_BYTES];

    printf("Outputting bytes from a sponge-based CSPRNG...\n");
    decaf_spongerng_next(  
    rng, /* The PRNG object. */
    CSPRNGbuffer, /* The output buffer for the sponge-based CSPRNG. */
    DECAF_EDDSA_448_PRIVATE_BYTES /* Number of bytes to output. */
    );

    printf("Using the random number that was generated as private key...\n");
    memcpy(privatekey, CSPRNGbuffer, DECAF_EDDSA_448_PRIVATE_BYTES);

    printf("generate the public key from the private key...\n");
    decaf_ed448_derive_public_key(publickey, privatekey); 

    printf("signing the message using ed448...\n");
    decaf_ed448_sign( 
        signature,
        privatekey,
        publickey,
        message,
        messageSize,
        0, /* prehash (a.k.a ed448_ph): 0=false. non-zero=true. */
        contextData,
        contextSize
    );

    printf("verifying the message using ed448...\n");
    decaf_error_t verificationstatus = decaf_ed448_verify(   
        signature, 
        publickey, 
        message, 
        messageSize, 
        0, /* prehash (a.k.a ed448_ph): 0=false. non-zero=true. */
        contextData, 
        contextSize
    ); 

    if (verificationstatus == DECAF_SUCCESS)
    {
        printf("verification succeeded!\n");
    }
    else
    {
        printf("verification failed!\n");
    }

    return 0;
}

