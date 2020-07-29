#include <string.h>
#include <stdio.h>
#include <decaf.h>
#include <decaf/spongerng.h>
#include <decaf/point_255.h>
#include <decaf/ed255.h>
#include <decaf/point_448.h>
#include <decaf/ed448.h>
#include <decaf/shake.h>
#include "bin2hexstr.h"

int main(const int argc, const char* argv[])
{
    uint8_t privatekey[DECAF_EDDSA_448_PRIVATE_BYTES];
    uint8_t publickey[DECAF_EDDSA_448_PUBLIC_BYTES];

    decaf_keccak_prng_t rng; 

    /* Set an initial value for the pseudo random number generator */
    uint8_t buf[] = "bench_cfrg_crypto"; 

    const size_t buflen = sizeof(buf);

    decaf_spongerng_init_from_buffer( 
      rng, /* The PRNG object. */
      buf, /*  The initialization data. */
      buflen, /* The length of the initialization data. */
      1 /* Make it deterministic */
    );

    /* Create output buffer for the sponge-based CSPRNG. */
    uint8_t csprng_buffer[DECAF_EDDSA_448_PRIVATE_BYTES];

    decaf_spongerng_next(  
      rng, /* The PRNG object. */
      csprng_buffer, /* The output buffer for the sponge-based CSPRNG. */
      DECAF_EDDSA_448_PRIVATE_BYTES /* Number of bytes to output. */
    );

    memcpy(privatekey, csprng_buffer, DECAF_EDDSA_448_PRIVATE_BYTES);

    decaf_ed448_derive_public_key(publickey, privatekey); 

    char privatekeyhex[256];
    char publickeyhex[256];

    eddsac_bin2hexstr(privatekey, sizeof(privatekey), privatekeyhex, sizeof(privatekeyhex), NULL, 0);
    eddsac_bin2hexstr(publickey, sizeof(publickey), publickeyhex, sizeof(publickeyhex), NULL, 0);

    fprintf(stdout, "{\"ed448_private_key\":\"%s\",\"ed448_public_key\":\"%s\"}\n", privatekeyhex, publickeyhex);

    memset(privatekeyhex, 0x00, sizeof(privatekeyhex));
    memset(publickeyhex, 0x00, sizeof(publickeyhex));

    return 0;
}

