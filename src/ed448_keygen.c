#include <string.h>
#include <stdio.h>
#include <decaf.h>
#include <decaf/spongerng.h>
#include <decaf/point_448.h>
#include <decaf/ed448.h>
#include "osrand.h"
#include "bin2hexstr.h"

#define EDDSAC_MIN(x, y) (((x) < (y)) ? (x) : (y))

int main(const int argc, const char* argv[])
{
    uint8_t privatekey[DECAF_EDDSA_448_PRIVATE_BYTES];
    uint8_t publickey[DECAF_EDDSA_448_PUBLIC_BYTES];

    decaf_keccak_prng_t rng; 

    uint8_t entropy[256];
    eddsac_dev_urandom(entropy, 128);

    size_t rem = 128;
    for (int i = 1; i < argc && rem > 0; i++)
    {
        const char* istr = argv[i];
        const size_t ilen = EDDSAC_MIN(rem, strlen(istr));
        snprintf((char*)(entropy + 128 + (sizeof(entropy) - rem)), ilen, "%s", istr);
        rem -= ilen;
    }

    decaf_spongerng_init_from_buffer(rng, entropy, sizeof(entropy), 1);

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

    memset(csprng_buffer, 0x00, sizeof(csprng_buffer));
    memset(privatekeyhex, 0x00, sizeof(privatekeyhex));
    memset(publickeyhex, 0x00, sizeof(publickeyhex));
    memset(privatekey, 0x00, sizeof(privatekey));
    memset(publickey, 0x00, sizeof(publickey));
    memset(entropy, 0x00, sizeof(entropy));
    memset(&rng, 0x00, sizeof(rng));
    rem = 0;
    
    return 0;
}

#undef EDDSAC_MIN
