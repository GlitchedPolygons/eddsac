#include <string.h>
#include <stdio.h>
#include <decaf.h>
#include <decaf/spongerng.h>
#include <decaf/point_255.h>
#include <decaf/ed255.h>
#include "hexstr2bin.h"

int main(const int argc, const char* argv[])
{
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0))
    {
        fprintf(stdout, "ed25519_sign: Sign a string using Ed25519. This program takes exactly 2 arguments: the first one being the private key with which to sign (hex-string), and the second one the message string that you want to sign.\n");
        return 0;
    }

    if (argc != 3)
    {
        fprintf(stderr, "ed25519_sign failed: wrong argument count. Check out \"ed25519_sign --help\" for more details about how to use this!\n");
        return -1;
    }

    int r = -1;

    uint8_t private_key[DECAF_EDDSA_25519_PRIVATE_BYTES + 1];
    uint8_t public_key[DECAF_EDDSA_25519_PUBLIC_BYTES];
    uint8_t signature[DECAF_EDDSA_25519_SIGNATURE_BYTES]; 

    uint8_t* ctx = NULL; 
    size_t ctx_size = 0;

    const char* private_key_hexstr = argv[1];
    const size_t private_key_hexstr_length = strlen(private_key_hexstr);

    const char* message = argv[2];
    const size_t message_length = strlen(message);

    if (private_key_hexstr_length != DECAF_EDDSA_25519_PRIVATE_BYTES * 2)
    {
        fprintf(stderr, "ed25519_sign failed: Invalid private key format/length!\n");
        r = -2;
        goto exit;
    }

    if (eddsac_hexstr2bin(private_key_hexstr, private_key_hexstr_length, private_key, sizeof(private_key), NULL) != 0)
    {
        fprintf(stderr, "ed25519_sign failed: Invalid private key format/length!\n");
        r = -2;
        goto exit;
    }

    decaf_ed25519_derive_public_key(public_key, private_key); 

    decaf_ed25519_sign( 
        signature,
        private_key,
        public_key,
        (uint8_t*)message,
        message_length,
        0, /* Prehash (set this to non-zero if what you're signing already is the hash of something) */
        ctx,
        ctx_size
    );

    decaf_error_t verification_status = decaf_ed25519_verify(   
        signature, 
        public_key, 
        (uint8_t*)message, 
        message_length, 
        0,
        ctx, 
        ctx_size
    ); 

    if (verification_status != DECAF_SUCCESS)
    {
        fprintf(stderr, "ed25519_sign failed: The signature that was generated is invalid.");
        r = -3;
        goto exit;
    }
    
    for (int i = 0; i < sizeof(signature); ++i)
    {
        fprintf(stdout, "%02x", signature[i]);
    }
    fprintf(stdout, "\n");
    r = 0;

exit:
    memset(signature, 0x00, sizeof(signature));
    memset(public_key, 0x00, sizeof(public_key));
    memset(private_key, 0x00, sizeof(private_key));
    
    return (r);
}
