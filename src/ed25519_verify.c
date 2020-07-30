
#include <string.h>
#include <stdio.h>
#include <decaf.h>
#include <decaf/spongerng.h>
#include <decaf/point_255.h>
#include <decaf/ed255.h>
#include <decaf/shake.h>
#include "hexstr2bin.h"

int main(const int argc, const char* argv[])
{
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0))
    {
        fprintf(stdout, "ed25519_verify:  Verify an Ed25519 signature using a specific public key. Call this program using exactly 3 arguments;  the FIRST one being the PUBLIC KEY (hex-string), the SECOND one being the SIGNATURE to verify (also a hex-string) and the THIRD one the actual STRING TO VERIFY the signature against.\n");
        return 0;
    }

    if (argc != 4)
    {
        fprintf(stderr, "ed25519_verify: wrong argument count. Check out \"ed25519_verify --help\" for more details about how to use this!\n");
        return -1;
    }

    int r = -1;

    uint8_t public_key[DECAF_EDDSA_25519_PUBLIC_BYTES + 1];
    uint8_t signature[DECAF_EDDSA_25519_SIGNATURE_BYTES + 1]; 

    uint8_t* ctx = NULL; 
    uint8_t ctx_size = 0;

    const char* public_key_hexstr = argv[1];
    const size_t public_key_hexstr_length = strlen(public_key_hexstr);

    const char* signature_hexstr = argv[2];
    const size_t signature_hexstr_length = strlen(signature_hexstr);

    const char* message = argv[3];
    const size_t message_length = strlen(message);

    if (public_key_hexstr_length != DECAF_EDDSA_25519_PUBLIC_BYTES * 2)
    {
        fprintf(stderr, "ed25519_verify failed: Invalid public key format/length!\n");
        r = -2;
        goto exit;
    }

    if (signature_hexstr_length != DECAF_EDDSA_25519_SIGNATURE_BYTES * 2)
    {
        fprintf(stderr, "ed25519_verify failed: Invalid signature format/length!\n");
        r = -2;
        goto exit;
    }

    if (eddsac_hexstr2bin(public_key_hexstr, public_key_hexstr_length, public_key, sizeof(public_key), NULL) != 0)
    {
        fprintf(stderr, "ed25519_verify failed: Invalid public key format/length!\n");
        r = -2;
        goto exit;
    }

    if (eddsac_hexstr2bin(signature_hexstr, signature_hexstr_length, signature, sizeof(signature), NULL) != 0)
    {
        fprintf(stderr, "ed25519_verify failed: Invalid signature format/length!\n");
        r = -2;
        goto exit;
    }

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
        fprintf(stderr, "ed25519_verify failed: The signature is invalid.\n");
        r = -3;
        goto exit;
    }
    
    fprintf(stdout, "ed25519_verify: Success! The signature is valid.\n");
    r = 0;

exit:
    memset(signature, 0x00, sizeof(signature));
    memset(public_key, 0x00, sizeof(public_key));
    
    return (r);
}
