#ifndef BIN2HEXSTR_H
#define BIN2HEXSTR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

static int eddsac_bin2hexstr(const unsigned char* bin, const size_t bin_length, char* output, const size_t output_size, size_t* output_length, const unsigned char uppercase)
{
    if (bin == NULL || bin_length == 0 || output == NULL)
    {
        return 1;
    }

    const size_t final_length = bin_length * 2;

    if (output_size < final_length + 1)
    {
        return 2;
    }

    const char* format = uppercase ? "%02X" : "%02x";

    for (size_t i = 0; i < bin_length; i++)
    {
        sprintf(output + i * 2, format, bin[i]);
    }

    output[final_length] = '\0';

    if (output_length != NULL)
    {
        *output_length = final_length;
    }

    return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // BIN2HEXSTR_H