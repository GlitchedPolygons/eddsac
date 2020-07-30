#ifndef OSRAND_H
#define OSRAND_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef _WIN32
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#endif

/**
 * (Tries to) read from <c>/dev/urandom</c> (or Windows equivalent, yeah...) filling the given \p output_buffer with \p output_buffer_size random bytes.
 * @param output_buffer Where to write the random bytes into.
 * @param output_buffer_size How many random bytes to write into \p output_buffer
 */
static inline void eddsac_dev_urandom(uint8_t* output_buffer, const size_t output_buffer_size)
{
    if (output_buffer != NULL && output_buffer_size > 0)
    {
#ifdef _WIN32
        BCryptGenRandom(NULL, output_buffer, output_buffer_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
        FILE* rnd = fopen("/dev/urandom", "rb");
        if (rnd != NULL)
        {
            fread(output_buffer, sizeof(uint8_t), output_buffer_size, rnd);
            fclose(rnd);
        }
#endif
    }
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // OSRAND_H
