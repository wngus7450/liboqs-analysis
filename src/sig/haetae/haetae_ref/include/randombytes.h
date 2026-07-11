#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <oqs/rand.h>
#include <stddef.h>
#include <stdint.h>

#define RNG_SUCCESS 0
#define RNG_BAD_MAXLEN -1
#define RNG_BAD_OUTBUF -2
#define RNG_BAD_REQ_LEN -3
#define RNG_FAIL_SYSCALL -4

static inline int randombytes(uint8_t *out, size_t outlen) {
    OQS_randombytes(out, outlen);
    return RNG_SUCCESS;
}

#endif
