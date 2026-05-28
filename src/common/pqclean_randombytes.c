// SPDX-License-Identifier: MIT

#include <oqs/rand.h>

void randombytes(unsigned char *out, unsigned long long outlen) {
	OQS_randombytes(out, (size_t)outlen);
}
