// SPDX-License-Identifier: MIT

#include <oqs/sha3.h>

void OQS_SHA3_shake128_absorb_once(OQS_SHA3_shake128_inc_ctx *state, const uint8_t *in, size_t inlen) {
	OQS_SHA3_shake128_inc_absorb(state, in, inlen);
	OQS_SHA3_shake128_inc_finalize(state);
}

void OQS_SHA3_shake256_absorb_once(OQS_SHA3_shake256_inc_ctx *state, const uint8_t *in, size_t inlen) {
	OQS_SHA3_shake256_inc_absorb(state, in, inlen);
	OQS_SHA3_shake256_inc_finalize(state);
}
