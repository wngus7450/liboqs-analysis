// SPDX-License-Identifier: MIT

#include <oqs/sha3x4.h>

void OQS_SHA3_shake128_x4_absorb_once(
    OQS_SHA3_shake128_x4_inc_ctx *state,
    const uint8_t *in0,
    const uint8_t *in1,
    const uint8_t *in2,
    const uint8_t *in3,
    size_t inlen) {
	OQS_SHA3_shake128_x4_inc_absorb(state, in0, in1, in2, in3, inlen);
	OQS_SHA3_shake128_x4_inc_finalize(state);
}

void OQS_SHA3_shake256_x4_absorb_once(
    OQS_SHA3_shake256_x4_inc_ctx *state,
    const uint8_t *in0,
    const uint8_t *in1,
    const uint8_t *in2,
    const uint8_t *in3,
    size_t inlen) {
	OQS_SHA3_shake256_x4_inc_absorb(state, in0, in1, in2, in3, inlen);
	OQS_SHA3_shake256_x4_inc_finalize(state);
}
