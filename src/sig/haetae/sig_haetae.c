// SPDX-License-Identifier: MIT

#include <stdlib.h>
#include <oqs/sig.h>
#include <oqs/sig_haetae.h>

#if defined(OQS_ENABLE_SIG_haetae)
static OQS_STATUS OQS_SIG_haetae_sign_with_ctx_str(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	(void) signature;
	(void) signature_len;
	(void) message;
	(void) message_len;
	(void) ctx_str;
	(void) ctx_str_len;
	(void) secret_key;
	return OQS_ERROR;
}

static OQS_STATUS OQS_SIG_haetae_verify_with_ctx_str(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	(void) message;
	(void) message_len;
	(void) signature;
	(void) signature_len;
	(void) ctx_str;
	(void) ctx_str_len;
	(void) public_key;
	return OQS_ERROR;
}

OQS_SIG *OQS_SIG_haetae_new(void) {

	OQS_SIG *sig = OQS_MEM_malloc(sizeof(OQS_SIG));
	if (sig == NULL) {
		return NULL;
	}
	sig->method_name = OQS_SIG_alg_haetae;
	sig->alg_version = "HAETAE submission package, mode 2";

	sig->claimed_nist_level = 2;
	sig->euf_cma = true;
	sig->suf_cma = false;
	sig->sig_with_ctx_support = false;

	sig->length_public_key = OQS_SIG_haetae_length_public_key;
	sig->length_secret_key = OQS_SIG_haetae_length_secret_key;
	sig->length_signature = OQS_SIG_haetae_length_signature;

	sig->keypair = OQS_SIG_haetae_keypair;
	sig->sign = OQS_SIG_haetae_sign;
	sig->verify = OQS_SIG_haetae_verify;
	sig->sign_with_ctx_str = OQS_SIG_haetae_sign_with_ctx_str;
	sig->verify_with_ctx_str = OQS_SIG_haetae_verify_with_ctx_str;

	return sig;
}

extern int cryptolab_haetae2_keypair(uint8_t *pk, uint8_t *sk);
extern int cryptolab_haetae2_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int cryptolab_haetae2_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

OQS_API OQS_STATUS OQS_SIG_haetae_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return cryptolab_haetae2_keypair(public_key, secret_key) == 0 ? OQS_SUCCESS : OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_haetae_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	return cryptolab_haetae2_signature(signature, signature_len, message, message_len, secret_key) == 0 ? OQS_SUCCESS : OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_haetae_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	return cryptolab_haetae2_verify(signature, signature_len, message, message_len, public_key) == 0 ? OQS_SUCCESS : OQS_ERROR;
}
#endif
