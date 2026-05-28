// SPDX-License-Identifier: MIT

#include <oqs/oqs.h>
#include <oqs/sig.h>
#include <oqs/sig_stfl.h>

OQS_API const char *OQS_SIG_alg_identifier(size_t i) {
	if (i == 0) {
		return OQS_SIG_alg_ml_dsa_44;
	} else if (i == 1) {
		return OQS_SIG_alg_ml_dsa_65;
	} else if (i == 2) {
		return OQS_SIG_alg_ml_dsa_87;
	}
	return "disabled";
}

OQS_API int OQS_SIG_alg_count(void) {
	return OQS_SIG_algs_length;
}

OQS_API int OQS_SIG_alg_is_enabled(const char *method_name) {
	(void)method_name;
	return 0;
}

OQS_API OQS_SIG *OQS_SIG_new(const char *method_name) {
	(void)method_name;
	return NULL;
}

OQS_API OQS_STATUS OQS_SIG_keypair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key) {
	(void)sig;
	(void)public_key;
	(void)secret_key;
	return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
	(void)sig;
	(void)signature;
	(void)signature_len;
	(void)message;
	(void)message_len;
	(void)secret_key;
	return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	(void)sig;
	(void)message;
	(void)message_len;
	(void)signature;
	(void)signature_len;
	(void)public_key;
	return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_sign_with_ctx_str(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *secret_key) {
	(void)sig;
	(void)signature;
	(void)signature_len;
	(void)message;
	(void)message_len;
	(void)ctx_str;
	(void)ctx_str_len;
	(void)secret_key;
	return OQS_ERROR;
}

OQS_API OQS_STATUS OQS_SIG_verify_with_ctx_str(const OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *ctx_str, size_t ctx_str_len, const uint8_t *public_key) {
	(void)sig;
	(void)message;
	(void)message_len;
	(void)signature;
	(void)signature_len;
	(void)ctx_str;
	(void)ctx_str_len;
	(void)public_key;
	return OQS_ERROR;
}

OQS_API void OQS_SIG_free(OQS_SIG *sig) {
	OQS_MEM_insecure_free(sig);
}

OQS_API OQS_STATUS OQS_SIG_STFL_verify(const OQS_SIG_STFL *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	(void)sig;
	(void)message;
	(void)message_len;
	(void)signature;
	(void)signature_len;
	(void)public_key;
	return OQS_ERROR;
}
