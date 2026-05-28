// SPDX-License-Identifier: MIT

#include <oqs/oqs.h>
#include <oqs/sig_stfl.h>

OQS_API OQS_STATUS OQS_SIG_STFL_verify(const OQS_SIG_STFL *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
	(void)sig;
	(void)message;
	(void)message_len;
	(void)signature;
	(void)signature_len;
	(void)public_key;
	return OQS_ERROR;
}
