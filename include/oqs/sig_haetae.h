// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_HAETAE_H
#define OQS_SIG_HAETAE_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_haetae)
#define OQS_SIG_haetae_length_public_key 992
#define OQS_SIG_haetae_length_secret_key 1408
#define OQS_SIG_haetae_length_signature 1463

OQS_SIG *OQS_SIG_haetae_new(void);
OQS_API OQS_STATUS OQS_SIG_haetae_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#endif
