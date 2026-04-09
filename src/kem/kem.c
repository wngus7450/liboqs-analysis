// SPDX-License-Identifier: MIT

#include <assert.h>
#include <stdlib.h>
#if defined(_WIN32)
#include <string.h>
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif
#include <oqs/kem.h>
#include <oqs/oqs.h>

OQS_API const char *OQS_KEM_alg_identifier(size_t i) {
	// EDIT-WHEN-ADDING-KEM
	const char *a[OQS_KEM_algs_length] = {
		// OQS_KEM_alg_hqc_128,
		// OQS_KEM_alg_hqc_192,
		// OQS_KEM_alg_hqc_256,
		OQS_KEM_alg_ml_kem_512,
		OQS_KEM_alg_ml_kem_768,
		OQS_KEM_alg_ml_kem_1024,
	};
	if (i >= OQS_KEM_algs_length) {
		return NULL;
	} else {
		return a[i];
	}
}

OQS_API int OQS_KEM_alg_count(void) {
	return OQS_KEM_algs_length;
}

OQS_API int OQS_KEM_alg_is_enabled(const char *method_name) {
	if (method_name == NULL) {
		return 0;
	} 
// else if (0 == strcasecmp(method_name, OQS_KEM_alg_hqc_128)) {
// #ifdef OQS_ENABLE_KEM_hqc_128
// 		return 1;
// #else
// 		return 0;
// #endif
// 
// 	} else if (0 == strcasecmp(method_name, OQS_KEM_alg_hqc_192)) {
// #ifdef OQS_ENABLE_KEM_hqc_192
// 		return 1;
// #else
// 		return 0;
// #endif
// 
// 	} else if (0 == strcasecmp(method_name, OQS_KEM_alg_hqc_256)) {
// #ifdef OQS_ENABLE_KEM_hqc_256
// 		return 1;
// #else
// 		return 0;
// #endif
// 	} 
	else if (0 == strcasecmp(method_name, OQS_KEM_alg_ml_kem_512)) {
#ifdef OQS_ENABLE_KEM_ml_kem_512
		return 1;
#else
		return 0;
#endif

	} else if (0 == strcasecmp(method_name, OQS_KEM_alg_ml_kem_768)) {
#ifdef OQS_ENABLE_KEM_ml_kem_768
		return 1;
#else
		return 0;
#endif

	} else if (0 == strcasecmp(method_name, OQS_KEM_alg_ml_kem_1024)) {
#ifdef OQS_ENABLE_KEM_ml_kem_1024
		return 1;
#else
		return 0;
#endif

		///// OQS_COPY_FROM_UPSTREAM_FRAGMENT_ENABLED_CASE_END
	} 
}

OQS_API OQS_KEM *OQS_KEM_new(const char *method_name) {
	if (method_name == NULL) {
		return NULL;
	}

// else if (0 == strcasecmp(method_name, OQS_KEM_alg_hqc_128)) {
// #ifdef OQS_ENABLE_KEM_hqc_128
// 		return OQS_KEM_hqc_128_new();
// #else
// 		return NULL;
// #endif
// 
// 	} else if (0 == strcasecmp(method_name, OQS_KEM_alg_hqc_192)) {
// #ifdef OQS_ENABLE_KEM_hqc_192
// 		return OQS_KEM_hqc_192_new();
// #else
// 		return NULL;
// #endif
// 
// 	} else if (0 == strcasecmp(method_name, OQS_KEM_alg_hqc_256)) {
// #ifdef OQS_ENABLE_KEM_hqc_256
// 		return OQS_KEM_hqc_256_new();
// #else
// 		return NULL;
// #endif
// 
// 	}
	else if (0 == strcasecmp(method_name, OQS_KEM_alg_ml_kem_512)) {
#ifdef OQS_ENABLE_KEM_ml_kem_512
		return OQS_KEM_ml_kem_512_new();
#else
		return NULL;
#endif

	} else if (0 == strcasecmp(method_name, OQS_KEM_alg_ml_kem_768)) {
#ifdef OQS_ENABLE_KEM_ml_kem_768
		return OQS_KEM_ml_kem_768_new();
#else
		return NULL;
#endif

	} else if (0 == strcasecmp(method_name, OQS_KEM_alg_ml_kem_1024)) {
#ifdef OQS_ENABLE_KEM_ml_kem_1024
		return OQS_KEM_ml_kem_1024_new();
#else
		return NULL;
#endif

		///// OQS_COPY_FROM_UPSTREAM_FRAGMENT_NEW_CASE_END
	} 
}

OQS_API OQS_STATUS OQS_KEM_keypair_derand(const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed) {
	if (kem == NULL) {
		return OQS_ERROR;
	} else {
		return kem->keypair_derand(public_key, secret_key, seed);
	}
}

OQS_API OQS_STATUS OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key) {
	if (kem == NULL) {
		return OQS_ERROR;
	} else {
		return kem->keypair(public_key, secret_key);
	}
}

OQS_API OQS_STATUS OQS_KEM_encaps_derand(const OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const uint8_t *seed) {
	if (kem == NULL) {
		return OQS_ERROR;
	} else {
		return kem->encaps_derand(ciphertext, shared_secret, public_key, seed);
	}
}

OQS_API OQS_STATUS OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	if (kem == NULL) {
		return OQS_ERROR;
	} else {
		return kem->encaps(ciphertext, shared_secret, public_key);
	}
}

OQS_API OQS_STATUS OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	if (kem == NULL) {
		return OQS_ERROR;
	} else {
		return kem->decaps(shared_secret, ciphertext, secret_key);
	}
}

OQS_API void OQS_KEM_free(OQS_KEM *kem) {
	OQS_MEM_insecure_free(kem);
}
