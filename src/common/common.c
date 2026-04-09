// SPDX-License-Identifier: Apache-2.0 AND MIT

#if !defined(OQS_USE_OPENSSL) && !defined(_WIN32) && !defined(OQS_HAVE_EXPLICIT_BZERO) && !defined(OQS_HAVE_EXPLICIT_MEMSET)
// Request memset_s
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include <oqs/common.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stddef.h>

#if defined(OQS_DIST_BUILD) && defined(OQS_USE_PTHREADS)
#include <pthread.h>
#endif

#if !defined(OQS_HAVE_POSIX_MEMALIGN) || defined(__MINGW32__) || defined(__MINGW64__) || defined(_MSC_VER)
#include <malloc.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

/* Identifying the CPU is expensive so we cache the results in cpu_ext_data */
#if defined(OQS_DIST_BUILD)
static unsigned int cpu_ext_data[OQS_CPU_EXT_COUNT] = {0};
#if defined(OQS_USE_PTHREADS)
static pthread_once_t once_control = PTHREAD_ONCE_INIT;
#endif
#endif

#if defined(OQS_DIST_BUILD)
static void set_available_cpu_extensions(void) {
	cpu_ext_data[OQS_CPU_EXT_INIT] = 1;
}
#endif

OQS_API int OQS_CPU_has_extension(OQS_CPU_EXT ext) {
#if defined(OQS_DIST_BUILD)
#if defined(OQS_USE_PTHREADS)
	pthread_once(&once_control, &set_available_cpu_extensions);
#else
	if (0 == cpu_ext_data[OQS_CPU_EXT_INIT]) {
		set_available_cpu_extensions();
	}
#endif
	if (0 < ext && ext < OQS_CPU_EXT_COUNT) {
		return (int)cpu_ext_data[ext];
	}
#else
	(void)ext;
#endif
	return 0;
}

OQS_API void OQS_init(void) {
#if defined(OQS_DIST_BUILD)
	OQS_CPU_has_extension(OQS_CPU_EXT_INIT);
#endif
}

OQS_API void OQS_thread_stop(void) {
}

OQS_API const char *OQS_version(void) {
	return OQS_VERSION_TEXT;
}

OQS_API void OQS_destroy(void) {
}

OQS_API int OQS_MEM_secure_bcmp(const void *a, const void *b, size_t len) {
	/* Assume CHAR_BIT = 8 */
	uint8_t r = 0;

	for (size_t i = 0; i < len; i++) {
		r |= ((const uint8_t *)a)[i] ^ ((const uint8_t *)b)[i];
	}

	// We have 0 <= r < 256, and unsigned int is at least 16 bits.
	return 1 & ((-(unsigned int)r) >> 8);
}

OQS_API void OQS_MEM_cleanse(void *ptr, size_t len) {
	if (ptr == NULL) {
		return;
	}
#if defined(_WIN32)
	SecureZeroMemory(ptr, len);
#elif defined(OQS_HAVE_EXPLICIT_BZERO)
	explicit_bzero(ptr, len);
#elif defined(OQS_HAVE_EXPLICIT_MEMSET)
	explicit_memset(ptr, 0, len);
#elif defined(__STDC_LIB_EXT1__) || defined(OQS_HAVE_MEMSET_S)
	if (0U < len && memset_s(ptr, (rsize_t)len, 0, (rsize_t)len) != 0) {
		abort();
	}
#else
	typedef void *(*memset_t)(void *, int, size_t);
	static volatile memset_t memset_func = memset;
	memset_func(ptr, 0, len);
#endif
}

OQS_API void OQS_MEM_secure_free(void *ptr, size_t len) {
	if (ptr != NULL) {
		OQS_MEM_cleanse(ptr, len);
		OQS_MEM_insecure_free(ptr);
	}
}

OQS_API void OQS_MEM_insecure_free(void *ptr) {
	free(ptr); // IGNORE memory-check
}

void *OQS_MEM_aligned_alloc(size_t alignment, size_t size) {
#if defined(OQS_HAVE_ALIGNED_ALLOC) // glibc and other implementations providing aligned_alloc
	return aligned_alloc(alignment, size);
#else
	// Check alignment (power of 2, and >= sizeof(void*)) and size (multiple of alignment)
	if (alignment & (alignment - 1) || size & (alignment - 1) || alignment < sizeof(void *)) {
		errno = EINVAL;
		return NULL;
	}

#if defined(OQS_HAVE_POSIX_MEMALIGN)
	void *ptr = NULL;
	const int err = posix_memalign(&ptr, alignment, size);
	if (err) {
		errno = err;
		ptr = NULL;
	}
	return ptr;
#elif defined(OQS_HAVE_MEMALIGN)
	return memalign(alignment, size);
#elif defined(__MINGW32__) || defined(__MINGW64__)
	return __mingw_aligned_malloc(size, alignment);
#elif defined(_MSC_VER)
	return _aligned_malloc(size, alignment);
#else
	if (!size) {
		return NULL;
	}
	// Overallocate to be able to align the pointer (alignment -1) and to store
	// the difference between the pointer returned to the user (ptr) and the
	// pointer returned by malloc (buffer). The difference is caped to 255 and
	// can be made larger if necessary, but this should be enough for all users
	// in liboqs.
	//
	// buffer      ptr
	// ↓           ↓
	// ...........|...................
	//            |
	//       diff = ptr - buffer
	const size_t offset = alignment - 1 + sizeof(uint8_t);
	uint8_t *buffer = malloc(size + offset); // IGNORE memory-check
	if (!buffer) {
		return NULL;
	}

	// Align the pointer returned to the user.
	uint8_t *ptr = (uint8_t *)(((uintptr_t)(buffer) + offset) & ~(alignment - 1));
	ptrdiff_t diff = ptr - buffer;
	if (diff > UINT8_MAX) {
		// This should never happen in our code, but just to be safe
		free(buffer); // IGNORE memory-check
		errno = EINVAL;
		return NULL;
	}
	// Store the difference one byte ahead the returned poitner so that free
	// can reconstruct buffer.
	ptr[-1] = diff;
	return ptr;
#endif
#endif
}

void OQS_MEM_aligned_free(void *ptr) {
	if (ptr == NULL) {
		return;
	}
#if defined(OQS_HAVE_ALIGNED_ALLOC) || defined(OQS_HAVE_POSIX_MEMALIGN) || defined(OQS_HAVE_MEMALIGN)
	free(ptr); // IGNORE memory-check
#elif defined(__MINGW32__) || defined(__MINGW64__)
	__mingw_aligned_free(ptr);
#elif defined(_MSC_VER)
	_aligned_free(ptr);
#else
	// Reconstruct the pointer returned from malloc using the difference
	// stored one byte ahead of ptr.
	uint8_t *u8ptr = ptr;
	free(u8ptr - u8ptr[-1]); // IGNORE memory-check
#endif
}

void OQS_MEM_aligned_secure_free(void *ptr, size_t len) {
	OQS_MEM_cleanse(ptr, len);
	OQS_MEM_aligned_free(ptr);
}

OQS_API void *OQS_MEM_malloc(size_t size) {
	return malloc(size); // IGNORE memory-check
}

OQS_API void *OQS_MEM_calloc(size_t num_elements, size_t element_size) {
	return calloc(num_elements, element_size); // IGNORE memory-check
}

OQS_API char *OQS_MEM_strdup(const char *str) {
	return strdup(str); // IGNORE memory-check
}
