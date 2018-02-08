#include "../include/gen_key.h"

int gen_key(unsigned char *key, int key_length) {
	int ret;
	mbedtls_havege_state ctx;

	/* *** Init *** */
	ret = 1; 

	/* *** check argument *** */
	if (key == NULL || key_length <= 0)
		goto cleanup;

	mbedtls_havege_init(&ctx);
	ret = mbedtls_havege_random(&ctx, key, key_length);

cleanup:
	memset(&ctx, 0x00, sizeof(mbedtls_havege_state));
	return ret;
}
