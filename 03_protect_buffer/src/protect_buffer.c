#include "../include/protect_buffer.h"

const unsigned char padding[16] =
{
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char iv[16] =
{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/**
 * @param [out] output        ciphered buffer
 * @param [out] output_len    ciphered buffer length in bytes
 * @param [in]  input         plain text buffer
 * @param [in]  input_len     plain text buffer length in bytes
 * @param [in]  master_key    master key (km)
 * @param [in]  key_len       master key length in bytes
 * @param [in]  salt          salt
 * @param [in]  salt_len      salt length in bytes
 * @return      0 if OK, 1 else
 */

int protect_buffer(unsigned char **output, int *output_len,
		unsigned char *input, int input_len,
		unsigned char *master_key, int key_len,
		unsigned char *salt, int salt_len) {

	int i, pad_len, ret;
	unsigned char k_c[32];
	unsigned char k_i[32];
	unsigned char tmp_1[36];
	unsigned char *input_padd;
	unsigned char *cipher;

	mbedtls_aes_context aes_ctx;
	mbedtls_md_context_t md_ctx;
	const mbedtls_md_info_t *md_info;

	/* *** Init *** */
	i = 0;
	pad_len = 0;
	ret = 1;
	input_padd = NULL;
	cipher = NULL;

	/* *** Deriv MasterKey to CipherKey / IntegrityKey *** */
	i = 0;
	memcpy(tmp_1, master_key, 32);
	memcpy(tmp_1+32, &i, sizeof(int));
	mbedtls_sha256_ret(tmp_1, 36, k_c, 0);
	i ++;
	memcpy(tmp_1, master_key, 32);
	memcpy(tmp_1+32, &i, sizeof(int));
	mbedtls_sha256_ret(tmp_1, 36, k_i, 0);

	/* *** Padding *** */
	pad_len = 16 - (input_len % 16);
	input_padd = (unsigned char *) malloc((input_len + pad_len) * sizeof(char));
	if(input_padd == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	cipher = (unsigned char *)malloc((input_len + pad_len + 32) * sizeof(char));
	if(cipher == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	memcpy(input_padd, input, input_len);
	memcpy(input_padd+input_len, padding, pad_len);

	/* *** Chiffrement *** */
	mbedtls_aes_init(&aes_ctx);
	ret = mbedtls_aes_setkey_enc(&aes_ctx, k_c, 256);
	if(ret != 0) {
		fprintf(stderr, "error : aes_setkey_enc failed\n");
		ret = 1;
		goto cleanup;
	}
	ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, (size_t)
			(input_len + pad_len), iv, input_padd, cipher);
	if(ret != 0) {
		fprintf(stderr, "error : aes_crypt_cbc failed\n");
		ret = 1;
		goto cleanup;
	}

	/* *** Ajout du controle d'integrite ***  */  
	mbedtls_md_init(&md_ctx);
	md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	mbedtls_md_setup(&md_ctx,md_info, 1);
	mbedtls_md_hmac_starts(&md_ctx , master_key, key_len);
	mbedtls_md_hmac_update(&md_ctx, cipher, input_len + pad_len);
	ret = mbedtls_md_finish(&md_ctx, &cipher[input_len + pad_len]);

	*output = cipher;
	*output_len = input_len + pad_len + 32;
	ret = 0;

cleanup:
	if(input_padd != NULL) {
		memset(input_padd, 0x00, input_len + pad_len);
		free(input_padd);
	}

	memset(&aes_ctx, 0x00, sizeof(mbedtls_aes_context));
	memset(master_key, 0x00, 32);
	memset(k_c, 0x00, 32);
	memset(k_i, 0x00, 32);
	memset(tmp_1, 0x00, 36);

	pad_len = 0;
	i = 0;

	return ret;

}


