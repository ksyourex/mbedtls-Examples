#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include "../include/mbedtls/sha256.h"
#include "../include/mbedtls/havege.h"

/* HOW TO :
 *  make
 *  make deriv_passwd
 * ./bin/deriv_passwd myPassword mySalt nbIter
 * ex: ./bin/deriv_passwd qwerty salt 15
 */

int print_hex(unsigned char *buffer, int buffer_len, char *id) {
	int i;

	printf(">>> %s\n", id);
	for(i = 0; i < buffer_len; i++)
		printf("%02X", buffer[i]);
	printf("\n");
	
	return 0;
}

/**
 * @param [out] key           (32 bytes)
 * @param [in]  password      user password
 * @param [in]  salt          salt
 * @param [in]  salt_len      salt length in bytes
 * @param [in]  iterations    number of iterations
 * @return      0 if OK, 1 else
 */
int deriv_passwd(unsigned char *key, char *password, unsigned char *salt, int salt_len,unsigned int iterations) {
	int ret;
	unsigned int i;
	unsigned char hash[32];
	mbedtls_sha256_context ctx;

	/* *** Init *** */
	ret = 1; // error
	i = 0;

	/* *** Check args *** */
	if((key == NULL) || (password == NULL) || (salt == NULL) 
		|| (salt_len <= 0) || (iterations == 0))
		goto cleanup;

	/* *** Get H0 *** */
	mbedtls_sha256_starts_ret(&ctx, 0);
	mbedtls_sha256_update_ret(&ctx, (unsigned char *)password, strlen(password));
	mbedtls_sha256_update_ret(&ctx, salt, salt_len);
	mbedtls_sha256_update_ret(&ctx, (unsigned char *)&i, sizeof(int));
	mbedtls_sha256_finish_ret(&ctx, hash); //hash == HO

	/* *** Hi *** */
	for(i = 1; i < iterations; i++)	{
		mbedtls_sha256_starts_ret(&ctx, 0);
		mbedtls_sha256_update_ret(&ctx, hash, 32);
		mbedtls_sha256_update_ret(&ctx, (unsigned char *)password,
			    strlen(password));
		mbedtls_sha256_update_ret(&ctx, salt, salt_len);
		mbedtls_sha256_update_ret(&ctx, (unsigned char *)&i, sizeof(int));
		mbedtls_sha256_finish_ret(&ctx, hash);
	}
	memcpy(key, hash, 32);

	ret = 0;

cleanup:
	memset(&ctx, 0x00, sizeof(mbedtls_sha256_context));
	memset(hash, 0x00, 32);
	return ret;
}

int gen_key(unsigned char *key, int key_length) {
	int ret;
	mbedtls_havege_state ctx;

	ret = 1; 

	/* *** check argument *** */
	if((key == NULL) || (key_length <= 0))
		goto cleanup;

	mbedtls_havege_init(&ctx);

	ret = mbedtls_havege_random(&ctx, key, key_length);
cleanup:
	//memset(&ctx, 0x00, sizeof(mbedtls_havege_state));
	return ret;
}

int main(int argc, char **argv) {
	int ret, password_len, salt_len;
	unsigned char key[32];
	unsigned int iterations;
	char *password;
	unsigned char *salt;

	/* *** check parameters *** */
	if (argc != 4) {
		fprintf(stderr, "usage : %s <password> <salt> <iterations>\n", argv[0]);
		return 1;
	}
	else if (strlen(argv[1]) > 32) {
		fprintf(stderr, "error : password too long (32 characters max)\n");
		return 1;
	}
	else if (strlen(argv[2]) > 16) { 
		fprintf(stderr, "error : salt too long (16 charachers max)\n");
		return 1;
	}
	else if (!atoi(argv[3]) || atoi(argv[3]) < 1) {
		fprintf(stderr, "error : number of iterations must be a positive integer\n");
		return 1;
	}

	/* *** initialization *** */
	password = NULL;
	salt = NULL;
	ret = 1;

	/* *** get password *** */
	password_len = strlen(argv[1]);
	password = (char *) malloc(sizeof(char) * (password_len + 1));
	if (password ==  NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	strcpy(password, argv[1]);
	password[password_len] = '\0';

	/* *** get salt *** */
	salt_len = strlen(argv[2]);
	salt = (unsigned char *) malloc(sizeof(unsigned char) * salt_len);
	if (salt == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;	
	}
	memcpy(salt, argv[2], salt_len);

	/* *** get number of iterations *** */
	iterations = atoi(argv[3]);

	/* *** deriv password *** */
	ret = deriv_passwd(key, password, salt, salt_len, iterations);
	if(ret != 0)
		goto cleanup;

	/* *** print the key *** */
	print_hex(key, 32, "key = ");

	ret = 0;

cleanup:
	/* *** cleanup and return *** */
	memset(key, 0x00, 32);

	if (password != NULL) {
		memset(password, 0x00, password_len);
		free(password);
	}
	password_len = 0;
	
	if (salt != NULL) {
		memset(salt, 0x00, salt_len);
		free(salt);
	}
	salt_len = 0;

	iterations = 0;

	return ret;
}
