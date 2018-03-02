#include "../include/main.h"

/*
 * HOW TO :
 * make
 * make protect_buffer
 * ./bin/protect_buffer myPassword message
 * ex : ./bin/protect_buffer qwerty HelloWorld
 */

int main(int argc, char **argv) {
	int ret, password_len, input_len, output_len, salt_len;
	unsigned char key[32]; //SHA256 used
	unsigned char k_m[32]; //masterkey
	int key_len = 32;
	unsigned char salt[8];
	unsigned char *input;
	unsigned int iterations;
	char *password;
	unsigned char *output;

	mbedtls_havege_state prng_ctx; // PRNG context

	/* *** check parameters *** */
	if (argc != 3) {
		fprintf(stderr, "usage : %s <password> <message>\n", argv[0]);
		return 1;
	}

	/* *** Init *** */
	ret = 1;
	password = NULL;
	input = NULL;
	output = NULL;
	password_len = 0;
	input_len = 0;
	output_len = 0;
	iterations = 0;

	/* *** Get Password *** */
	password_len = strlen(argv[1]);
	password = (char *) malloc(sizeof(char) * (password_len + 1));
	
	if (password == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;	
	}
	strcpy(password, argv[1]);
	password[password_len] = '\0';

	/* *** Set Input Text *** */
	input_len = strlen(argv[2]);
	input = (unsigned char *) malloc(input_len + 1);
	
	if (input == NULL) {
		fprintf(stderr, "error : memory allocation failed\n");
		ret = 1;
		goto cleanup;
	}
	strcpy((char *)input, argv[2]);
	input[input_len] = '\0';

	/* *** Set Salt *** */
	mbedtls_havege_init(&prng_ctx);
	mbedtls_havege_random(&prng_ctx, (unsigned char *)salt, sizeof(salt));

	/* *** Print Salt *** */
	printf("Salt = %s \n", salt);
	print_hex(salt, 8, "Salt hex");

	/* *** Set Salt Length *** */
	salt_len = 8;

	/* *** Set Number of Iterations *** */
	iterations = 1<<5; //32

	/* *** Deriv password to MasterKey *** */
	ret = deriv_passwd(k_m, password, salt, salt_len, iterations);
	
	if(ret != 0) {
		fprintf(stderr, "error: deriv_passwd failed\n");
		return 1;
	}

	print_hex(k_m, 32, "MasterKey");

	/* *** protect buffers *** */
	ret = protect_buffer(&output, &output_len, input, input_len,
			k_m, key_len , salt, salt_len);

	/* *** print protect buffer *** */
	printf(">>> ret : %d\n", ret);
	print_hex(output, output_len, "OUTPUT");

	ret = 0;

cleanup:
	/* *** cleanup and return *** */
	memset(key, 0x00, 32);

	if (password != NULL) {
		memset(password, 0x00, password_len);
		free(password);
	}
	password_len = 0;

	if (input != NULL) {
		memset(input, 0x00, input_len);
		free(input);
	}
	input_len = 0;
	memset(salt, 0x00, 8);

	if (output != NULL) {
		memset(output, 0x00, output_len);
		free(output);
	}
	output_len = 0;
	iterations = 0;

	return ret;
}
