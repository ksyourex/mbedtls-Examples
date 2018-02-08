#include "../include/main.h"

/* HOW TO :
 *  make
 *  make deriv_passwd
 * ./bin/deriv_passwd myPassword mySalt nbIter
 * ex: ./bin/deriv_passwd qwerty salt 15
 */

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

