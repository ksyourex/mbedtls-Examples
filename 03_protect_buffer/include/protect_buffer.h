#ifndef _PROTECT_BUFFER_H_
#define _PROTECT_BUFFER_H_

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "mbedtls/sha256.h"
#include "mbedtls/havege.h"
#include "mbedtls/aes.h"
#include "mbedtls/md.h"

int protect_buffer(unsigned char **output, int *output_len, 
		unsigned char *input, int input_len,
		unsigned char *master_key, int key_len,
		unsigned char *salt, int salt_len);

#endif
