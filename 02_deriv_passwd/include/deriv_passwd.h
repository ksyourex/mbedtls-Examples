#ifndef _DERIV_PASSWD_H_
#define _DERIV_PASSWD_H_

#include <string.h>

#include "mbedtls/sha256.h"
#include "mbedtls/havege.h"

int deriv_passwd(unsigned char *key, char *password, unsigned char *salt, int salt_len, unsigned int iterations);

#endif
