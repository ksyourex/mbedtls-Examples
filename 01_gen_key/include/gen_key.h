#ifndef _GEN_KEY_H
#define _GEN_KEY_H

#include <string.h>
#include "mbedtls/havege.h"

int gen_key(unsigned char *key, int key_length);

#endif
