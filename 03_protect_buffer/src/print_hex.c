#include "../include/print_hex.h"

int print_hex(unsigned char *buffer, int buffer_len, char *id) {
	int i;
	
	printf(">>> %s\n", id);
	for(i = 0; i < buffer_len; i++)
		printf("%02X", buffer[i]);
	    printf("\n");
	
	return 0;
}

