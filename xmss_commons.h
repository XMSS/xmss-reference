#ifndef XMSS_COMMONS_H
#define XMSS_COMMONS_H

#include <stdlib.h>

void to_byte(unsigned char *output, uint in, int bytes);
void hexdump(const unsigned char *a, size_t len);
#endif