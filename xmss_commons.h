/*
xmss_commons.h version 20151120
Andreas Hülsing
Public domain.
*/
#ifndef XMSS_COMMONS_H
#define XMSS_COMMONS_H

#include <stdlib.h>

void to_byte(unsigned char *output, unsigned int in, int bytes);
void hexdump(const unsigned char *a, size_t len);
#endif