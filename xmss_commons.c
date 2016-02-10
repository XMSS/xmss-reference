/*
xmss_commons.c version 20151120
Andreas Hülsing
Public domain.
*/

#include "xmss_commons.h"
#include <stdlib.h>
#include <stdio.h>

void to_byte(unsigned char *out, unsigned int in, int bytes)
{
  int i;
  for(i = 0; i < bytes; i++){
    out[i] = in & 0xff;
    in = in >> 8;
  }
}

void hexdump(const unsigned char *a, size_t len)
{
  size_t i;
  for (i = 0; i < len; i++)
    printf("%02x", a[i]);
}