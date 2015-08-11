#include <stdio.h>
#include "../prg.h"

static void hexdump(unsigned char *a, size_t len)
{
  size_t i;
  for (i = 0; i < len; i++)
    printf("%02x", a[i]);
}


int main()
{
  unsigned char seed[32] = {0};
  unsigned char out[64];
  unsigned char addr[16] = {2};

  printf("Case 1: All 0\n");
  prg(out, 64, seed, 32);

  printf("\n");
  hexdump(out, 64);
  printf("\n");
  
  printf("Case 2: key = 1\n");
  seed[31] = 1;
  prg_with_counter(out, 64, seed, 32, addr);

  printf("\n");
  hexdump(out, 64);
  printf("\n");
  return 0;
}
