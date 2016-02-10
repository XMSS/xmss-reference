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
  int n = 32;
  unsigned char seed[32] = {0};
//   unsigned char seed[64] = {0,0};

  unsigned char out[2*n];
  unsigned char addr[16] = {2};

  printf("Case 1: All 0\n");
  prg(out, 2*n, seed, n);

  printf("\n");
  hexdump(out, 2*n);
  printf("\n");

  printf("Case 2: key = 1\n");
  seed[31] = 1;
  prg_with_counter(out, seed, n, addr);

  printf("\n");
  hexdump(out, n);
  printf("\n");
  return 0;
}
