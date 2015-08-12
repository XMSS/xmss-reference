#include <stdio.h>
#include "../wots.h"
#include "../randombytes.h"

static void hexdump(unsigned char *a, size_t len)
{
  size_t i;
  for (i = 0; i < len; i++)
    printf("%02x", a[i]);
}

int main()
{
unsigned char seed[32];
unsigned char pub_seed[32];
wots_params params;
wots_set_params(&params, 32, 32, 16);

int sig_len = params.len*params.n;

unsigned char pk1[sig_len];
unsigned char pk2[sig_len];
unsigned char sig[sig_len];
unsigned char addr[16] = {1,2,3,4};

  unsigned char msg[32];
  int i;

  randombytes(seed, 32);
  randombytes(pub_seed, 32);
  randombytes(msg, 32);
  //randombytes(addr, 16);

  wots_pkgen(pk1, seed, &params, pub_seed, addr);
  wots_sign(sig, msg, seed, &params, pub_seed, addr);
  wots_pkFromSig(pk2, sig, msg, &params, pub_seed, addr);

  for(i=0;i<sig_len;i++)
    if(pk1[i] != pk2[i])
    {
      printf("pk1 != pk2 %d\n",i);
      return -1;
    }
  printf("worked great!\npk1: ");
  hexdump(pk1, sig_len);
  printf("\npk2: ");
  hexdump(pk2, sig_len);
  printf("\nsig: ");
  hexdump(sig, sig_len);
  printf("\n");
  
  return 0;
}
