#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include "../wots.h"
#include "../randombytes.h"
#include "../params.h"

static void hexdump(unsigned char *a, size_t len)
{
  size_t i;
  for (i = 0; i < len; i++)
    printf("%02x", a[i]);
}

int main()
{
  xmss_params params;
  // TODO test more different OIDs
  uint32_t oid = 0x01000001;
  xmssmt_parse_oid(&params, oid);

  unsigned char seed[params.n];
  unsigned char pub_seed[params.n];

  int sig_len = params.wots_len*params.n;

  unsigned char pk1[sig_len];
  unsigned char pk2[sig_len];
  unsigned char sig[sig_len];
  uint32_t addr[8] = {1,2,3,4};

  unsigned char msg[params.n];
  int i;

  randombytes(seed, params.n);
  randombytes(pub_seed, params.n);
  randombytes(msg, params.n);
  //randombytes(addr, 16);

  wots_pkgen(&params, pk1, seed, pub_seed, addr);
  wots_sign(&params, sig, msg, seed, pub_seed, addr);
  wots_pk_from_sig(&params, pk2, sig, msg, pub_seed, addr);

  for (i = 0; i < sig_len; i++)
    if (pk1[i] != pk2[i]) {
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
