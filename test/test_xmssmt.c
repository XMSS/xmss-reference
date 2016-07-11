#include <stdio.h>
#include <string.h>

#include "../xmss.h"

#define MLEN 3491
#define SIGNATURES 1024

unsigned char mi[MLEN];
unsigned long long smlen;
unsigned long long mlen;

int main()
{
  int r;
  unsigned long long i,j;
  unsigned int n = 32;
  unsigned int h = 20;
  unsigned int d = 5;
  unsigned int w = 16;

  xmssmt_params p;
  xmssmt_params *params = &p;
  xmssmt_set_params(params, n, h, d, w);

  unsigned char sk[(params->index_len+4*n)];
  unsigned char pk[2*n];

  unsigned long long signature_length = params->index_len + n + (d*params->xmss_par.wots_par.keysize) + h*n;
  unsigned char mo[MLEN+signature_length];
  unsigned char sm[MLEN+signature_length];

  FILE *urandom = fopen("/dev/urandom", "r");
  for (i = 0; i < MLEN; i++) mi[i] = fgetc(urandom);

  printf("keypair\n");
  xmssmt_keypair(pk, sk, params);
  // check pub_seed in SK
  for (i = 0; i < n; i++) {
    if (pk[n+i] != sk[params->index_len+2*n+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
    if (pk[i] != sk[4+3*n+i]) printf("pk.root != sk.root %llu",i);
  }
  printf("pk checked\n");

  unsigned int idx_len = params->index_len;
  // check index
  unsigned long long idx = 0;
  for (i = 0; i < idx_len; i++) {
    idx |= ((unsigned long long)sk[i]) << 8*(idx_len - 1 - i);
  }

  if (idx) printf("\nidx != 0: %llu\n",idx);

  for (i = 0; i < SIGNATURES; i++) {
    printf("sign\n");
    xmssmt_sign(sk, sm, &smlen, mi, MLEN, params);
    idx = 0;
    for (j = 0; j < idx_len; j++) {
      idx += ((unsigned long long)sm[j]) << 8*(idx_len - 1 - j);
    }
    printf("\nidx = %llu\n",idx);
    r = memcmp(mi, sm+signature_length,MLEN);
    printf("%d\n", r);

    /* Test valid signature */
    printf("verify\n");
    r = xmssmt_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", r);
    printf("%llu\n", MLEN-mlen);

    /* Test with modified message */
    sm[52] ^= 1;
    r = xmssmt_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r+1);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Test with modified signature */
    sm[260] ^= 1;
    sm[52] ^= 1;
    sm[2] ^= 1;
    r = xmssmt_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r+1);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);
  }
  fclose(urandom);
  return 0;
}


