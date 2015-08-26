#include <stdio.h>
#include <string.h>

#include "../xmss.h"

#define MLEN 3491
#define SIGNATURES 50


unsigned char sk[100];
unsigned char pk[64];
unsigned char mi[MLEN];
unsigned long long smlen;
unsigned long long mlen;

int main()
{
  int r;
  unsigned long long i;
  int m = 32;
  int n = 32;
  int h = 8;
  int w = 16;
  
  xmss_params p;
  xmss_params *params = &p;
  xmss_set_params(params, m, n, h, w);
  unsigned long long signature_length = 4+m+params->wots_par.keysize+h*n;
  unsigned char mo[MLEN+signature_length];
  unsigned char sm[MLEN+signature_length];

  FILE *urandom = fopen("/dev/urandom", "r");
  for(i=0;i<MLEN;i++) mi[i] = fgetc(urandom);

  printf("keypair\n");
  xmss_keypair(pk, sk, params);
  // check pub_seed in SK
  for(i=0;i<n;i++)
  {
    if(pk[n+i] != sk[4+m+n+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
  }

  // check index
  unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
  if(idx) printf("\nidx != 0 %lu\n",idx);
  
  for(i=0;i<SIGNATURES;i++){
    printf("sign\n");
    xmss_sign(sk, sm, &smlen, mi, MLEN, params);
    idx = ((unsigned long)sm[0] << 24) | ((unsigned long)sm[1] << 16) | ((unsigned long)sm[2] << 8) | sm[3];
    printf("\nidx = %lu\n",idx);

    r = memcmp(mi, sm+signature_length,MLEN);
    printf("%d\n", r);

    /* Test valid signature */
    printf("verify\n");
    r = xmss_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", r);
    printf("%llu\n", MLEN-mlen);

    /* Test with modified message */
    sm[52] ^= 1;
    r = xmss_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r+1);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Test with modified signature */
    sm[260] ^= 1;
    sm[52] ^= 1;
    sm[2] ^= 1;
    r = xmss_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r+1);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);
  }

  fclose(urandom);
  return 0;
}


