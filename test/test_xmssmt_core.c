#include <stdio.h>
#include <string.h>

#include "../xmss_core.h"
#include "../params.h"
#include "../randombytes.h"

#define MLEN 3491
#define SIGNATURES 5

unsigned char mi[MLEN];
unsigned long long smlen;
unsigned long long mlen;

int main()
{
  int r;
  unsigned long long i,j;

  unsigned char sk[(XMSS_INDEX_LEN+4*XMSS_N)];
  unsigned char pk[2*XMSS_N];

  unsigned long long signature_length = XMSS_INDEX_LEN + XMSS_N + (XMSS_D*XMSS_WOTS_KEYSIZE) + XMSS_FULLHEIGHT*XMSS_N;
  unsigned char mo[MLEN+signature_length];
  unsigned char sm[MLEN+signature_length];

  printf("keypair\n");
  xmssmt_core_keypair(pk, sk);
  // check pub_seed in SK
  for (i = 0; i < XMSS_N; i++) {
    if (pk[XMSS_N+i] != sk[XMSS_INDEX_LEN+2*XMSS_N+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
    if (pk[i] != sk[XMSS_INDEX_LEN+3*XMSS_N+i]) printf("pk.root != sk.root %llu",i);
  }
  printf("pk checked\n");

  unsigned int idx_len = XMSS_INDEX_LEN;
  // check index
  unsigned long long idx = 0;
  for (i = 0; i < idx_len; i++) {
    idx |= ((unsigned long long)sk[i]) << 8*(idx_len - 1 - i);
  }

  if (idx) printf("\nidx != 0: %llu\n",idx);

  for (i = 0; i < SIGNATURES; i++) {
    randombytes(mi, MLEN);

    printf("sign\n");
    xmssmt_core_sign(sk, sm, &smlen, mi, MLEN);
    idx = 0;
    for (j = 0; j < idx_len; j++) {
      idx += ((unsigned long long)sm[j]) << 8*(idx_len - 1 - j);
    }
    printf("\nidx = %llu\n",idx);
    r = memcmp(mi, sm+signature_length,MLEN);
    printf("%d\n", r);

    for (j = 0; j < smlen; j++) {
      printf("%02X", sm[j]);
    }
    printf("\n");

    /* Test valid signature */
    printf("verify\n");
    r = xmssmt_core_sign_open(mo, &mlen, sm, smlen, pk);
    printf("%d\n", r);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", r);
    printf("%llu\n", MLEN-mlen);

    /* Test with modified message */
    sm[52] ^= 1;
    r = xmssmt_core_sign_open(mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Test with modified signature */
    sm[260] ^= 1;
    sm[52] ^= 1;
    sm[2] ^= 1;
    r = xmssmt_core_sign_open(mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);
  }
  return 0;
}


