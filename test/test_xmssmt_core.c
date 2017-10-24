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
  xmss_params params;
  // TODO test more different OIDs
  uint32_t oid = 0x01000001;
  xmssmt_parse_oid(&params, oid);

  int r;
  unsigned long long i,j;

  unsigned char sk[(params.index_bytes+4*params.n)];
  unsigned char pk[2*params.n];

  unsigned long long signature_length = params.index_bytes + params.n + (params.d*params.wots_sig_bytes) + params.full_height*params.n;
  unsigned char mo[MLEN+signature_length];
  unsigned char sm[MLEN+signature_length];

  printf("keypair\n");
  xmssmt_core_keypair(&params, pk, sk);
  // check pub_seed in SK
  for (i = 0; i < params.n; i++) {
    if (pk[params.n+i] != sk[params.index_bytes+2*params.n+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
    if (pk[i] != sk[params.index_bytes+3*params.n+i]) printf("pk.root != sk.root %llu",i);
  }
  printf("pk checked\n");

  unsigned int idx_len = params.index_bytes;
  // check index
  unsigned long long idx = 0;
  for (i = 0; i < idx_len; i++) {
    idx |= ((unsigned long long)sk[i]) << 8*(idx_len - 1 - i);
  }

  if (idx) printf("\nidx != 0: %llu\n",idx);

  for (i = 0; i < SIGNATURES; i++) {
    randombytes(mi, MLEN);

    printf("sign\n");
    xmssmt_core_sign(&params, sk, sm, &smlen, mi, MLEN);
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
    r = xmssmt_core_sign_open(&params, mo, &mlen, sm, smlen, pk);
    printf("%d\n", r);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", r);
    printf("%llu\n", MLEN-mlen);

    /* Test with modified message */
    sm[52] ^= 1;
    r = xmssmt_core_sign_open(&params, mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Test with modified signature */
    sm[260] ^= 1;
    sm[52] ^= 1;
    sm[2] ^= 1;
    r = xmssmt_core_sign_open(&params, mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);
  }
  return 0;
}


