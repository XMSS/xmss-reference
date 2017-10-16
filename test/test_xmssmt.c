#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../xmss.h"
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

  unsigned char sk[XMSS_OID_LEN + params.privatekey_bytes];
  unsigned char pk[XMSS_OID_LEN + params.publickey_bytes];

  unsigned char mo[MLEN+params.bytes];
  unsigned char sm[MLEN+params.bytes];

  printf("keypair\n");
  xmssmt_keypair(pk, sk, oid);
  // check pub_seed in SK
  for (i = 0; i < params.n; i++) {
    if (pk[XMSS_OID_LEN+params.n+i] != sk[XMSS_OID_LEN+params.index_len+2*params.n+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
    if (pk[XMSS_OID_LEN+i] != sk[XMSS_OID_LEN+params.index_len+3*params.n+i]) printf("pk.root != sk.root %llu",i);
  }

  printf("pk checked\n");

  // check index
  unsigned long long idx = 0;
  for (i = 0; i < params.index_len; i++) {
    idx |= ((unsigned long long)sk[i + XMSS_OID_LEN]) << 8*(params.index_len - 1 - i);
  }

  if (idx) printf("\nidx != 0: %llu\n",idx);

  for (i = 0; i < SIGNATURES; i++) {
    randombytes(mi, MLEN);

    printf("sign\n");
    xmssmt_sign(sk, sm, &smlen, mi, MLEN);
    idx = 0;
    for (j = 0; j < params.index_len; j++) {
      idx += ((unsigned long long)sm[j]) << 8*(params.index_len - 1 - j);
    }
    printf("\nidx = %llu\n",idx);
    r = memcmp(mi, sm+params.bytes,MLEN);
    printf("%d\n", r);

    for (j = 0; j < smlen; j++) {
      printf("%02X", sm[j]);
    }
    printf("\n");

    /* Test valid signature */
    printf("verify\n");
    r = xmssmt_sign_open(mo, &mlen, sm, smlen, pk);
    printf("%d\n", r);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", r);
    printf("%llu\n", MLEN-mlen);

    /* Test with modified message */
    sm[52] ^= 1;
    r = xmssmt_sign_open(mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Test with modified signature */
    sm[260] ^= 1;
    sm[52] ^= 1;
    sm[2] ^= 1;
    r = xmssmt_sign_open(mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);
  }
  return 0;
}


