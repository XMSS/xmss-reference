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
  // TODO test more different OIDs
  uint32_t oid = 0x01000001;
  xmssmt_parse_oid(oid); // Parse it to make sure the sizes are set

  int r;
  unsigned long long i,j;

  unsigned char sk[XMSS_OID_LEN + XMSS_PRIVATEKEY_BYTES];
  unsigned char pk[XMSS_OID_LEN + XMSS_PUBLICKEY_BYTES];

  unsigned char mo[MLEN+XMSS_BYTES];
  unsigned char sm[MLEN+XMSS_BYTES];

  printf("keypair\n");
  xmssmt_keypair(pk, sk, oid);
  // check pub_seed in SK
  for (i = 0; i < XMSS_N; i++) {
    if (pk[XMSS_OID_LEN+XMSS_N+i] != sk[XMSS_OID_LEN+XMSS_INDEX_LEN+2*XMSS_N+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
    if (pk[XMSS_OID_LEN+i] != sk[XMSS_OID_LEN+XMSS_INDEX_LEN+3*XMSS_N+i]) printf("pk.root != sk.root %llu",i);
  }

  printf("pk checked\n");

  // check index
  unsigned long long idx = 0;
  for (i = 0; i < XMSS_INDEX_LEN; i++) {
    idx |= ((unsigned long long)sk[i + XMSS_OID_LEN]) << 8*(XMSS_INDEX_LEN - 1 - i);
  }

  if (idx) printf("\nidx != 0: %llu\n",idx);

  for (i = 0; i < SIGNATURES; i++) {
    randombytes(mi, MLEN);

    printf("sign\n");
    xmssmt_sign(sk, sm, &smlen, mi, MLEN);
    idx = 0;
    for (j = 0; j < XMSS_INDEX_LEN; j++) {
      idx += ((unsigned long long)sm[j]) << 8*(XMSS_INDEX_LEN - 1 - j);
    }
    printf("\nidx = %llu\n",idx);
    r = memcmp(mi, sm+XMSS_BYTES,MLEN);
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


