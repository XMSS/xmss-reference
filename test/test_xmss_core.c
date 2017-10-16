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
  xmss_parse_oid(&params, oid);

  int r;
  unsigned long long i, j;
  unsigned long errors = 0;

  unsigned char sk[4*params.n+4];
  unsigned char pk[2*params.n];

  unsigned long long signature_length = 4+params.n+params.wots_keysize+params.tree_height*params.n;
  unsigned char mo[MLEN+signature_length];
  unsigned char sm[MLEN+signature_length];

  printf("keypair\n");
  xmss_core_keypair(&params, pk, sk);
  // check pub_seed in SK
  for (i = 0; i < params.n; i++) {
    if (pk[params.n+i] != sk[4+2*params.n+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
    if (pk[i] != sk[4+3*params.n+i]) printf("pk.root != sk.root %llu",i);
  }

  // check index
  unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
  if (idx) printf("\nidx != 0 %lu\n",idx);

  for (i = 0; i < SIGNATURES; i++) {
    randombytes(mi, MLEN);

    printf("sign\n");
    xmss_core_sign(&params, sk, sm, &smlen, mi, MLEN);
    idx = ((unsigned long)sm[0] << 24) | ((unsigned long)sm[1] << 16) | ((unsigned long)sm[2] << 8) | sm[3];
    printf("\nidx = %lu\n",idx);

    for (j = 0; j < smlen; j++) {
      printf("%02X", sm[j]);
    }
    printf("\n");

    r = memcmp(mi, sm+signature_length,MLEN);
    printf("%d\n", r);

    /* Test valid signature */
    printf("verify\n");
    r = xmss_core_sign_open(&params, mo, &mlen, sm, smlen, pk);
    printf("%d\n", r);
    if (r != 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", r);
    printf("%llu\n", MLEN-mlen);

    /* Test with modified message */
    sm[signature_length+10] ^= 1;
    r = xmss_core_sign_open(&params, mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    if (r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Test with modified signature */
    /* Modified index */
    sm[signature_length+10] ^= 1;
    sm[2] ^= 1;
    r = xmss_core_sign_open(&params, mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    if (r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Modified R */
    sm[2] ^= 1;
    sm[5] ^= 1;
    r = xmss_core_sign_open(&params, mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    if (r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Modified OTS sig */
    sm[5] ^= 1;
    sm[240] ^= 1;
    r = xmss_core_sign_open(&params, mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    if (r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Modified AUTH */
    sm[240] ^= 1;
    sm[signature_length - 10] ^= 1;
    r = xmss_core_sign_open(&params, mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    if (r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);
  }

  printf("#errors = %lu\n", errors);
  return 0;
}


