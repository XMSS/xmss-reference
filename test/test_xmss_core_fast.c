#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../xmss_core_fast.h"
#include "../params.h"
#include "../randombytes.h"

#define MLEN 3491
#define SIGNATURES 256

unsigned long long t1, t2;

unsigned long long cpucycles(void)
{
  unsigned long long result;
  asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax" : "=a" (result) ::  "%rdx");
  return result;
}

int main()
{
  xmss_params params;
  // TODO test more different OIDs
  uint32_t oid = 0x01000001;
  xmss_parse_oid(&params, oid);

  int r;
  unsigned long long i;
  unsigned int k = params.bds_k;

  unsigned long errors = 0;

  unsigned char sk[4*params.n+4];
  unsigned char pk[2*params.n];

  // TODO should we hide this into xmss_fast.c and just allocate a large enough chunk of memory here?
  unsigned char stack[(params.tree_height+1)*params.n];
  unsigned int stackoffset = 0;
  unsigned char stacklevels[params.tree_height+1];
  unsigned char auth[(params.tree_height)*params.n];
  unsigned char keep[(params.tree_height >> 1)*params.n];
  treehash_inst treehash[params.tree_height-k];
  unsigned char th_nodes[(params.tree_height-k)*params.n];
  unsigned char retain[((1 << k) - k - 1)*params.n];
  bds_state s;
  bds_state *state = &s;
  for (i = 0; i < params.tree_height-k; i++)
    treehash[i].node = &th_nodes[params.n*i];
  xmss_set_bds_state(state, stack, stackoffset, stacklevels, auth, keep, treehash, retain, 0);

  unsigned long long signature_length = 4+params.n+params.wots_keysize+params.tree_height*params.n;
  unsigned char mi[MLEN];
  unsigned char mo[MLEN+signature_length];
  unsigned char sm[MLEN+signature_length];
  unsigned long long smlen;
  unsigned long long mlen;

  randombytes(mi, MLEN);

  printf("keypair\n");
  t1 = cpucycles();
  xmss_core_keypair(&params, pk, sk, state);
  t2 = cpucycles();
  printf("cycles = %llu\n", (t2-t1));
  double sec = (t2-t1)/3500000;
  printf("ms = %f\n", sec);
  // check pub_seed in SK
  for (i = 0; i < params.n; i++) {
    if (pk[params.n+i] != sk[4+2*params.n+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
    if (pk[i] != sk[4+3*params.n+i]) printf("pk.root != sk.root %llu",i);
  }

  // check index
  unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
  if (idx) printf("\nidx != 0 %lu\n",idx);

  for (i = 0; i < SIGNATURES; i++) {
    printf("sign\n");
    xmss_core_sign(&params, sk, state, sm, &smlen, mi, MLEN);
    idx = ((unsigned long)sm[0] << 24) | ((unsigned long)sm[1] << 16) | ((unsigned long)sm[2] << 8) | sm[3];
    printf("\nidx = %lu\n",idx);

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
  printf("finished loop\n");
  return 0;
}
