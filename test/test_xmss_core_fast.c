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
  int r;
  unsigned long long i;
  unsigned int k = XMSS_BDS_K;

  unsigned long errors = 0;

  unsigned char sk[4*XMSS_N+4];
  unsigned char pk[2*XMSS_N];

  // TODO should we hide this into xmss_fast.c and just allocate a large enough chunk of memory here?
  unsigned char stack[(XMSS_TREEHEIGHT+1)*XMSS_N];
  unsigned int stackoffset = 0;
  unsigned char stacklevels[XMSS_TREEHEIGHT+1];
  unsigned char auth[(XMSS_TREEHEIGHT)*XMSS_N];
  unsigned char keep[(XMSS_TREEHEIGHT >> 1)*XMSS_N];
  treehash_inst treehash[XMSS_TREEHEIGHT-k];
  unsigned char th_nodes[(XMSS_TREEHEIGHT-k)*XMSS_N];
  unsigned char retain[((1 << k) - k - 1)*XMSS_N];
  bds_state s;
  bds_state *state = &s;
  for (i = 0; i < XMSS_TREEHEIGHT-k; i++)
    treehash[i].node = &th_nodes[XMSS_N*i];
  xmss_set_bds_state(state, stack, stackoffset, stacklevels, auth, keep, treehash, retain, 0);

  unsigned long long signature_length = 4+XMSS_N+XMSS_WOTS_KEYSIZE+XMSS_TREEHEIGHT*XMSS_N;
  unsigned char mi[MLEN];
  unsigned char mo[MLEN+signature_length];
  unsigned char sm[MLEN+signature_length];
  unsigned long long smlen;
  unsigned long long mlen;

  randombytes(mi, MLEN);

  printf("keypair\n");
  t1 = cpucycles();
  xmss_core_keypair(pk, sk, state);
  t2 = cpucycles();
  printf("cycles = %llu\n", (t2-t1));
  double sec = (t2-t1)/3500000;
  printf("ms = %f\n", sec);
  // check pub_seed in SK
  for (i = 0; i < XMSS_N; i++) {
    if (pk[XMSS_N+i] != sk[4+2*XMSS_N+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
    if (pk[i] != sk[4+3*XMSS_N+i]) printf("pk.root != sk.root %llu",i);
  }

  // check index
  unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
  if (idx) printf("\nidx != 0 %lu\n",idx);

  for (i = 0; i < SIGNATURES; i++) {
    printf("sign\n");
    xmss_core_sign(sk, state, sm, &smlen, mi, MLEN);
    idx = ((unsigned long)sm[0] << 24) | ((unsigned long)sm[1] << 16) | ((unsigned long)sm[2] << 8) | sm[3];
    printf("\nidx = %lu\n",idx);

    r = memcmp(mi, sm+signature_length,MLEN);
    printf("%d\n", r);

        /* Test valid signature */
    printf("verify\n");
    r = xmss_core_sign_open(mo, &mlen, sm, smlen, pk);
    printf("%d\n", r);
    if (r != 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", r);
    printf("%llu\n", MLEN-mlen);

    /* Test with modified message */
    sm[signature_length+10] ^= 1;
    r = xmss_core_sign_open(mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    if (r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Test with modified signature */
    /* Modified index */
    sm[signature_length+10] ^= 1;
    sm[2] ^= 1;
    r = xmss_core_sign_open(mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    if (r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Modified R */
    sm[2] ^= 1;
    sm[5] ^= 1;
    r = xmss_core_sign_open(mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    if (r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Modified OTS sig */
    sm[5] ^= 1;
    sm[240] ^= 1;
    r = xmss_core_sign_open(mo, &mlen, sm, smlen, pk);
    printf("%d\n", r+1);
    if (r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Modified AUTH */
    sm[240] ^= 1;
    sm[signature_length - 10] ^= 1;
    r = xmss_core_sign_open(mo, &mlen, sm, smlen, pk);
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
