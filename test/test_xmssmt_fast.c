#include <stdio.h>
#include <string.h>

#include "../xmss_fast.h"
#include "../params.h"
#include "../randombytes.h"

#define MLEN 3491
#define SIGNATURES 128

unsigned char mi[MLEN];
unsigned long long smlen;
unsigned long long mlen;

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
  unsigned long long i,j;
  unsigned int n = XMSS_N;
  unsigned int h = XMSS_FULLHEIGHT;
  unsigned int d = XMSS_D;
  unsigned int k = XMSS_BDS_K;

  unsigned int tree_h = h / d;

  // stack needs to be larger than regular (H-K-1), since we re-use for 'next'
  unsigned char stack[(2*d-1) * (tree_h + 1)*n];
  unsigned char stacklevels[(2*d-1) * (tree_h + 1)*n];
  unsigned char auth[(2*d-1) * tree_h*n];
  unsigned char keep[(2*d-1) * (tree_h >> 1)*n];
  treehash_inst treehash[(2*d-1) * (tree_h-k)];
  unsigned char th_nodes[(2*d-1) * (tree_h-k)*n];
  unsigned char retain[(2*d-1) * ((1 << k) - k - 1)*n];
  unsigned char wots_sigs[d * XMSS_WOTS_KEYSIZE];
  // first d are 'regular' states, second d are 'next'; top tree has no 'next'
  bds_state states[2*d-1];

  for (i = 0; i < 2*d-1; i++) {
    for (j = 0; j < tree_h-k; j++)
      treehash[i*(tree_h-k) + j].node = th_nodes + (i*(tree_h-k) + j) * n;
    xmss_set_bds_state(states + i,
      stack + i*(tree_h + 1)*n, 0, stacklevels + i*(tree_h + 1),
      auth + i*tree_h*n,
      keep + i*(tree_h >> 1)*n,
      treehash + i*(tree_h-k),
      retain + i*((1 << k) - k - 1)*n,
      0
    );
  }

  unsigned char sk[(XMSS_INDEX_LEN+4*n)];
  unsigned char pk[2*n];

  unsigned long long signature_length = XMSS_INDEX_LEN + n + (d*XMSS_WOTS_KEYSIZE) + h*n;
  unsigned char mo[MLEN+signature_length];
  unsigned char sm[MLEN+signature_length];

  randombytes(mi, MLEN);

  printf("keypair\n");
  xmssmt_keypair(pk, sk, states, wots_sigs);
  // check pub_seed in SK
  for (i = 0; i < n; i++) {
    if (pk[n+i] != sk[XMSS_INDEX_LEN+2*n+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
    if (pk[i] != sk[XMSS_INDEX_LEN+3*n+i]) printf("pk.root != sk.root %llu",i);
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
    printf("sign\n");
    t1 = cpucycles();
    xmssmt_sign(sk, states, wots_sigs, sm, &smlen, mi, MLEN);
    t2 = cpucycles();
    printf("signing cycles = %llu\n", (t2-t1));

    idx = 0;
    for (j = 0; j < idx_len; j++) {
      idx += ((unsigned long long)sm[j]) << 8*(idx_len - 1 - j);
    }
    printf("\nidx = %llu\n",idx);
    r = memcmp(mi, sm+signature_length,MLEN);
    printf("%d\n", r);

    /* Test valid signature */
    printf("verify\n");
    t1 = cpucycles();
    r = xmssmt_sign_open(mo, &mlen, sm, smlen, pk);
    t2 = cpucycles();
    printf("verification cycles = %llu\n", (t2-t1));
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
