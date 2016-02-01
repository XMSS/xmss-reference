#include <stdio.h>
#include <string.h>

#include "../xmss_fast.h"

#define MLEN 3491
#define SIGNATURES 4096


unsigned char mi[MLEN];
unsigned long long smlen;
unsigned long long mlen;

int main()
{
  int r;
  unsigned long long i,j;
  int m = 32;
  int n = 32;
  int h = 12;
  int d = 2;
  int w = 16;
  int k = 2;

  xmssmt_params p;
  xmssmt_params *params = &p;
  if (xmssmt_set_params(params, m, n, h, d, w, k)) {
    return 1;
  }

  unsigned int tree_h = h / d;

  // stack needs to be larger than regular (H-K-1), since we re-use for 'next'
  unsigned char stack[(2*d-1) * (tree_h + 1)*n];
  unsigned char stacklevels[(2*d-1) * (tree_h + 1)*n];
  unsigned char auth[(2*d-1) * tree_h*n];
  unsigned char keep[(2*d-1) * (tree_h >> 1)*n];
  treehash_inst treehash[(2*d-1) * (tree_h-k)];
  unsigned char th_nodes[(2*d-1) * (tree_h-k)*n];
  unsigned char retain[(2*d-1) * ((1 << k) - k - 1)*n];
  unsigned char wots_sigs[d * params->xmss_par.wots_par.keysize];
  // first d are 'regular' states, second d are 'next'; top tree has no 'next'
  bds_state states[2*d-1];

  for (i = 0; i < 2*d-1; i++) {
    for(j=0;j<tree_h-k;j++)
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

  unsigned char sk[(params->index_len+2*n+m)];
  unsigned char pk[2*n];

  unsigned long long signature_length = params->index_len + m + (d*params->xmss_par.wots_par.keysize) + h*n;
  unsigned char mo[MLEN+signature_length];
  unsigned char sm[MLEN+signature_length];

  FILE *urandom = fopen("/dev/urandom", "r");
  for(i=0;i<MLEN;i++) mi[i] = fgetc(urandom);

  printf("keypair\n");
  xmssmt_keypair(pk, sk, states, wots_sigs, params);
  // check pub_seed in SK
  for(i=0;i<n;i++)
  {
    if(pk[n+i] != sk[params->index_len+m+n+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
  }
  printf("pk checked\n");

  unsigned int idx_len = params->index_len;
  // check index
  unsigned long long idx = 0;
  for(i = 0; i < idx_len; i++){
    idx |= ((unsigned long long)sk[i]) << 8*(idx_len - 1 - i);
  }

  if(idx) printf("\nidx != 0: %llu\n",idx);

  for(i=0;i<SIGNATURES;i++){
    printf("sign\n");
    xmssmt_sign(sk, states, wots_sigs, sm, &smlen, mi, MLEN, params);

    idx = 0;
    for(j = 0; j < idx_len; j++){
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
