#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../xmss_fast.h"

#define MLEN 3491
#define SIGNATURES 256


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
  int k = 2;
  
  unsigned long errors = 0;
  
  xmss_params p;
  xmss_params *params = &p;
  xmss_set_params(params, m, n, h, w, k);

  // TODO should we hide this into xmss_fast.c and just allocate a large enough chunk of memory here?
  unsigned char stack[(h-k-1)*n];
  unsigned int stackoffset = 0;
  unsigned char stacklevels[h-k-1];
  unsigned char auth[h*n];
  unsigned char keep[(h >> 1)*n];
  treehash_inst treehash[h-k];
  unsigned char th_nodes[(h-k)*n];
  unsigned char retain[((1 << k) - k - 1)*n];
  bds_state s;
  bds_state *state = &s;
  for(i=0;i<h-k;i++)
    treehash[i].node = &th_nodes[n*i];
  xmss_set_bds_state(state, stack, stackoffset, stacklevels, auth, keep, treehash, retain, 0);

  unsigned long long signature_length = 4+m+params->wots_par.keysize+h*n;
  unsigned char mo[MLEN+signature_length];
  unsigned char sm[MLEN+signature_length];

  FILE *urandom = fopen("/dev/urandom", "r");
  for(i=0;i<MLEN;i++) mi[i] = fgetc(urandom);

  printf("keypair\n");
  xmss_keypair(pk, sk, state, params);
  // check pub_seed in SK
  for(i=0;i<n;i++)
  {
    if(pk[n+i] != sk[4+m+n+i]) printf("pk.pub_seed != sk.pub_seed %llu",i);
  }

  // check index
  unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
  if(idx) printf("\nidx != 0 %lu\n",idx);
  
  for(i=0;i<(1<<h);i++){
    printf("sign\n");
    xmss_sign(sk, state, sm, &smlen, mi, MLEN, params);
    idx = ((unsigned long)sm[0] << 24) | ((unsigned long)sm[1] << 16) | ((unsigned long)sm[2] << 8) | sm[3];
    printf("\nidx = %lu\n",idx);

    r = memcmp(mi, sm+signature_length,MLEN);
    printf("%d\n", r);

        /* Test valid signature */
    printf("verify\n");
    r = xmss_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r);
    if(r != 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", r);
    printf("%llu\n", MLEN-mlen);

    /* Test with modified message */
    sm[signature_length+10] ^= 1;
    r = xmss_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r+1);
    if(r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);

    /* Test with modified signature */
    /* Modified index */
    sm[2] ^= 1;
    r = xmss_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r+1);
    if(r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);
    
    /* Modified R */
    sm[2] ^= 1;
    sm[5] ^= 1;
    r = xmss_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r+1);
    if(r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);
    
    /* Modified OTS sig */
    sm[5] ^= 1;
    sm[240] ^= 1;
    r = xmss_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r+1);
    if(r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);
    
    /* Modified AUTH */
    sm[240] ^= 1;
    sm[signature_length - 10] ^= 1;
    r = xmss_sign_open(mo, &mlen, sm, smlen, pk, params);
    printf("%d\n", r+1);
    if(r == 0) errors++;
    r = memcmp(mi,mo,MLEN);
    printf("%d\n", (r!=0) - 1);
    printf("%llu\n", mlen+1);
  }

  printf("#errors = %lu\n", errors);
  printf("finished loop\n");
  fclose(urandom);
  printf("closed urandom\n");
  return 0;
}


