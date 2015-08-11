#include <stdio.h>
#include <stdlib.h>
#include "../crypto_sign.h"
#include "../cpucycles.h"
#include "../randombytes.h"
#include "../horst.h"
#include "../wots.h"
#include "../hash.h"


#define MLEN 59
#define REP 1
#define NRUNS 100

static int ull_cmp(const void *a, const void *b) 
{ 
  const unsigned long long *ia = (const unsigned long long *)a; 
  const unsigned long long *ib = (const unsigned long long *)b;
  if (*ia > *ib) return 1;
  if (*ia < *ib) return -1;
  return 0;
} 

static const unsigned char seed[32] = {
  0x22, 0x26, 0xb5, 0x64, 0xbb, 0x78, 0xcc, 0xab, 0x4a, 0x4c, 0x0a, 0x64, 0xc2, 0x0b, 0x5d, 0x68, 
  0x38, 0x74, 0x1a, 0xc0, 0x03, 0x17, 0xff, 0xd8, 0xe3, 0x53, 0xc8, 0x59, 0xc6, 0x23, 0x5b, 0xaa};


int main()
{
  unsigned long long t[NRUNS];
  int i,j;

  printf("\n=== Benchmarks of signatures ===\n\n");
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];

  unsigned char m[MLEN+CRYPTO_BYTES];
  unsigned char sm[MLEN+CRYPTO_BYTES];
  unsigned long long mlen;
  unsigned long long smlen;
 
  unsigned char masks[2*HORST_LOGT*HASH_BYTES];
  randombytes(masks,N_MASKS*HASH_BYTES);

  unsigned char msg_seed[MSGHASH_BYTES];
  randombytes(msg_seed, MSGHASH_BYTES);

  //Benchmarking signature key generation
  for(i=0;i<NRUNS;i++)
  {
    t[i] = cpucycles();
    for(j=0;j<REP;j++)
      crypto_sign_keypair(pk, sk);
  }
  for(i=0;i<NRUNS-1;i++)
    t[i] = (t[i+1] - t[i]);
  qsort(t, NRUNS-1, sizeof(unsigned long long), ull_cmp);
  printf("keypair:           %13.3lf\n", (double)t[NRUNS/2-1]/REP);

  //Benchmarking signature generation
  for(i=0;i<NRUNS;i++)
  {
    t[i] = cpucycles();
    for(j=0;j<REP;j++)
      crypto_sign(sm, &smlen, m, MLEN, sk);
  }
  for(i=0;i<NRUNS-1;i++)
    t[i] = (t[i+1] - t[i]);
  qsort(t, NRUNS-1, sizeof(unsigned long long), ull_cmp);
  printf("sign:              %13.3lf\n", (double)t[NRUNS/2-1]/REP);

  //Benchmarking signature verification
  for(i=0;i<NRUNS;i++)
  {
    t[i] = cpucycles();
    for(j=0;j<REP;j++)
      crypto_sign_open(m, &mlen, sm, smlen, pk);
  }
  for(i=0;i<NRUNS-1;i++)
    t[i] = (t[i+1] - t[i]);
  qsort(t, NRUNS-1, sizeof(unsigned long long), ull_cmp);
  printf("sign_open:         %13.3lf\n", (double)t[NRUNS/2-1]/REP);

  //Benchmarking WOTS pkgen
  for(i=0;i<NRUNS;i++)
  {
    t[i] = cpucycles();
    for(j=0;j<REP;j++)
      wots_pkgen(sm, seed, masks);
  }
  for(i=0;i<NRUNS-1;i++)
    t[i] = (t[i+1] - t[i]);
  qsort(t, NRUNS-1, sizeof(unsigned long long), ull_cmp);
  printf("wots_pkgen:        %13.3lf\n", (double)t[NRUNS/2-1]/REP);
  printf("416*wots_pkgen:    %13.3lf\n", 416*(double)t[NRUNS/2-1]/REP);

  //Benchmarking HORSt signing
  for(i=0;i<NRUNS;i++)
  {
    t[i] = cpucycles();
    for(j=0;j<REP;j++)
      horst_sign(sm, pk, &smlen, m, MLEN, seed, masks, msg_seed);
  }
  for(i=0;i<NRUNS-1;i++)
    t[i] = (t[i+1] - t[i]);
  qsort(t, NRUNS-1, sizeof(unsigned long long), ull_cmp);
  printf("horst_sign:        %13.3lf\n", (double)t[NRUNS/2-1]/REP);

  //Benchmarking hash_2n_n
  for(i=0;i<NRUNS;i++)
  {
    t[i] = cpucycles();
    for(j=0;j<REP;j++)
      hash_2n_n(sm, sm);
  }
  for(i=0;i<NRUNS-1;i++)
    t[i] = (t[i+1] - t[i]);
  qsort(t, NRUNS-1, sizeof(unsigned long long), ull_cmp);
  printf("hash_2n_n:         %13.3lf\n", (double)t[NRUNS/2-1]/REP);


  return 0;
}
