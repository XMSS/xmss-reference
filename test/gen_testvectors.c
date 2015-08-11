#include <stdint.h>
#include <stdio.h>
#include "../crypto_sign.h"

#define MAXMBYTES 2048

typedef uint32_t uint32;

static uint32 seed[32] = { 3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3,2,3,8,4,6,2,6,4,3,3,8,3,2,7,9,5 } ;
static uint32 in[12];
static uint32 out[8];
static int outleft = 0;

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x,b));

static void surf(void)
{
  uint32 t[12]; uint32 x; uint32 sum = 0;
  int r; int i; int loop;

  for (i = 0;i < 12;++i) t[i] = in[i] ^ seed[12 + i];
  for (i = 0;i < 8;++i) out[i] = seed[24 + i];
  x = t[11];
  for (loop = 0;loop < 2;++loop) {
    for (r = 0;r < 16;++r) {
      sum += 0x9e3779b9;
      MUSH(0,5) MUSH(1,7) MUSH(2,9) MUSH(3,13)
      MUSH(4,5) MUSH(5,7) MUSH(6,9) MUSH(7,13)
      MUSH(8,5) MUSH(9,7) MUSH(10,9) MUSH(11,13)
    }
    for (i = 0;i < 8;++i) out[i] ^= t[i + 4];
  }
}

void randombytes(unsigned char *x,unsigned long long xlen)
{
  while (xlen > 0) {
    if (!outleft) {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
    *x = out[--outleft];
    ++x;
    --xlen;
  }
}


unsigned char pk[CRYPTO_PUBLICKEYBYTES];
unsigned char sk[CRYPTO_SECRETKEYBYTES];
unsigned char m[MAXMBYTES];
unsigned char sm[MAXMBYTES+CRYPTO_BYTES];
//unsigned char mo[MAXMBYTES+CRYPTO_BYTES];
unsigned long long smlen;
unsigned long long mlen;

int main(void)
{
  int n,i,r;
  for(n=0;n<MAXMBYTES;n++)
  {
    crypto_sign_keypair(pk,sk);
    randombytes(m,n);

    crypto_sign(sm, &smlen, m, n, sk);
    for(i=0;i<smlen;i++)
      printf("%02x",sm[i]);
    printf("\n");
    r = crypto_sign_open(sm, &mlen, sm, smlen, pk);
    if(r)
    {
      printf("signature verification fails\n");
      return -1;
    }
    if(mlen != n)
    {
      printf("signature verification produces wrong message length\n");
      return -1;
    }
    for(i=0;i<n;i++)
    {
      if(sm[i] != m[i])
      {
        printf("signature verification does not recover message\n");
        return -1;
      }
    }
  }
  return 0;
}
