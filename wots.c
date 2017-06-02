/*
wots.c version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include "math.h"
#include "stdio.h"
#include "stdint.h"
#include "xmss_commons.h"
#include "hash.h"
#include "wots.h"
#include "hash_address.h"
#include "params.h"

/**
 * Helper method for pseudorandom key generation
 * Expands an n-byte array into a len*n byte array
 * this is done using PRF
 */
static void expand_seed(unsigned char *outseeds, const unsigned char *inseed)
{
  uint32_t i = 0;
  unsigned char ctr[32];
  for(i = 0; i < XMSS_WOTS_LEN; i++){
    to_byte(ctr, i, 32);
    prf(outseeds + i*XMSS_N, ctr, inseed, XMSS_N);
  }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays
 *
 * interpretes in as start-th value of the chain
 * addr has to contain the address of the chain
 */
static void gen_chain(unsigned char *out, const unsigned char *in, unsigned int start, unsigned int steps, const unsigned char *pub_seed, uint32_t addr[8])
{
  uint32_t i, j;
  for (j = 0; j < XMSS_N; j++)
    out[j] = in[j];

  for (i = start; i < (start+steps) && i < XMSS_WOTS_W; i++) {
    setHashADRS(addr, i);
    hash_f(out, out, pub_seed, addr);
  }
}

/**
 * base_w algorithm as described in draft.
 *
 *
 */
static void base_w(int *output, const int out_len, const unsigned char *input)
{
  int in = 0;
  int out = 0;
  uint32_t total = 0;
  int bits = 0;
  int consumed = 0;

  for (consumed = 0; consumed < out_len; consumed++) {
    if (bits == 0) {
      total = input[in];
      in++;
      bits += 8;
    }
    bits -= XMSS_WOTS_LOG_W;
    output[out] = (total >> bits) & (XMSS_WOTS_W - 1);
    out++;
  }
}

void wots_pkgen(unsigned char *pk, const unsigned char *sk, const unsigned char *pub_seed, uint32_t addr[8])
{
  uint32_t i;
  expand_seed(pk, sk);
  for (i=0; i < XMSS_WOTS_LEN; i++) {
    setChainADRS(addr, i);
    gen_chain(pk+i*XMSS_N, pk+i*XMSS_N, 0, XMSS_WOTS_W-1, pub_seed, addr);
  }
}


void wots_sign(unsigned char *sig, const unsigned char *msg, const unsigned char *sk, const unsigned char *pub_seed, uint32_t addr[8])
{
  int basew[XMSS_WOTS_LEN];
  int csum = 0;
  uint32_t i = 0;

  base_w(basew, XMSS_WOTS_LEN1, msg);

  for (i=0; i < XMSS_WOTS_LEN1; i++) {
    csum += XMSS_WOTS_W - 1 - basew[i];
  }

  csum = csum << (8 - ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) % 8));

  int len_2_bytes = ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) + 7) / 8;

  unsigned char csum_bytes[len_2_bytes];
  to_byte(csum_bytes, csum, len_2_bytes);

  int csum_basew[len_2_bytes / XMSS_WOTS_LOG_W];
  base_w(csum_basew, XMSS_WOTS_LEN2, csum_bytes);

  for (i = 0; i < XMSS_WOTS_LEN2; i++) {
    basew[XMSS_WOTS_LEN1 + i] = csum_basew[i];
  }

  expand_seed(sig, sk);

  for (i = 0; i < XMSS_WOTS_LEN; i++) {
    setChainADRS(addr, i);
    gen_chain(sig+i*XMSS_N, sig+i*XMSS_N, 0, basew[i], pub_seed, addr);
  }
}

void wots_pkFromSig(unsigned char *pk, const unsigned char *sig, const unsigned char *msg, const unsigned char *pub_seed, uint32_t addr[8])
{
  int basew[XMSS_WOTS_LEN];
  int csum = 0;
  uint32_t i = 0;

  base_w(basew, XMSS_WOTS_LEN1, msg);

  for (i=0; i < XMSS_WOTS_LEN1; i++) {
    csum += XMSS_WOTS_W - 1 - basew[i];
  }

  csum = csum << (8 - ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) % 8));

  int len_2_bytes = ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) + 7) / 8;

  unsigned char csum_bytes[len_2_bytes];
  to_byte(csum_bytes, csum, len_2_bytes);

  int csum_basew[len_2_bytes / XMSS_WOTS_LOG_W];
  base_w(csum_basew, XMSS_WOTS_LEN2, csum_bytes);

  for (i = 0; i < XMSS_WOTS_LEN2; i++) {
    basew[XMSS_WOTS_LEN1 + i] = csum_basew[i];
  }
  for (i=0; i < XMSS_WOTS_LEN; i++) {
    setChainADRS(addr, i);
    gen_chain(pk+i*XMSS_N, sig+i*XMSS_N, basew[i], XMSS_WOTS_W-1-basew[i], pub_seed, addr);
  }
}
