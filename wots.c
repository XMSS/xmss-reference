/*
wots.c version 20150811
Andreas Hülsing
Public domain.
*/

#include "math.h"
#include "stdio.h"
#include "xmss_commons.h"
//#include "params.h"
#include "prg.h"
#include "hash.h"
#include "wots.h"

/**
 * Macros used to manipulate the respective fields
 * in the 16byte hash address
 */
#define SET_HASH_ADDRESS(a, v) {\
  a[15] = (a[15] & 1) | ((v << 1) & 254);\
  a[14] = (a[14] & 254) | ((v >> 7) & 1);}

#define SET_CHAIN_ADDRESS(a, v) {\
  a[14] = (a[14] & 1) | ((v << 1) & 254);\
  a[13] = (v >> 7) & 255;\
  a[12] = (a[12] & 254) | ((v >> 15) & 1);}


void wots_set_params(wots_params *params, int m, int n, int w)
{
  params->m = m;
  params->n = n;
  params->w = w;
  params->log_w = (int) log2(w);
  params->len_1 = (int) ceil(((8*m) / params->log_w));
  params->len_2 = (int) floor(log2(params->len_1*(w-1)) / params->log_w) + 1;
  params->len = params->len_1 + params->len_2;
  params->keysize = params->len*params->n;
}

/**
 * Helper method for pseudorandom key generation
 * Expands an n-byte array into a len*n byte array
 * this is done using chacha20 with nonce 0 and counter 0
 */
static void expand_seed(unsigned char *outseeds, const unsigned char *inseed, const wots_params *params)
{
  prg(outseeds, params->keysize, inseed, params->n);
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays
 *
 * interpretes in as start-th value of the chain
 * addr has to contain the address of the chain
 */
static void gen_chain(unsigned char *out, const unsigned char *in, unsigned int start, unsigned int steps, const wots_params *params, const unsigned char *pub_seed, unsigned char addr[16])
{
  unsigned int i, j;
  for (j = 0; j < params->n; j++)
    out[j] = in[j];

  for (i = start; i < (start+steps) && i < params->w; i++) {
    SET_HASH_ADDRESS(addr, i);
    hash_n_n(out, out, pub_seed, addr, params->n);
  }
}

/**
 * base_w algorithm as described in draft.
 *
 *
 */
static void base_w(int *output, const unsigned char *input, int in_len, const wots_params *params)
{
  int in = 0;
  int out = 0;
  int total = 0;
  int bits = 0;
  int consumed = 0;

  for (consumed = 0; consumed < 8 * in_len; consumed += params->log_w) {
    if (bits == 0) {
      total = input[in_len - 1 - in];
      in++;
      bits += 8;
    }
    bits -= params->log_w;
    output[out] = (total >> bits) & (params->w - 1);
    out++;
  }
}

void wots_pkgen(unsigned char *pk, const unsigned char *sk, const wots_params *params, const unsigned char *pub_seed, unsigned char addr[16])
{
  unsigned int i;
  expand_seed(pk, sk, params);
  for (i=0; i < params->len; i++) {
    SET_CHAIN_ADDRESS(addr, i);
    gen_chain(pk+i*params->n, pk+i*params->n, 0, params->w-1, params, pub_seed, addr);
  }
}


void wots_sign(unsigned char *sig, const unsigned char *msg, const unsigned char *sk, const wots_params *params, const unsigned char *pub_seed, unsigned char addr[16])
{
  int basew[params->len];
  int csum = 0;
  unsigned int i = 0;

  base_w(basew, msg, params->m, params);

  for (i=0; i < params->len_1; i++) {
    csum += params->w - 1 - basew[i];
  }

  csum = csum << (8 - ((params->len_2 * params->log_w) % 8));

  int len_2_bytes = ((params->len_2 * params->log_w) + 7) / 8;

  unsigned char csum_bytes[len_2_bytes];
  to_byte(csum_bytes, csum, len_2_bytes);

  int csum_basew[len_2_bytes / params->log_w];
  base_w(csum_basew, csum_bytes, len_2_bytes, params);

  for (i = 0; i < params->len_2; i++) {
    basew[params->len_1 + i] = csum_basew[i];
  }

  expand_seed(sig, sk, params);

  for (i = 0; i < params->len; i++) {
    SET_CHAIN_ADDRESS(addr, i);
    gen_chain(sig+i*params->n, sig+i*params->n, 0, basew[i], params, pub_seed, addr);
  }
}

void wots_pkFromSig(unsigned char *pk, const unsigned char *sig, const unsigned char *msg, const wots_params *params, const unsigned char *pub_seed, unsigned char addr[16])
{
  int basew[params->len];
  int csum = 0;
  unsigned int i = 0;

  base_w(basew, msg, params->m, params);

  for (i=0; i < params->len_1; i++) {
    csum += params->w - 1 - basew[i];
  }

  csum = csum << (8 - ((params->len_2 * params->log_w) % 8));

  int len_2_bytes = ((params->len_2 * params->log_w) + 7) / 8;

  unsigned char csum_bytes[len_2_bytes];
  to_byte(csum_bytes, csum, len_2_bytes);

  int csum_basew[len_2_bytes / params->log_w];
  base_w(csum_basew, csum_bytes, len_2_bytes, params);

  for (i = 0; i < params->len_2; i++) {
    basew[params->len_1 + i] = csum_basew[i];
  }
  for (i=0; i < params->len; i++) {
    SET_CHAIN_ADDRESS(addr, i);
    gen_chain(pk+i*params->n, sig+i*params->n, basew[i], params->w-1-basew[i], params, pub_seed, addr);
  }
}
