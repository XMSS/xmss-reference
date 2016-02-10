/*
hash.c version 20151120
Andreas Hülsing
Public domain.
*/

#include "prg.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>


#define SET_KEY_BIT(a, b) (a[15] = (a[15] & 253) | ((b << 1) & 2))
#define SET_BLOCK_BIT(a, b) (a[15] = (a[15] & 254) | (b & 1))

#define WOTS_SELECT_KEY(a) (a[15] = (a[15] & 254) | 1)
#define WOTS_SELECT_BLOCK(a) (a[15] = (a[15] & 254) | 0)

/**
 * Implements PRF_m
 */
int prf_m(unsigned char *out, const unsigned char *in, size_t inlen, const unsigned char *key, unsigned int keylen)
{
  unsigned int length;
  if (keylen == 32) {
    HMAC(EVP_sha256(), key, keylen, in, inlen, out, &length);
    if (length != 32) {
      fprintf(stderr, "HMAC outputs %d bytes... That should not happen...", length);
    }
    return 0;
  }
  else {
    if (keylen == 64) {
      HMAC(EVP_sha512(), key, keylen, in, inlen, out, &length);
      if (length != 64) {
        fprintf(stderr, "HMAC outputs %d bytes... That should not happen...", length);
      }
      return 0;
    }
  }
  return 1;
}

/*
 * Implemts H_m
 */
int hash_m(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *key, const unsigned int keylen, const unsigned int m)
{
  unsigned int i;
  unsigned char buf[inlen + keylen + m];

  if (keylen != m){
    fprintf(stderr, "H_m takes m-bit keys, we got m=%d but a keylength of %d.\n", m, keylen);
    return 1;
  }
  for (i=0; i < m; i++) {
    buf[i] = 0x00;
  }
  for (i=0; i < keylen; i++) {
    buf[m + i] = key[i];
  }
  for (i=0; i < inlen; i++) {
    buf[m + keylen + i] = in[i];
  }

  if (m == 32) {
    SHA256(buf, inlen + keylen + m, out);
    return 0;
  }
  else {
    if (m == 64) {
      SHA512(buf, inlen + keylen + m, out);
      return 0;
    }
  }
  return 1;
}

/**
 * We assume the left half is in in[0]...in[n-1]
 */
int hash_2n_n(unsigned char *out, const unsigned char *in, const unsigned char *pub_seed, unsigned char addr[16], const unsigned int n)
{

  unsigned char buf[4*n];
  unsigned char key[n];
  unsigned char bitmask[2*n];
  unsigned int i;

  SET_KEY_BIT(addr, 1);
  SET_BLOCK_BIT(addr, 0);
  prg_with_counter(key, pub_seed, n, addr);
  SET_KEY_BIT(addr, 0);
  // Use MSB order
  prg_with_counter(bitmask, pub_seed, n, addr);
  SET_BLOCK_BIT(addr, 1);
  prg_with_counter(bitmask+n, pub_seed, n, addr);
  for (i = 0; i < n; i++) {
    buf[i] = 0x00;
    buf[n+i] = key[i];
    buf[2*n+i] = in[i] ^ bitmask[i];
    buf[3*n+i] = in[n+i] ^ bitmask[n+i];
  }
  if (n == 32) {
    SHA256(buf, 4*n, out);
    return 0;
  }
  else {
    if (n == 64) {
      SHA512(buf, 4*n, out);
      return 0;
    }
    else {
      fprintf(stderr, "Hash.c:hash_2n_n: Code only supports n=32 or n=64");
      return -1;
    }
  }
}

int hash_n_n(unsigned char *out, const unsigned char *in, const unsigned char *pub_seed, unsigned char addr[16], const unsigned int n)
{
  unsigned char buf[3*n];
  unsigned char key[n];
  unsigned char bitmask[n];
  unsigned int i;

  WOTS_SELECT_KEY(addr);
  prg_with_counter(key, pub_seed, n, addr);
  WOTS_SELECT_BLOCK(addr);
  prg_with_counter(bitmask, pub_seed, n, addr);
  for (i = 0; i < n; i++) {
    buf[i] = 0x00;
    buf[n+i] = key[i];
    buf[2*n+i] = in[i] ^ bitmask[i];
  }
  if (n == 32) {
    SHA256(buf, 3*n, out);
    return 0;
  }
  else {
    if (n == 64) {
      SHA512(buf, 3*n, out);
      return 0;
    }
    else {
      fprintf(stderr, "Hash.c:hash_n_n: Code only supports n=32 or n=64");
      return -1;
    }
  }
}
