/*
hash.c version 20160708
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include "hash_address.h"
#include "xmss_commons.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>


int core_hash_SHA2(unsigned char *out, const unsigned int type, const unsigned char *key, unsigned int keylen, const unsigned char *in, unsigned long long inlen, unsigned int n){  
  unsigned long long i = 0;
  unsigned char buf[inlen + n + keylen];
  
  // Input is (toByte(X, 32) || KEY || M) 
  
  // set toByte
  to_byte(buf, type, n);
  
  for (i=0; i < keylen; i++) {
    buf[i+n] = key[i];
  }
  
  for (i=0; i < inlen; i++) {
    buf[keylen + n + i] = in[i];
  }

  if (n == 32) {
    SHA256(buf, inlen + keylen + n, out);
    return 0;
  }
  else {
    if (n == 64) {
      SHA512(buf, inlen + keylen + n, out);
      return 0;
    }
  }
  return 1;
}

/**
 * Implements PRF
 */
int prf(unsigned char *out, const unsigned char *in, const unsigned char *key, unsigned int keylen)
{
  size_t inlen = 32;  
  return core_hash_SHA2(out, 3, key, keylen, in, inlen, keylen);
}

/*
 * Implemts H_msg
 */
int h_msg(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *key, const unsigned int keylen, const unsigned int n)
{
  if (keylen != 3*n){
    fprintf(stderr, "H_msg takes 3n-bit keys, we got n=%d but a keylength of %d.\n", n, keylen);
    return 1;
  }  
  return core_hash_SHA2(out, 2, key, keylen, in, inlen, n);
}

/**
 * We assume the left half is in in[0]...in[n-1]
 */
int hash_h(unsigned char *out, const unsigned char *in, const unsigned char *pub_seed, uint32_t addr[8], const unsigned int n)
{

  unsigned char buf[2*n];
  unsigned char key[n];
  unsigned char bitmask[2*n];
  unsigned int i;

  setKeyAndMask(addr, 0);
  prf(key, (unsigned char *)addr, pub_seed, n);
  // Use MSB order
  setKeyAndMask(addr, 1);
  prf(bitmask, (unsigned char *)addr, pub_seed, n);
  setKeyAndMask(addr, 2);
  prf(bitmask+n, (unsigned char *)addr, pub_seed, n);
  for (i = 0; i < 2*n; i++) {
    buf[i] = in[i] ^ bitmask[i];
  }
  return core_hash_SHA2(out, 1, key, n, buf, 2*n, n);
}

int hash_f(unsigned char *out, const unsigned char *in, const unsigned char *pub_seed, uint32_t addr[8], const unsigned int n)
{
  unsigned char buf[n];
  unsigned char key[n];
  unsigned char bitmask[n];
  unsigned int i;

  setKeyAndMask(addr, 0);
  prf(key, (unsigned char *)addr, pub_seed, n);
  // Use MSB order
  setKeyAndMask(addr, 1);
  prf(bitmask, (unsigned char *)addr, pub_seed, n);
  
  for (i = 0; i < n; i++) {
    buf[i] = in[i] ^ bitmask[i];
  }
  return core_hash_SHA2(out, 0, key, n, buf, n, n);
}
