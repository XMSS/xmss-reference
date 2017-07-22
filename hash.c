/*
hash.c version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include "hash_address.h"
#include "xmss_commons.h"
#include "hash.h"
#include "fips202.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

unsigned char* addr_to_byte(unsigned char *bytes, const uint32_t addr[8]){
#if IS_LITTLE_ENDIAN==1 
  int i = 0;
  for(i=0;i<8;i++)
    to_byte(bytes+i*4, addr[i],4);
  return bytes;  
#else
  memcpy(bytes, addr, 32);
  return bytes; 
#endif   
}

int core_hash(unsigned char *out, const unsigned int type, const unsigned char *key, unsigned int keylen, const unsigned char *in, unsigned long long inlen, unsigned int n, const unsigned char hash_alg){  
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

  if (n == 32 && hash_alg == XMSS_SHA2) {
    SHA256(buf, inlen + keylen + n, out);
  }
  else if (n == 32 && hash_alg == XMSS_SHAKE) {
    shake128(out, 32, buf, inlen + keylen + n);
  }
  else if (n == 64 && hash_alg == XMSS_SHA2) {
    SHA512(buf, inlen + keylen + n, out);
  }
  else if (n == 64 && hash_alg == XMSS_SHAKE) {
    shake256(out, 64, buf, inlen + keylen + n);
  }
  else {
    return 1;
  }
  return 0;
}

/**
 * Implements PRF
 */
int prf(unsigned char *out, const unsigned char *in, const unsigned char *key, unsigned int keylen, const unsigned char hash_alg)
{ 
  return core_hash(out, 3, key, keylen, in, 32, keylen, hash_alg);
}

/*
 * Implemts H_msg
 */
int h_msg(unsigned char *out, const unsigned char *in, unsigned long long inlen, const unsigned char *key, const unsigned int keylen, const unsigned int n, const unsigned char hash_alg)
{
  if (keylen != 3*n){
    fprintf(stderr, "H_msg takes 3n-bit keys, we got n=%d but a keylength of %d.\n", n, keylen);
    return 1;
  }  
  return core_hash(out, 2, key, keylen, in, inlen, n, hash_alg);
}

/**
 * We assume the left half is in in[0]...in[n-1]
 */
int hash_h(unsigned char *out, const unsigned char *in, const unsigned char *pub_seed, uint32_t addr[8], const unsigned int n, const unsigned char hash_alg)
{

  unsigned char buf[2*n];
  unsigned char key[n];
  unsigned char bitmask[2*n];
  unsigned char byte_addr[32];
  unsigned int i;

  setKeyAndMask(addr, 0);
  addr_to_byte(byte_addr, addr);
  prf(key, byte_addr, pub_seed, n, hash_alg);
  // Use MSB order
  setKeyAndMask(addr, 1);
  addr_to_byte(byte_addr, addr);
  prf(bitmask, byte_addr, pub_seed, n, hash_alg);
  setKeyAndMask(addr, 2);
  addr_to_byte(byte_addr, addr);
  prf(bitmask+n, byte_addr, pub_seed, n, hash_alg);
  for (i = 0; i < 2*n; i++) {
    buf[i] = in[i] ^ bitmask[i];
  }
  return core_hash(out, 1, key, n, buf, 2*n, n, hash_alg);
}

int hash_f(unsigned char *out, const unsigned char *in, const unsigned char *pub_seed, uint32_t addr[8], const unsigned int n, const unsigned char hash_alg)
{
  unsigned char buf[n];
  unsigned char key[n];
  unsigned char bitmask[n];
  unsigned char byte_addr[32];
  unsigned int i;

  setKeyAndMask(addr, 0);  
  addr_to_byte(byte_addr, addr);  
  prf(key, byte_addr, pub_seed, n, hash_alg);
  
  setKeyAndMask(addr, 1);
  addr_to_byte(byte_addr, addr);
  prf(bitmask, byte_addr, pub_seed, n, hash_alg);
  
  for (i = 0; i < n; i++) {
    buf[i] = in[i] ^ bitmask[i];
  }
  return core_hash(out, 0, key, n, buf, n, n, hash_alg);
}
