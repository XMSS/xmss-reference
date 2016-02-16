/*
prg.c version 20160210
Andreas Hülsing
Joost Rijneveld
Public domain.
*/
#include "chacha.h"
#include "prg.h"
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

const unsigned char zero_nonce[12] = {0};

/**
 * Generates rlen output bytes using ChaCha20 with a zero nonce and counter = 0
 */
void prg(unsigned char *r, unsigned long long rlen, const unsigned char *key, unsigned int key_len)
{
  if (key_len == 32) {
    CRYPTO_chacha_20_keystream(r, rlen, key, zero_nonce, 0);
  }
  else {
    if (key_len == 64) {
      unsigned long long left = rlen;
      u_int32_t counter = 0;
      unsigned char *c = (unsigned char*)&counter;
      unsigned int length;
      unsigned int i = 0;
      unsigned char tmp[64];
      while (left > 0) {
        HMAC(EVP_sha512(), key, key_len, c , 4, tmp, &length);
        if (length != 64) {
          fprintf(stderr, "HMAC outputs %d bytes... That should not happen...", length);
        }
        for (i = 0; ((i < length) && (i < left)); i++) {
          r[rlen-left+i] = tmp[i];
        }
        left -= length;
        counter++;
      }
    }
    else {
      fprintf(stderr,"prg.c:: Code only supports 32 byte and 64 byte seeds");
    }
  }
}

/**
 * Generates n output bytes using ChaCha20 (n=32) or HMAC-SHA2-512 (n=64).
 *
 * For ChaCha, nonce and counter are set depending on the address addr. For HMAC, addr is used as message.
 */
void prg_with_counter(unsigned char *r, const unsigned char *key, unsigned int n, const unsigned char addr[16])
{
  int i;
  unsigned char nonce[12];
  if (n == 32) {
    for (i = 0; i < 12; i++) {
      nonce[i] = addr[i];
    }
    uint32_t counter;
    counter = (((uint32_t)addr[12]) << 24) | (((uint32_t)addr[13]) << 16) | (((uint32_t)addr[14]) << 8) | addr[15];
    // TODO: Check address handling. Endianess?
    CRYPTO_chacha_20_keystream(r, n, key, nonce, counter);
  }
  else {
    if (n == 64) {
      unsigned int length;
      HMAC(EVP_sha512(), key, n, addr, 16, r, &length);
      if (length != 64) {
        fprintf(stderr, "HMAC outputs %d bytes... That should not happen...", length);
      }
    }
    else {
      fprintf(stderr,"prg.c:: Code only supports 32 byte and 64 byte seeds");
    }
  }
}