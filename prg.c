/*
prg.c version 20150811
Andreas Hülsing
Public domain.
*/

#include "chacha.h"
#include "prg.h"

const unsigned char zero_nonce[12] = {0};

/**
 * Generates rlen output bytes using ChaCha20 with a zero nonce and counter = 0
 */
void prg(unsigned char *r, unsigned long long rlen, const unsigned char *key, unsigned int key_len)
{  
  CRYPTO_chacha_20_keystream(r, rlen, key, zero_nonce, 0);
}

/**
 * Generates rlen output bytes using ChaCha20.
 * Nonce and counter are set depending on the address addr.
 */
void prg_with_counter(unsigned char *r, unsigned long long rlen, const unsigned char *key, unsigned int key_len, const unsigned char addr[16])
{
  int i;
  unsigned char nonce[12];
  for(i = 0; i < 12; i++)
  {
    nonce[i] = addr[i];
  }
  uint32_t counter;
  counter = (addr[12] << 24)|(addr[13] << 16)|(addr[14] << 8)|addr[15];
  // TODO: Check address handling. Endianess?
  CRYPTO_chacha_20_keystream(r, rlen, key, nonce, counter);
}