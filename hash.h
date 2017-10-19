/*
hash.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#ifndef XMSS_HASH_H
#define XMSS_HASH_H

#include "params.h"

#define IS_LITTLE_ENDIAN 1

unsigned char* addr_to_byte(unsigned char *bytes, const uint32_t addr[8]);

int prf(const xmss_params *params,
        unsigned char *out, const unsigned char *in,
        const unsigned char *key, unsigned int keylen);

int h_msg(const xmss_params *params,
          unsigned char *out,
          const unsigned char *in, unsigned long long inlen,
          const unsigned char *key, const unsigned int keylen);

int hash_h(const xmss_params *params,
           unsigned char *out, const unsigned char *in,
           const unsigned char *pub_seed, uint32_t addr[8]);

int hash_f(const xmss_params *params,
           unsigned char *out, const unsigned char *in,
           const unsigned char *pub_seed, uint32_t addr[8]);

#endif
