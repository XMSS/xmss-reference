/*
xmss_commons.h 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/
#ifndef XMSS_COMMONS_H
#define XMSS_COMMONS_H

#include <stdlib.h>
#include <stdint.h>

void to_byte(unsigned char *output, unsigned long long in, uint32_t bytes);

void hexdump(const unsigned char *a, size_t len);

void gen_leaf_wots(unsigned char *leaf,
                   const unsigned char *sk_seed, const unsigned char *pub_seed,
                   uint32_t ltree_addr[8], uint32_t ots_addr[8]);

void get_seed(unsigned char *seed,
              const unsigned char *sk_seed, uint32_t addr[8]);

void l_tree(unsigned char *leaf, unsigned char *wots_pk,
            const unsigned char *pub_seed, uint32_t addr[8]);

int xmss_core_sign_open(unsigned char *m, unsigned long long *mlen,
                        const unsigned char *sm, unsigned long long smlen,
                        const unsigned char *pk);

int xmssmt_core_sign_open(unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk);
#endif
