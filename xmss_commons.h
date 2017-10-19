/*
xmss_commons.h 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/
#ifndef XMSS_COMMONS_H
#define XMSS_COMMONS_H

#include <stdint.h>
#include "params.h"

void to_byte(unsigned char *output, unsigned long long in, uint32_t bytes);

void gen_leaf_wots(const xmss_params *params, unsigned char *leaf,
                   const unsigned char *sk_seed, const unsigned char *pub_seed,
                   uint32_t ltree_addr[8], uint32_t ots_addr[8]);

void get_seed(const xmss_params *params, unsigned char *seed,
              const unsigned char *sk_seed, uint32_t addr[8]);

void l_tree(const xmss_params *params, unsigned char *leaf, unsigned char *wots_pk,
            const unsigned char *pub_seed, uint32_t addr[8]);

int xmss_core_sign_open(const xmss_params *params,
                        unsigned char *m, unsigned long long *mlen,
                        const unsigned char *sm, unsigned long long smlen,
                        const unsigned char *pk);

int xmssmt_core_sign_open(const xmss_params *params,
                          unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk);
#endif
