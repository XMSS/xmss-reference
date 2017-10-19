/*
hash_address.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#ifndef XMSS_HASH_ADDRESS_H
#define XMSS_HASH_ADDRESS_H

#include <stdint.h>

void set_layer_addr(uint32_t addr[8], uint32_t layer);

void set_tree_addr(uint32_t addr[8], uint64_t tree);

void set_type(uint32_t addr[8], uint32_t type);

void set_key_and_mask(uint32_t addr[8], uint32_t key_and_mask);

/* These functions are used for OTS addresses. */

void set_ots_addr(uint32_t addr[8], uint32_t ots);

void set_chain_addr(uint32_t addr[8], uint32_t chain);

void set_hash_addr(uint32_t addr[8], uint32_t hash);

/* This function is used for L-trees. */

void set_ltree_addr(uint32_t addr[8], uint32_t ltree);

/* These functions are used for hash tree addresses. */

void set_tree_height(uint32_t addr[8], uint32_t treeHeight);

void set_tree_index(uint32_t addr[8], uint32_t treeIndex);

#endif
