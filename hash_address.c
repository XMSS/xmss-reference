/*
hash_address.c version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/
#include <stdint.h>

void set_layer_addr(uint32_t addr[8], uint32_t layer) {
    addr[0] = layer;
}

void set_tree_addr(uint32_t addr[8], uint64_t tree) {
    addr[1] = (uint32_t) (tree >> 32);
    addr[2] = (uint32_t) tree;
}

void set_type(uint32_t addr[8], uint32_t type) {
    int i;

    addr[3] = type;
    for (i = 4; i < 8; i++) {
        addr[i] = 0;
    }
}

void set_key_and_mask(uint32_t addr[8], uint32_t key_and_mask) {
    addr[7] = key_and_mask;
}

/* These functions are used for OTS addresses. */

void set_ots_addr(uint32_t addr[8], uint32_t ots) {
    addr[4] = ots;
}

void set_chain_addr(uint32_t addr[8], uint32_t chain) {
    addr[5] = chain;
}

void set_hash_addr(uint32_t addr[8], uint32_t hash) {
    addr[6] = hash;
}

/* This function is used for L-trees. */

void set_ltree_addr(uint32_t addr[8], uint32_t ltree) {
    addr[4] = ltree;
}

/* These functions are used for hash tree addresses. */

void set_tree_height(uint32_t addr[8], uint32_t treeHeight) {
    addr[5] = treeHeight;
}

void set_tree_index(uint32_t addr[8], uint32_t treeIndex) {
    addr[6] = treeIndex;
}
