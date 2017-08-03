/*
xmss_commons.c 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "wots.h"
#include "xmss_commons.h"

void to_byte(unsigned char *out, unsigned long long in, uint32_t bytes)
{
    int i;

    for (i = bytes-1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}

/**
 * Computes the leaf at a given address. First generates the WOTS key pair, then computes leaf using l_tree. As this happens position independent, we only require that addr encodes the right ltree-address.
 */
void gen_leaf_wots(unsigned char *leaf,
                   const unsigned char *sk_seed, const unsigned char *pub_seed,
                   uint32_t ltree_addr[8], uint32_t ots_addr[8])
{
    unsigned char seed[XMSS_N];
    unsigned char pk[XMSS_WOTS_KEYSIZE];

    get_seed(seed, sk_seed, ots_addr);
    wots_pkgen(pk, seed, pub_seed, ots_addr);

    l_tree(leaf, pk, pub_seed, ltree_addr);
}

/**
 * Used for pseudorandom keygeneration,
 * generates the seed for the WOTS keypair at address addr
 *
 * takes XMSS_N byte sk_seed and returns XMSS_N byte seed using 32 byte address addr.
 */
void get_seed(unsigned char *seed,
              const unsigned char *sk_seed, uint32_t addr[8])
{
    unsigned char bytes[32];

    // Make sure that chain addr, hash addr, and key bit are 0!
    set_chain_addr(addr, 0);
    set_hash_addr(addr, 0);
    set_key_and_mask(addr, 0);
    // Generate pseudorandom value
    addr_to_byte(bytes, addr);
    prf(seed, bytes, sk_seed, XMSS_N);
}

/**
 * Computes a leaf from a WOTS public key using an L-tree.
 */
void l_tree(unsigned char *leaf, unsigned char *wots_pk,
            const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned int l = XMSS_WOTS_LEN;
    uint32_t i = 0;
    uint32_t height = 0;
    uint32_t bound;

    set_tree_height(addr, height);

    while (l > 1) {
        bound = l >> 1;
        for (i = 0; i < bound; i++) {
            set_tree_index(addr, i);
            hash_h(wots_pk + i*XMSS_N, wots_pk + i*2*XMSS_N, pub_seed, addr);
        }
        if (l & 1) {
            memcpy(wots_pk + (l >> 1)*XMSS_N, wots_pk + (l - 1)*XMSS_N, XMSS_N);
            l = (l >> 1) + 1;
        }
        else {
            l = l >> 1;
        }
        height++;
        set_tree_height(addr, height);
    }
    memcpy(leaf, wots_pk, XMSS_N);
}

/**
 * Computes a root node given a leaf and an authapth
 */
static void validate_authpath(unsigned char *root,
                              const unsigned char *leaf, unsigned long leafidx,
                              const unsigned char *authpath,
                              const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i, j;
    unsigned char buffer[2*XMSS_N];

    // If leafidx is odd (last bit = 1), current path element is a right child and authpath has to go to the left.
    // Otherwise, it is the other way around
    if (leafidx & 1) {
        for (j = 0; j < XMSS_N; j++) {
            buffer[XMSS_N + j] = leaf[j];
            buffer[j] = authpath[j];
        }
    }
    else {
        for (j = 0; j < XMSS_N; j++) {
            buffer[j] = leaf[j];
            buffer[XMSS_N + j] = authpath[j];
        }
    }
    authpath += XMSS_N;

    for (i = 0; i < XMSS_TREEHEIGHT-1; i++) {
        set_tree_height(addr, i);
        leafidx >>= 1;
        set_tree_index(addr, leafidx);
        if (leafidx & 1) {
            hash_h(buffer + XMSS_N, buffer, pub_seed, addr);
            for (j = 0; j < XMSS_N; j++) {
                buffer[j] = authpath[j];
            }
        }
        else {
            hash_h(buffer, buffer, pub_seed, addr);
            for (j = 0; j < XMSS_N; j++) {
                buffer[j + XMSS_N] = authpath[j];
            }
        }
        authpath += XMSS_N;
    }
    set_tree_height(addr, XMSS_TREEHEIGHT - 1);
    leafidx >>= 1;
    set_tree_index(addr, leafidx);
    hash_h(root, buffer, pub_seed, addr);
}

/**
 * Verifies a given message signature pair under a given public key.
 */
int xmss_core_sign_open(unsigned char *m, unsigned long long *mlen,
                        const unsigned char *sm, unsigned long long smlen,
                        const unsigned char *pk)
{
    unsigned long long i;
    unsigned long idx = 0;
    unsigned char wots_pk[XMSS_WOTS_KEYSIZE];
    unsigned char pkhash[XMSS_N];
    unsigned char root[XMSS_N];
    unsigned char msg_h[XMSS_N];
    unsigned char hash_key[3*XMSS_N];

    unsigned char pub_seed[XMSS_N];
    memcpy(pub_seed, pk + XMSS_N, XMSS_N);

    // Init addresses
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    set_type(ots_addr, 0);
    set_type(ltree_addr, 1);
    set_type(node_addr, 2);

    *mlen = smlen - XMSS_BYTES;

    // Extract index
    for (i = 0; i < XMSS_INDEX_LEN; i++) {
        idx |= ((unsigned long long)sm[i]) << (8*(XMSS_INDEX_LEN - 1 - i));
    }

    // Generate hash key (R || root || idx)
    memcpy(hash_key, sm + XMSS_INDEX_LEN, XMSS_N);
    memcpy(hash_key + XMSS_N, pk, XMSS_N);
    to_byte(hash_key + 2*XMSS_N, idx, XMSS_N);

    // hash message
    h_msg(msg_h, sm + XMSS_BYTES, *mlen, hash_key, 3*XMSS_N);
    sm += XMSS_INDEX_LEN + XMSS_N;

    // Prepare Address
    set_ots_addr(ots_addr, idx);
    // Check WOTS signature
    wots_pk_from_sig(wots_pk, sm, msg_h, pub_seed, ots_addr);
    sm += XMSS_WOTS_KEYSIZE;

    // Compute Ltree
    set_ltree_addr(ltree_addr, idx);
    l_tree(pkhash, wots_pk, pub_seed, ltree_addr);

    // Compute root
    validate_authpath(root, pkhash, idx, sm, pub_seed, node_addr);
    sm += XMSS_TREEHEIGHT*XMSS_N;

    for (i = 0; i < XMSS_N; i++) {
        if (root[i] != pk[i]) {
            for (i = 0; i < *mlen; i++) {
                m[i] = 0;
            }
            *mlen = -1;
            return -1;
        }
    }

    for (i = 0; i < *mlen; i++) {
        m[i] = sm[i];
    }

    return 0;
}

/**
 * Verifies a given message signature pair under a given public key.
 */
int xmssmt_core_sign_open(unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk)
{
    uint32_t idx_leaf;
    unsigned long long i;
    unsigned long long idx = 0;
    unsigned char wots_pk[XMSS_WOTS_KEYSIZE];
    unsigned char pkhash[XMSS_N];
    unsigned char root[XMSS_N];
    unsigned char *msg_h = root;
    unsigned char hash_key[3*XMSS_N];
    const unsigned char *pub_seed = pk + XMSS_N;

    // Init addresses
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    set_type(ots_addr, 0);
    set_type(ltree_addr, 1);
    set_type(node_addr, 2);

    *mlen = smlen - XMSS_BYTES;

    // Extract index
    for (i = 0; i < XMSS_INDEX_LEN; i++) {
        idx |= ((unsigned long long)sm[i]) << (8*(XMSS_INDEX_LEN - 1 - i));
    }

    // Generate hash key (R || root || idx)
    memcpy(hash_key, sm + XMSS_INDEX_LEN, XMSS_N);
    memcpy(hash_key + XMSS_N, pk, XMSS_N);
    to_byte(hash_key + 2*XMSS_N, idx, XMSS_N);

    // hash message
    h_msg(msg_h, sm + XMSS_BYTES, *mlen, hash_key, 3*XMSS_N);
    sm += XMSS_INDEX_LEN + XMSS_N;

    for (i = 0; i < XMSS_D; i++) {
        // Prepare Address
        idx_leaf = (idx & ((1 << XMSS_TREEHEIGHT)-1));
        idx = idx >> XMSS_TREEHEIGHT;

        set_layer_addr(ots_addr, i);
        set_layer_addr(ltree_addr, i);
        set_layer_addr(node_addr, i);

        set_tree_addr(ltree_addr, idx);
        set_tree_addr(ots_addr, idx);
        set_tree_addr(node_addr, idx);

        set_ots_addr(ots_addr, idx_leaf);

        // Check WOTS signature
        wots_pk_from_sig(wots_pk, sm, root, pub_seed, ots_addr);
        sm += XMSS_WOTS_KEYSIZE;

        // Compute Ltree
        set_ltree_addr(ltree_addr, idx_leaf);
        l_tree(pkhash, wots_pk, pub_seed, ltree_addr);

        // Compute root
        validate_authpath(root, pkhash, idx_leaf, sm, pub_seed, node_addr);
        sm += XMSS_TREEHEIGHT*XMSS_N;
    }

    for (i = 0; i < XMSS_N; i++) {
        if (root[i] != pk[i]) {
            for (i = 0; i < *mlen; i++) {
                m[i] = 0;
            }
            *mlen = -1;
            return -1;
        }
    }

    for (i = 0; i < *mlen; i++) {
        m[i] = sm[i];
    }

    return 0;
}
