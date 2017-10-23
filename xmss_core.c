#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "randombytes.h"
#include "wots.h"
#include "xmss_commons.h"
#include "xmss_core.h"

/**
 * Merkle's TreeHash algorithm. Currently only used for key generation.
 * Computes the root node of the top-most subtree.
 */
static void treehash_root(const xmss_params *params, unsigned char *root,
                          const unsigned char *sk_seed,
                          const unsigned char *pub_seed)
{
    unsigned char stack[(params->tree_height+1)*params->n];
    unsigned int heights[params->tree_height+1];
    unsigned int offset = 0;

    /* The subtree has at most 2^20 leafs, so uint32_t suffices. */
    uint32_t idx;

    /* We need all three types of addresses in parallel. */
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    /* To support the multi-tree setting, select the top tree. */
    set_layer_addr(ots_addr, params->d - 1);
    set_layer_addr(ltree_addr, params->d - 1);
    set_layer_addr(node_addr, params->d - 1);

    set_type(ots_addr, 0);
    set_type(ltree_addr, 1);
    set_type(node_addr, 2);

    for (idx = 0; idx < (uint32_t)(1 << params->tree_height); idx++) {
        /* Add the next leaf node to the stack. */
        set_ltree_addr(ltree_addr, idx);
        set_ots_addr(ots_addr, idx);
        gen_leaf_wots(params, stack + offset*params->n,
                      sk_seed, pub_seed, ltree_addr, ots_addr);
        heights[offset] = 0;
        offset++;

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Hash the top-most nodes from the stack together. */
            set_tree_height(node_addr, heights[offset - 1]);
            set_tree_index(node_addr, (idx >> (heights[offset - 1] + 1)));
            hash_h(params, stack + (offset-2)*params->n,
                           stack + (offset-2)*params->n, pub_seed, node_addr);
            /* Note that the top-most node is now one layer higher. */
            heights[offset-2]++;
            offset--;
        }
    }
    memcpy(root, stack, params->n);
}

/**
 * Computes the authpath and the root. This method is using a lot of space as we
 * build the whole tree and then select the authpath nodes. For more efficient
 * algorithms see e.g. the chapter on hash-based signatures in Bernstein,
 * Buchmann, Dahmen. "Post-quantum Cryptography", Springer 2009.
 *
 * Returns the authpath in "authpath" with the node on level 0 at index 0.
 */
static void compute_authpath_wots(const xmss_params *params, unsigned char *root, unsigned char *authpath, unsigned long leaf_idx, const unsigned char *sk_seed, unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i, j, level;

    unsigned char tree[2*(1 << params->tree_height)*params->n];

    uint32_t ots_addr[8];
    uint32_t ltree_addr[8];
    uint32_t node_addr[8];

    memcpy(ots_addr, addr, 12);
    set_type(ots_addr, 0);
    memcpy(ltree_addr, addr, 12);
    set_type(ltree_addr, 1);
    memcpy(node_addr, addr, 12);
    set_type(node_addr, 2);

    // Compute all leaves
    for (i = 0; i < (1U << params->tree_height); i++) {
        set_ltree_addr(ltree_addr, i);
        set_ots_addr(ots_addr, i);
        gen_leaf_wots(params, tree+((1 << params->tree_height)*params->n + i*params->n), sk_seed, pub_seed, ltree_addr, ots_addr);
    }


    level = 0;
    // Compute tree:
    // Outer loop: For each inner layer
    for (i = (1 << params->tree_height); i > 1; i>>=1) {
        set_tree_height(node_addr, level);
        // Inner loop: for each pair of sibling nodes
        for (j = 0; j < i; j+=2) {
            set_tree_index(node_addr, j>>1);
            hash_h(params, tree + (i>>1)*params->n + (j>>1) * params->n, tree + i*params->n + j*params->n, pub_seed, node_addr);
        }
        level++;
    }

    // copy authpath
    for (i = 0; i < params->tree_height; i++) {
        memcpy(authpath + i*params->n, tree + ((1 << params->tree_height)>>i)*params->n + ((leaf_idx >> i) ^ 1) * params->n, params->n);
    }

    // copy root
    memcpy(root, tree+params->n, params->n);
}

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) index || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED], omitting algorithm OID.
 */
int xmss_core_keypair(const xmss_params *params,
                      unsigned char *pk, unsigned char *sk)
{
    /* Initialize index to 0. */
    memset(sk, 0, params->index_len);
    sk += 4;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED. */
    randombytes(sk, 3 * params->n);
    memcpy(pk + params->n, sk + 2*params->n, params->n);

    /* Compute root node. */
    treehash_root(params, pk, sk, pk + params->n);
    memcpy(sk + 3*params->n, pk, params->n);

    return 0;
}

/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmss_core_sign(const xmss_params *params, unsigned char *sk, unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen)
{
    uint16_t i = 0;

    // Extract SK
    uint32_t idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
    unsigned char sk_seed[params->n];
    unsigned char sk_prf[params->n];
    unsigned char pub_seed[params->n];
    unsigned char hash_key[3*params->n];

    // index as 32 bytes string
    unsigned char idx_bytes_32[32];
    ull_to_bytes(idx_bytes_32, 32, idx);

    memcpy(sk_seed, sk+4, params->n);
    memcpy(sk_prf, sk+4+params->n, params->n);
    memcpy(pub_seed, sk+4+2*params->n, params->n);

    // Update SK
    sk[0] = ((idx + 1) >> 24) & 255;
    sk[1] = ((idx + 1) >> 16) & 255;
    sk[2] = ((idx + 1) >> 8) & 255;
    sk[3] = (idx + 1) & 255;
    // Secret key for this non-forward-secure version is now updated.
    // A production implementation should consider using a file handle instead,
    //  and write the updated secret key at this point!

    // Init working params
    unsigned char R[params->n];
    unsigned char msg_h[params->n];
    unsigned char root[params->n];
    unsigned char ots_seed[params->n];
    uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    // ---------------------------------
    // Message Hashing
    // ---------------------------------

    // Message Hash:
    // First compute pseudorandom value
    prf(params, R, idx_bytes_32, sk_prf, params->n);
    // Generate hash key (R || root || idx)
    memcpy(hash_key, R, params->n);
    memcpy(hash_key+params->n, sk+4+3*params->n, params->n);
    ull_to_bytes(hash_key+2*params->n, params->n, idx);
    // Then use it for message digest
    h_msg(params, msg_h, m, mlen, hash_key, 3*params->n);

    // Start collecting signature
    *smlen = 0;

    // Copy index to signature
    sm[0] = (idx >> 24) & 255;
    sm[1] = (idx >> 16) & 255;
    sm[2] = (idx >> 8) & 255;
    sm[3] = idx & 255;

    sm += 4;
    *smlen += 4;

    // Copy R to signature
    for (i = 0; i < params->n; i++)
    sm[i] = R[i];

    sm += params->n;
    *smlen += params->n;

    // ----------------------------------
    // Now we start to "really sign"
    // ----------------------------------

    // Prepare Address
    set_type(ots_addr, 0);
    set_ots_addr(ots_addr, idx);

    // Compute seed for OTS key pair
    get_seed(params, ots_seed, sk_seed, ots_addr);

    // Compute WOTS signature
    wots_sign(params, sm, msg_h, ots_seed, pub_seed, ots_addr);

    sm += params->wots_keysize;
    *smlen += params->wots_keysize;

    compute_authpath_wots(params, root, sm, idx, sk_seed, pub_seed, ots_addr);
    sm += params->tree_height*params->n;
    *smlen += params->tree_height*params->n;

    memcpy(sm, m, mlen);
    *smlen += mlen;

    return 0;
}

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algorithm OID.
 */
int xmssmt_core_keypair(const xmss_params *params, unsigned char *pk, unsigned char *sk)
{
    /* Initialize index to 0. */
    memset(sk, 0, params->index_len);
    sk += 4;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED. */
    randombytes(sk, 3 * params->n);
    memcpy(pk + params->n, sk + 2*params->n, params->n);

    /* Compute root node of the top-most subtree. */
    treehash_root(params, pk, sk, pk + params->n);
    memcpy(sk + 3*params->n, pk, params->n);

    return 0;
}

/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmssmt_core_sign(const xmss_params *params, unsigned char *sk, unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen)
{
    uint64_t idx_tree;
    uint32_t idx_leaf;
    uint64_t i;

    unsigned char sk_seed[params->n];
    unsigned char sk_prf[params->n];
    unsigned char pub_seed[params->n];
    // Init working params
    unsigned char R[params->n];
    unsigned char hash_key[3*params->n];
    unsigned char msg_h[params->n];
    unsigned char root[params->n];
    unsigned char ots_seed[params->n];
    uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char idx_bytes_32[32];

    // Extract SK
    unsigned long long idx = 0;
    for (i = 0; i < params->index_len; i++) {
        idx |= ((unsigned long long)sk[i]) << 8*(params->index_len - 1 - i);
    }

    memcpy(sk_seed, sk+params->index_len, params->n);
    memcpy(sk_prf, sk+params->index_len+params->n, params->n);
    memcpy(pub_seed, sk+params->index_len+2*params->n, params->n);

    // Update SK
    for (i = 0; i < params->index_len; i++) {
        sk[i] = ((idx + 1) >> 8*(params->index_len - 1 - i)) & 255;
    }
    // Secret key for this non-forward-secure version is now updated.
    // A production implementation should consider using a file handle instead,
    //  and write the updated secret key at this point!

    // ---------------------------------
    // Message Hashing
    // ---------------------------------

    // Message Hash:
    // First compute pseudorandom value
    ull_to_bytes(idx_bytes_32, 32, idx);
    prf(params, R, idx_bytes_32, sk_prf, params->n);
    // Generate hash key (R || root || idx)
    memcpy(hash_key, R, params->n);
    memcpy(hash_key+params->n, sk+params->index_len+3*params->n, params->n);
    ull_to_bytes(hash_key+2*params->n, params->n, idx);

    // Then use it for message digest
    h_msg(params, msg_h, m, mlen, hash_key, 3*params->n);

    // Start collecting signature
    *smlen = 0;

    // Copy index to signature
    for (i = 0; i < params->index_len; i++) {
        sm[i] = (idx >> 8*(params->index_len - 1 - i)) & 255;
    }

    sm += params->index_len;
    *smlen += params->index_len;

    // Copy R to signature
    for (i = 0; i < params->n; i++) {
        sm[i] = R[i];
    }

    sm += params->n;
    *smlen += params->n;

    // ----------------------------------
    // Now we start to "really sign"
    // ----------------------------------

    // Handle lowest layer separately as it is slightly different...

    // Prepare Address
    set_type(ots_addr, 0);
    idx_tree = idx >> params->tree_height;
    idx_leaf = (idx & ((1 << params->tree_height)-1));
    set_layer_addr(ots_addr, 0);
    set_tree_addr(ots_addr, idx_tree);
    set_ots_addr(ots_addr, idx_leaf);

    // Compute seed for OTS key pair
    get_seed(params, ots_seed, sk_seed, ots_addr);

    // Compute WOTS signature
    wots_sign(params, sm, msg_h, ots_seed, pub_seed, ots_addr);

    sm += params->wots_keysize;
    *smlen += params->wots_keysize;

    compute_authpath_wots(params, root, sm, idx_leaf, sk_seed, pub_seed, ots_addr);
    sm += params->tree_height*params->n;
    *smlen += params->tree_height*params->n;

    // Now loop over remaining layers...
    unsigned int j;
    for (j = 1; j < params->d; j++) {
        // Prepare Address
        idx_leaf = (idx_tree & ((1 << params->tree_height)-1));
        idx_tree = idx_tree >> params->tree_height;
        set_layer_addr(ots_addr, j);
        set_tree_addr(ots_addr, idx_tree);
        set_ots_addr(ots_addr, idx_leaf);

        // Compute seed for OTS key pair
        get_seed(params, ots_seed, sk_seed, ots_addr);

        // Compute WOTS signature
        wots_sign(params, sm, root, ots_seed, pub_seed, ots_addr);

        sm += params->wots_keysize;
        *smlen += params->wots_keysize;

        compute_authpath_wots(params, root, sm, idx_leaf, sk_seed, pub_seed, ots_addr);
        sm += params->tree_height*params->n;
        *smlen += params->tree_height*params->n;
    }

    memcpy(sm, m, mlen);
    *smlen += mlen;

    return 0;
}
