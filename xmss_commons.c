#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "wots.h"
#include "xmss_commons.h"

/**
 * Converts the value of 'in' to 'len' bytes in big-endian byte order.
 */
void ull_to_bytes(unsigned char *out, unsigned long long in, uint32_t len)
{
    int i;

    for (i = len - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}

/**
 * Computes the leaf at a given address. First generates the WOTS key pair,
 * then computes leaf using l_tree. As this happens position independent, we
 * only require that addr encodes the right ltree-address.
 */
void gen_leaf_wots(const xmss_params *params, unsigned char *leaf,
                   const unsigned char *sk_seed, const unsigned char *pub_seed,
                   uint32_t ltree_addr[8], uint32_t ots_addr[8])
{
    unsigned char seed[params->n];
    unsigned char pk[params->wots_keysize];

    get_seed(params, seed, sk_seed, ots_addr);
    wots_pkgen(params, pk, seed, pub_seed, ots_addr);

    l_tree(params, leaf, pk, pub_seed, ltree_addr);
}

/**
 * Used for pseudo-random key generation.
 * Generates the seed for the WOTS key pair at address 'addr'.
 *
 * Takes n-byte sk_seed and returns n-byte seed using 32 byte address 'addr'.
 */
void get_seed(const xmss_params *params, unsigned char *seed,
              const unsigned char *sk_seed, uint32_t addr[8])
{
    unsigned char bytes[32];

    /* Make sure that chain addr, hash addr, and key bit are zeroed. */
    set_chain_addr(addr, 0);
    set_hash_addr(addr, 0);
    set_key_and_mask(addr, 0);

    /* Generate seed. */
    addr_to_bytes(bytes, addr);
    prf(params, seed, bytes, sk_seed, params->n);
}

/**
 * Computes a leaf node from a WOTS public key using an L-tree.
 * Note that this destroys the used WOTS public key.
 */
void l_tree(const xmss_params *params,
            unsigned char *leaf, unsigned char *wots_pk,
            const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned int l = params->wots_len;
    unsigned int parent_nodes;
    uint32_t i;
    uint32_t height = 0;

    set_tree_height(addr, height);

    while (l > 1) {
        parent_nodes = l >> 1;
        for (i = 0; i < parent_nodes; i++) {
            set_tree_index(addr, i);
            /* Hashes the nodes at (i*2)*params->n and (i*2)*params->n + 1 */
            hash_h(params, wots_pk + i*params->n, wots_pk + (i*2)*params->n, pub_seed, addr);
        }
        /* If the row contained an odd number of nodes, the last node was not hashed.
           Instead, we pull it up to the next layer. */
        if (l & 1) {
            memcpy(wots_pk + (l >> 1)*params->n, wots_pk + (l - 1)*params->n, params->n);
            l = (l >> 1) + 1;
        }
        else {
            l = l >> 1;
        }
        height++;
        set_tree_height(addr, height);
    }
    memcpy(leaf, wots_pk, params->n);
}

/**
 * Computes a root node given a leaf and an auth path
 */
static void validate_authpath(const xmss_params *params, unsigned char *root,
                              const unsigned char *leaf, unsigned long leafidx,
                              const unsigned char *authpath,
                              const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i, j;
    unsigned char buffer[2*params->n];

    /* If leafidx is odd (last bit = 1), current path element is a right child
       and authpath has to go left. Otherwise it is the other way around. */
    if (leafidx & 1) {
        for (j = 0; j < params->n; j++) {
            buffer[params->n + j] = leaf[j];
            buffer[j] = authpath[j];
        }
    }
    else {
        for (j = 0; j < params->n; j++) {
            buffer[j] = leaf[j];
            buffer[params->n + j] = authpath[j];
        }
    }
    authpath += params->n;

    for (i = 0; i < params->tree_height-1; i++) {
        set_tree_height(addr, i);
        leafidx >>= 1;
        set_tree_index(addr, leafidx);
        /* Pick the right or left neighbor, depending on parity of the node. */
        if (leafidx & 1) {
            hash_h(params, buffer + params->n, buffer, pub_seed, addr);
            for (j = 0; j < params->n; j++) {
                buffer[j] = authpath[j];
            }
        }
        else {
            hash_h(params, buffer, buffer, pub_seed, addr);
            for (j = 0; j < params->n; j++) {
                buffer[j + params->n] = authpath[j];
            }
        }
        authpath += params->n;
    }
    set_tree_height(addr, params->tree_height - 1);
    leafidx >>= 1;
    set_tree_index(addr, leafidx);
    hash_h(params, root, buffer, pub_seed, addr);
}

/**
 * Verifies a given message signature pair under a given public key.
 * Note that this assumes a pk without an OID, i.e. [root || PUB_SEED]
 */
int xmss_core_sign_open(const xmss_params *params,
                        unsigned char *m, unsigned long long *mlen,
                        const unsigned char *sm, unsigned long long smlen,
                        const unsigned char *pk)
{
    unsigned long long i;
    unsigned long idx = 0;
    unsigned char wots_pk[params->wots_keysize];
    unsigned char pkhash[params->n];
    unsigned char root[params->n];
    unsigned char msg_h[params->n];
    unsigned char hash_key[3*params->n];

    unsigned char pub_seed[params->n];
    memcpy(pub_seed, pk + params->n, params->n);

    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    set_type(ots_addr, 0);
    set_type(ltree_addr, 1);
    set_type(node_addr, 2);

    *mlen = smlen - params->bytes;

    /* Convert the index bytes from the signature to an integer. */
    for (i = 0; i < params->index_len; i++) {
        idx |= ((unsigned long long)sm[i]) << (8*(params->index_len - 1 - i));
    }

    /* Prepare the hash key, of the form [R || root || idx]. */
    memcpy(hash_key, sm + params->index_len, params->n);
    memcpy(hash_key + params->n, pk, params->n);
    ull_to_bytes(hash_key + 2*params->n, idx, params->n);

    /* Compute the message hash. */
    h_msg(params, msg_h, sm + params->bytes, *mlen, hash_key, 3*params->n);
    sm += params->index_len + params->n;

    /* The WOTS public key is only correct if the signature was correct. */
    set_ots_addr(ots_addr, idx);
    wots_pk_from_sig(params, wots_pk, sm, msg_h, pub_seed, ots_addr);
    sm += params->wots_keysize;

    /* Compute the leaf node using the WOTS public key. */
    set_ltree_addr(ltree_addr, idx);
    l_tree(params, pkhash, wots_pk, pub_seed, ltree_addr);

    /* Compute the root node. */
    validate_authpath(params, root, pkhash, idx, sm, pub_seed, node_addr);
    sm += params->tree_height*params->n;

    /* Check if the root node equals the root node in the public key. */
    for (i = 0; i < params->n; i++) {
        if (root[i] != pk[i]) {
            for (i = 0; i < *mlen; i++) {
                m[i] = 0;
            }
            *mlen = -1;
            return -1;
        }
    }

    /* If verification was successful, copy the message from the signature. */
    for (i = 0; i < *mlen; i++) {
        m[i] = sm[i];
    }

    return 0;
}

/**
 * Verifies a given message signature pair under a given public key.
 * Note that this assumes a pk without an OID, i.e. [root || PUB_SEED]
 */
int xmssmt_core_sign_open(const xmss_params *params,
                          unsigned char *m, unsigned long long *mlen,
                          const unsigned char *sm, unsigned long long smlen,
                          const unsigned char *pk)
{
    uint32_t idx_leaf;
    unsigned long long i;
    unsigned long long idx = 0;
    unsigned char wots_pk[params->wots_keysize];
    unsigned char pkhash[params->n];
    unsigned char root[params->n];
    unsigned char *msg_h = root;
    unsigned char hash_key[3*params->n];
    const unsigned char *pub_seed = pk + params->n;

    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    set_type(ots_addr, 0);
    set_type(ltree_addr, 1);
    set_type(node_addr, 2);

    *mlen = smlen - params->bytes;

    /* Convert the index bytes from the signature to an integer. */
    for (i = 0; i < params->index_len; i++) {
        idx |= ((unsigned long long)sm[i]) << (8*(params->index_len - 1 - i));
    }

    /* Prepare the hash key, of the form [R || root || idx]. */
    memcpy(hash_key, sm + params->index_len, params->n);
    memcpy(hash_key + params->n, pk, params->n);
    ull_to_bytes(hash_key + 2*params->n, idx, params->n);

    /* Compute the message hash. */
    h_msg(params, msg_h, sm + params->bytes, *mlen, hash_key, 3*params->n);
    sm += params->index_len + params->n;

    /* For each subtree.. */
    for (i = 0; i < params->d; i++) {
        idx_leaf = (idx & ((1 << params->tree_height)-1));
        idx = idx >> params->tree_height;

        set_layer_addr(ots_addr, i);
        set_layer_addr(ltree_addr, i);
        set_layer_addr(node_addr, i);

        set_tree_addr(ltree_addr, idx);
        set_tree_addr(ots_addr, idx);
        set_tree_addr(node_addr, idx);

        /* The WOTS public key is only correct if the signature was correct. */
        set_ots_addr(ots_addr, idx_leaf);
        /* Initially, root = msg_h, but on subsequent iterations it is the root
           of the subtree below the currently processed subtree. */
        wots_pk_from_sig(params, wots_pk, sm, root, pub_seed, ots_addr);
        sm += params->wots_keysize;

        /* Compute the leaf node using the WOTS public key. */
        set_ltree_addr(ltree_addr, idx_leaf);
        l_tree(params, pkhash, wots_pk, pub_seed, ltree_addr);

        /* Compute the root node of this subtree. */
        validate_authpath(params, root, pkhash, idx_leaf, sm, pub_seed, node_addr);
        sm += params->tree_height*params->n;
    }

    /* Check if the final root node equals the root node in the public key. */
    for (i = 0; i < params->n; i++) {
        if (root[i] != pk[i]) {
            for (i = 0; i < *mlen; i++) {
                m[i] = 0;
            }
            *mlen = -1;
            return -1;
        }
    }

    /* If verification was successful, copy the message from the signature. */
    for (i = 0; i < *mlen; i++) {
        m[i] = sm[i];
    }

    return 0;
}
