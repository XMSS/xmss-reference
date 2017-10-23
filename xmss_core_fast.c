#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "randombytes.h"
#include "wots.h"
#include "xmss_commons.h"
#include "xmss_core_fast.h"

/**
 * Initialize BDS state struct
 * parameter names are the same as used in the description of the BDS traversal
 */
void xmss_set_bds_state(bds_state *state, unsigned char *stack,
                        int stackoffset, unsigned char *stacklevels,
                        unsigned char *auth, unsigned char *keep,
                        treehash_inst *treehash, unsigned char *retain,
                        int next_leaf)
{
    state->stack = stack;
    state->stackoffset = stackoffset;
    state->stacklevels = stacklevels;
    state->auth = auth;
    state->keep = keep;
    state->treehash = treehash;
    state->retain = retain;
    state->next_leaf = next_leaf;
}

static int treehash_minheight_on_stack(const xmss_params *params,
                                       bds_state* state,
                                       const treehash_inst *treehash)
{
    unsigned int r = params->tree_height, i;

    for (i = 0; i < treehash->stackusage; i++) {
        if (state->stacklevels[state->stackoffset - i - 1] < r) {
            r = state->stacklevels[state->stackoffset - i - 1];
        }
    }
    return r;
}

/**
 * Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
 * Currently only used for key generation.
 *
 */
static void treehash_init(const xmss_params *params,
                          unsigned char *node, int height, int index,
                          bds_state *state, const unsigned char *sk_seed,
                          const unsigned char *pub_seed, const uint32_t addr[8])
{
    unsigned int idx = index;
    // use three different addresses because at this point we use all three formats in parallel
    uint32_t ots_addr[8];
    uint32_t ltree_addr[8];
    uint32_t node_addr[8];
    // only copy layer and tree address parts
    memcpy(ots_addr, addr, 12);
    // type = ots
    set_type(ots_addr, 0);
    memcpy(ltree_addr, addr, 12);
    set_type(ltree_addr, 1);
    memcpy(node_addr, addr, 12);
    set_type(node_addr, 2);

    uint32_t lastnode, i;
    unsigned char stack[(height+1)*params->n];
    unsigned int stacklevels[height+1];
    unsigned int stackoffset=0;
    unsigned int nodeh;

    lastnode = idx+(1<<height);

    for (i = 0; i < params->tree_height-params->bds_k; i++) {
        state->treehash[i].h = i;
        state->treehash[i].completed = 1;
        state->treehash[i].stackusage = 0;
    }

    i = 0;
    for (; idx < lastnode; idx++) {
        set_ltree_addr(ltree_addr, idx);
        set_ots_addr(ots_addr, idx);
        gen_leaf_wots(params, stack+stackoffset*params->n, sk_seed, pub_seed, ltree_addr, ots_addr);
        stacklevels[stackoffset] = 0;
        stackoffset++;
        if (params->tree_height - params->bds_k > 0 && i == 3) {
            memcpy(state->treehash[0].node, stack+stackoffset*params->n, params->n);
        }
        while (stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2]) {
            nodeh = stacklevels[stackoffset-1];
            if (i >> nodeh == 1) {
                memcpy(state->auth + nodeh*params->n, stack+(stackoffset-1)*params->n, params->n);
            }
            else {
                if (nodeh < params->tree_height - params->bds_k && i >> nodeh == 3) {
                    memcpy(state->treehash[nodeh].node, stack+(stackoffset-1)*params->n, params->n);
                }
                else if (nodeh >= params->tree_height - params->bds_k) {
                    memcpy(state->retain + ((1 << (params->tree_height - 1 - nodeh)) + nodeh - params->tree_height + (((i >> nodeh) - 3) >> 1)) * params->n, stack+(stackoffset-1)*params->n, params->n);
                }
            }
            set_tree_height(node_addr, stacklevels[stackoffset-1]);
            set_tree_index(node_addr, (idx >> (stacklevels[stackoffset-1]+1)));
            hash_h(params, stack+(stackoffset-2)*params->n, stack+(stackoffset-2)*params->n, pub_seed, node_addr);
            stacklevels[stackoffset-2]++;
            stackoffset--;
        }
        i++;
    }

    for (i = 0; i < params->n; i++) {
        node[i] = stack[i];
    }
}

static void treehash_update(const xmss_params *params,
                            treehash_inst *treehash, bds_state *state,
                            const unsigned char *sk_seed,
                            const unsigned char *pub_seed,
                            const uint32_t addr[8])
{
    uint32_t ots_addr[8];
    uint32_t ltree_addr[8];
    uint32_t node_addr[8];
    // only copy layer and tree address parts
    memcpy(ots_addr, addr, 12);
    // type = ots
    set_type(ots_addr, 0);
    memcpy(ltree_addr, addr, 12);
    set_type(ltree_addr, 1);
    memcpy(node_addr, addr, 12);
    set_type(node_addr, 2);

    set_ltree_addr(ltree_addr, treehash->next_idx);
    set_ots_addr(ots_addr, treehash->next_idx);

    unsigned char nodebuffer[2 * params->n];
    unsigned int nodeheight = 0;
    gen_leaf_wots(params, nodebuffer, sk_seed, pub_seed, ltree_addr, ots_addr);
    while (treehash->stackusage > 0 && state->stacklevels[state->stackoffset-1] == nodeheight) {
        memcpy(nodebuffer + params->n, nodebuffer, params->n);
        memcpy(nodebuffer, state->stack + (state->stackoffset-1)*params->n, params->n);
        set_tree_height(node_addr, nodeheight);
        set_tree_index(node_addr, (treehash->next_idx >> (nodeheight+1)));
        hash_h(params, nodebuffer, nodebuffer, pub_seed, node_addr);
        nodeheight++;
        treehash->stackusage--;
        state->stackoffset--;
    }
    if (nodeheight == treehash->h) { // this also implies stackusage == 0
        memcpy(treehash->node, nodebuffer, params->n);
        treehash->completed = 1;
    }
    else {
        memcpy(state->stack + state->stackoffset*params->n, nodebuffer, params->n);
        treehash->stackusage++;
        state->stacklevels[state->stackoffset] = nodeheight;
        state->stackoffset++;
        treehash->next_idx++;
    }
}

/**
 * Performs one treehash update on the instance that needs it the most.
 * Returns 1 if such an instance was not found
 **/
static char bds_treehash_update(const xmss_params *params,
                                bds_state *state, unsigned int updates,
                                const unsigned char *sk_seed,
                                unsigned char *pub_seed,
                                const uint32_t addr[8])
{
    uint32_t i, j;
    unsigned int level, l_min, low;
    unsigned int used = 0;

    for (j = 0; j < updates; j++) {
        l_min = params->tree_height;
        level = params->tree_height - params->bds_k;
        for (i = 0; i < params->tree_height - params->bds_k; i++) {
            if (state->treehash[i].completed) {
                low = params->tree_height;
            }
            else if (state->treehash[i].stackusage == 0) {
                low = i;
            }
            else {
                low = treehash_minheight_on_stack(params, state, &(state->treehash[i]));
            }
            if (low < l_min) {
                level = i;
                l_min = low;
            }
        }
        if (level == params->tree_height - params->bds_k) {
            break;
        }
        treehash_update(params, &(state->treehash[level]), state, sk_seed, pub_seed, addr);
        used++;
    }
    return updates - used;
}

/**
 * Updates the state (typically NEXT_i) by adding a leaf and updating the stack
 * Returns 1 if all leaf nodes have already been processed
 **/
static char bds_state_update(const xmss_params *params,
                             bds_state *state, const unsigned char *sk_seed,
                             const unsigned char *pub_seed,
                             const uint32_t addr[8])
{
    uint32_t ltree_addr[8];
    uint32_t node_addr[8];
    uint32_t ots_addr[8];

    unsigned int nodeh;
    int idx = state->next_leaf;
    if (idx == 1 << params->tree_height) {
        return 1;
    }

    // only copy layer and tree address parts
    memcpy(ots_addr, addr, 12);
    // type = ots
    set_type(ots_addr, 0);
    memcpy(ltree_addr, addr, 12);
    set_type(ltree_addr, 1);
    memcpy(node_addr, addr, 12);
    set_type(node_addr, 2);

    set_ots_addr(ots_addr, idx);
    set_ltree_addr(ltree_addr, idx);

    gen_leaf_wots(params, state->stack+state->stackoffset*params->n, sk_seed, pub_seed, ltree_addr, ots_addr);

    state->stacklevels[state->stackoffset] = 0;
    state->stackoffset++;
    if (params->tree_height - params->bds_k > 0 && idx == 3) {
        memcpy(state->treehash[0].node, state->stack+state->stackoffset*params->n, params->n);
    }
    while (state->stackoffset>1 && state->stacklevels[state->stackoffset-1] == state->stacklevels[state->stackoffset-2]) {
        nodeh = state->stacklevels[state->stackoffset-1];
        if (idx >> nodeh == 1) {
            memcpy(state->auth + nodeh*params->n, state->stack+(state->stackoffset-1)*params->n, params->n);
        }
        else {
            if (nodeh < params->tree_height - params->bds_k && idx >> nodeh == 3) {
                memcpy(state->treehash[nodeh].node, state->stack+(state->stackoffset-1)*params->n, params->n);
            }
            else if (nodeh >= params->tree_height - params->bds_k) {
                memcpy(state->retain + ((1 << (params->tree_height - 1 - nodeh)) + nodeh - params->tree_height + (((idx >> nodeh) - 3) >> 1)) * params->n, state->stack+(state->stackoffset-1)*params->n, params->n);
            }
        }
        set_tree_height(node_addr, state->stacklevels[state->stackoffset-1]);
        set_tree_index(node_addr, (idx >> (state->stacklevels[state->stackoffset-1]+1)));
        hash_h(params, state->stack+(state->stackoffset-2)*params->n, state->stack+(state->stackoffset-2)*params->n, pub_seed, node_addr);

        state->stacklevels[state->stackoffset-2]++;
        state->stackoffset--;
    }
    state->next_leaf++;
    return 0;
}

/**
 * Returns the auth path for node leaf_idx and computes the auth path for the
 * next leaf node, using the algorithm described by Buchmann, Dahmen and Szydlo
 * in "Post Quantum Cryptography", Springer 2009.
 */
static void bds_round(const xmss_params *params,
                      bds_state *state, const unsigned long leaf_idx,
                      const unsigned char *sk_seed,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned int i;
    unsigned int tau = params->tree_height;
    unsigned int startidx;
    unsigned int offset, rowidx;
    unsigned char buf[2 * params->n];

    uint32_t ots_addr[8];
    uint32_t ltree_addr[8];
    uint32_t node_addr[8];
    // only copy layer and tree address parts
    memcpy(ots_addr, addr, 12);
    // type = ots
    set_type(ots_addr, 0);
    memcpy(ltree_addr, addr, 12);
    set_type(ltree_addr, 1);
    memcpy(node_addr, addr, 12);
    set_type(node_addr, 2);

    for (i = 0; i < params->tree_height; i++) {
        if (! ((leaf_idx >> i) & 1)) {
            tau = i;
            break;
        }
    }

    if (tau > 0) {
        memcpy(buf, state->auth + (tau-1) * params->n, params->n);
        // we need to do this before refreshing state->keep to prevent overwriting
        memcpy(buf + params->n, state->keep + ((tau-1) >> 1) * params->n, params->n);
    }
    if (!((leaf_idx >> (tau + 1)) & 1) && (tau < params->tree_height - 1)) {
        memcpy(state->keep + (tau >> 1)*params->n, state->auth + tau*params->n, params->n);
    }
    if (tau == 0) {
        set_ltree_addr(ltree_addr, leaf_idx);
        set_ots_addr(ots_addr, leaf_idx);
        gen_leaf_wots(params, state->auth, sk_seed, pub_seed, ltree_addr, ots_addr);
    }
    else {
        set_tree_height(node_addr, (tau-1));
        set_tree_index(node_addr, leaf_idx >> tau);
        hash_h(params, state->auth + tau * params->n, buf, pub_seed, node_addr);
        for (i = 0; i < tau; i++) {
            if (i < params->tree_height - params->bds_k) {
                memcpy(state->auth + i * params->n, state->treehash[i].node, params->n);
            }
            else {
                offset = (1 << (params->tree_height - 1 - i)) + i - params->tree_height;
                rowidx = ((leaf_idx >> i) - 1) >> 1;
                memcpy(state->auth + i * params->n, state->retain + (offset + rowidx) * params->n, params->n);
            }
        }

        for (i = 0; i < ((tau < params->tree_height - params->bds_k) ? tau : (params->tree_height - params->bds_k)); i++) {
            startidx = leaf_idx + 1 + 3 * (1 << i);
            if (startidx < 1U << params->tree_height) {
                state->treehash[i].h = i;
                state->treehash[i].next_idx = startidx;
                state->treehash[i].completed = 0;
                state->treehash[i].stackusage = 0;
            }
        }
    }
}

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmss_core_keypair(const xmss_params *params,
                      unsigned char *pk, unsigned char *sk, bds_state *state)
{
    uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    // Set idx = 0
    sk[0] = 0;
    sk[1] = 0;
    sk[2] = 0;
    sk[3] = 0;
    // Init SK_SEED (n byte), SK_PRF (n byte), and PUB_SEED (n byte)
    randombytes(sk + params->index_len, 3*params->n);
    // Copy PUB_SEED to public key
    memcpy(pk + params->n, sk + params->index_len + 2*params->n, params->n);

    // Compute root
    treehash_init(params, pk, params->tree_height, 0, state, sk + params->index_len, sk + params->index_len + 2*params->n, addr);
    // copy root o sk
    memcpy(sk + params->index_len + 3*params->n, pk, params->n);
    return 0;
}

/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmss_core_sign(const xmss_params *params,
                   unsigned char *sk, bds_state *state,
                   unsigned char *sm, unsigned long long *smlen,
                   const unsigned char *m, unsigned long long mlen)
{
    uint16_t i = 0;

    // Extract SK
    unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
    unsigned char sk_seed[params->n];
    memcpy(sk_seed, sk + params->index_len, params->n);
    unsigned char sk_prf[params->n];
    memcpy(sk_prf, sk + params->index_len + params->n, params->n);
    unsigned char pub_seed[params->n];
    memcpy(pub_seed, sk + params->index_len + 2*params->n, params->n);

    // index as 32 bytes string
    unsigned char idx_bytes_32[32];
    ull_to_bytes(idx_bytes_32, idx, 32);

    unsigned char hash_key[3*params->n];

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
    ull_to_bytes(hash_key+2*params->n, idx, params->n);
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
    for (i = 0; i < params->n; i++) {
        sm[i] = R[i];
    }

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

    // the auth path was already computed during the previous round
    memcpy(sm, state->auth, params->tree_height*params->n);

    if (idx < (1U << params->tree_height) - 1) {
        bds_round(params, state, idx, sk_seed, pub_seed, ots_addr);
        bds_treehash_update(params, state, (params->tree_height - params->bds_k) >> 1, sk_seed, pub_seed, ots_addr);
    }

    sm += params->tree_height*params->n;
    *smlen += params->tree_height*params->n;

    memcpy(sm, m, mlen);
    *smlen += mlen;

    return 0;
}

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssmt_core_keypair(const xmss_params *params,
                        unsigned char *pk, unsigned char *sk,
                        bds_state *states, unsigned char *wots_sigs)
{
    unsigned char ots_seed[params->n];
    uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    unsigned int i;

    // Set idx = 0
    for (i = 0; i < params->index_len; i++) {
        sk[i] = 0;
    }
    // Init SK_SEED (params->n byte), SK_PRF (params->n byte), and PUB_SEED (params->n byte)
    randombytes(sk+params->index_len, 3*params->n);
    // Copy PUB_SEED to public key
    memcpy(pk+params->n, sk+params->index_len+2*params->n, params->n);

    // Start with the bottom-most layer
    set_layer_addr(addr, 0);
    // Set up state and compute wots signatures for all but topmost tree root
    for (i = 0; i < params->d - 1; i++) {
        // Compute seed for OTS key pair
        treehash_init(params, pk, params->tree_height, 0, states + i, sk+params->index_len, pk+params->n, addr);
        set_layer_addr(addr, (i+1));
        get_seed(params, ots_seed, sk + params->index_len, addr);
        wots_sign(params, wots_sigs + i*params->wots_keysize, pk, ots_seed, pk+params->n, addr);
    }
    // Address now points to the single tree on layer d-1
    treehash_init(params, pk, params->tree_height, 0, states + i, sk+params->index_len, pk+params->n, addr);
    memcpy(sk + params->index_len + 3*params->n, pk, params->n);
    return 0;
}

/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmssmt_core_sign(const xmss_params *params,
                     unsigned char *sk,
                     bds_state *states, unsigned char *wots_sigs,
                     unsigned char *sm, unsigned long long *smlen,
                     const unsigned char *m, unsigned long long mlen)
{
    uint64_t idx_tree;
    uint32_t idx_leaf;
    uint64_t i, j;
    int needswap_upto = -1;
    unsigned int updates;

    unsigned char sk_seed[params->n];
    unsigned char sk_prf[params->n];
    unsigned char pub_seed[params->n];
    // Init working params
    unsigned char R[params->n];
    unsigned char msg_h[params->n];
    unsigned char hash_key[3*params->n];
    unsigned char ots_seed[params->n];
    uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char idx_bytes_32[32];
    bds_state tmp;

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
    ull_to_bytes(idx_bytes_32, idx, 32);
    prf(params, R, idx_bytes_32, sk_prf, params->n);
    // Generate hash key (R || root || idx)
    memcpy(hash_key, R, params->n);
    memcpy(hash_key+params->n, sk+params->index_len+3*params->n, params->n);
    ull_to_bytes(hash_key+2*params->n, idx, params->n);

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

    memcpy(sm, states[0].auth, params->tree_height*params->n);
    sm += params->tree_height*params->n;
    *smlen += params->tree_height*params->n;

    // prepare signature of remaining layers
    for (i = 1; i < params->d; i++) {
        // put WOTS signature in place
        memcpy(sm, wots_sigs + (i-1)*params->wots_keysize, params->wots_keysize);

        sm += params->wots_keysize;
        *smlen += params->wots_keysize;

        // put AUTH nodes in place
        memcpy(sm, states[i].auth, params->tree_height*params->n);
        sm += params->tree_height*params->n;
        *smlen += params->tree_height*params->n;
    }

    updates = (params->tree_height - params->bds_k) >> 1;

    set_tree_addr(addr, (idx_tree + 1));
    // mandatory update for NEXT_0 (does not count towards h-k/2) if NEXT_0 exists
    if ((1 + idx_tree) * (1 << params->tree_height) + idx_leaf < (1ULL << params->full_height)) {
        bds_state_update(params, &states[params->d], sk_seed, pub_seed, addr);
    }

    for (i = 0; i < params->d; i++) {
        // check if we're not at the end of a tree
        if (! (((idx + 1) & ((1ULL << ((i+1)*params->tree_height)) - 1)) == 0)) {
            idx_leaf = (idx >> (params->tree_height * i)) & ((1 << params->tree_height)-1);
            idx_tree = (idx >> (params->tree_height * (i+1)));
            set_layer_addr(addr, i);
            set_tree_addr(addr, idx_tree);
            if (i == (unsigned int) (needswap_upto + 1)) {
                bds_round(params, &states[i], idx_leaf, sk_seed, pub_seed, addr);
            }
            updates = bds_treehash_update(params, &states[i], updates, sk_seed, pub_seed, addr);
            set_tree_addr(addr, (idx_tree + 1));
            // if a NEXT-tree exists for this level;
            if ((1 + idx_tree) * (1 << params->tree_height) + idx_leaf < (1ULL << (params->full_height - params->tree_height * i))) {
                if (i > 0 && updates > 0 && states[params->d + i].next_leaf < (1ULL << params->full_height)) {
                    bds_state_update(params, &states[params->d + i], sk_seed, pub_seed, addr);
                    updates--;
                }
            }
        }
        else if (idx < (1ULL << params->full_height) - 1) {
            memcpy(&tmp, states+params->d + i, sizeof(bds_state));
            memcpy(states+params->d + i, states + i, sizeof(bds_state));
            memcpy(states + i, &tmp, sizeof(bds_state));

            set_layer_addr(ots_addr, (i+1));
            set_tree_addr(ots_addr, ((idx + 1) >> ((i+2) * params->tree_height)));
            set_ots_addr(ots_addr, (((idx >> ((i+1) * params->tree_height)) + 1) & ((1 << params->tree_height)-1)));

            get_seed(params, ots_seed, sk+params->index_len, ots_addr);
            wots_sign(params, wots_sigs + i*params->wots_keysize, states[i].stack, ots_seed, pub_seed, ots_addr);

            states[params->d + i].stackoffset = 0;
            states[params->d + i].next_leaf = 0;

            updates--; // WOTS-signing counts as one update
            needswap_upto = i;
            for (j = 0; j < params->tree_height-params->bds_k; j++) {
                states[i].treehash[j].completed = 1;
            }
        }
    }

    memcpy(sm, m, mlen);
    *smlen += mlen;

    return 0;
}
