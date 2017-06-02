/*
xmss_fast.c version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include "xmss_fast.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "randombytes.h"
#include "wots.h"
#include "hash.h"

#include "xmss_commons.h"
#include "hash_address.h"
#include "params.h"

/**
 * Initialize BDS state struct
 * parameter names are the same as used in the description of the BDS traversal
 */
void xmss_set_bds_state(bds_state *state, unsigned char *stack, int stackoffset, unsigned char *stacklevels, unsigned char *auth, unsigned char *keep, treehash_inst *treehash, unsigned char *retain, int next_leaf)
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

static int treehash_minheight_on_stack(bds_state* state, const treehash_inst *treehash) {
  unsigned int r = XMSS_TREEHEIGHT, i;
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
static void treehash_setup(unsigned char *node, int height, int index, bds_state *state, const unsigned char *sk_seed, const unsigned char *pub_seed, const uint32_t addr[8])
{
  unsigned int idx = index;
  // use three different addresses because at this point we use all three formats in parallel
  uint32_t ots_addr[8];
  uint32_t ltree_addr[8];
  uint32_t node_addr[8];
  // only copy layer and tree address parts
  memcpy(ots_addr, addr, 12);
  // type = ots
  setType(ots_addr, 0);
  memcpy(ltree_addr, addr, 12);
  setType(ltree_addr, 1);
  memcpy(node_addr, addr, 12);
  setType(node_addr, 2);

  uint32_t lastnode, i;
  unsigned char stack[(height+1)*XMSS_N];
  unsigned int stacklevels[height+1];
  unsigned int stackoffset=0;
  unsigned int nodeh;

  lastnode = idx+(1<<height);

  for (i = 0; i < XMSS_TREEHEIGHT-XMSS_BDS_K; i++) {
    state->treehash[i].h = i;
    state->treehash[i].completed = 1;
    state->treehash[i].stackusage = 0;
  }

  i = 0;
  for (; idx < lastnode; idx++) {
    setLtreeADRS(ltree_addr, idx);
    setOTSADRS(ots_addr, idx);
    gen_leaf_wots(stack+stackoffset*XMSS_N, sk_seed, pub_seed, ltree_addr, ots_addr);
    stacklevels[stackoffset] = 0;
    stackoffset++;
    if (XMSS_TREEHEIGHT - XMSS_BDS_K > 0 && i == 3) {
      memcpy(state->treehash[0].node, stack+stackoffset*XMSS_N, XMSS_N);
    }
    while (stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2])
    {
      nodeh = stacklevels[stackoffset-1];
      if (i >> nodeh == 1) {
        memcpy(state->auth + nodeh*XMSS_N, stack+(stackoffset-1)*XMSS_N, XMSS_N);
      }
      else {
        if (nodeh < XMSS_TREEHEIGHT - XMSS_BDS_K && i >> nodeh == 3) {
          memcpy(state->treehash[nodeh].node, stack+(stackoffset-1)*XMSS_N, XMSS_N);
        }
        else if (nodeh >= XMSS_TREEHEIGHT - XMSS_BDS_K) {
          memcpy(state->retain + ((1 << (XMSS_TREEHEIGHT - 1 - nodeh)) + nodeh - XMSS_TREEHEIGHT + (((i >> nodeh) - 3) >> 1)) * XMSS_N, stack+(stackoffset-1)*XMSS_N, XMSS_N);
        }
      }
      setTreeHeight(node_addr, stacklevels[stackoffset-1]);
      setTreeIndex(node_addr, (idx >> (stacklevels[stackoffset-1]+1)));
      hash_h(stack+(stackoffset-2)*XMSS_N, stack+(stackoffset-2)*XMSS_N, pub_seed,
          node_addr, XMSS_N);
      stacklevels[stackoffset-2]++;
      stackoffset--;
    }
    i++;
  }

  for (i = 0; i < XMSS_N; i++)
    node[i] = stack[i];
}

static void treehash_update(treehash_inst *treehash, bds_state *state, const unsigned char *sk_seed, const unsigned char *pub_seed, const uint32_t addr[8]) {
  uint32_t ots_addr[8];
  uint32_t ltree_addr[8];
  uint32_t node_addr[8];
  // only copy layer and tree address parts
  memcpy(ots_addr, addr, 12);
  // type = ots
  setType(ots_addr, 0);
  memcpy(ltree_addr, addr, 12);
  setType(ltree_addr, 1);
  memcpy(node_addr, addr, 12);
  setType(node_addr, 2);

  setLtreeADRS(ltree_addr, treehash->next_idx);
  setOTSADRS(ots_addr, treehash->next_idx);

  unsigned char nodebuffer[2 * XMSS_N];
  unsigned int nodeheight = 0;
  gen_leaf_wots(nodebuffer, sk_seed, pub_seed, ltree_addr, ots_addr);
  while (treehash->stackusage > 0 && state->stacklevels[state->stackoffset-1] == nodeheight) {
    memcpy(nodebuffer + XMSS_N, nodebuffer, XMSS_N);
    memcpy(nodebuffer, state->stack + (state->stackoffset-1)*XMSS_N, XMSS_N);
    setTreeHeight(node_addr, nodeheight);
    setTreeIndex(node_addr, (treehash->next_idx >> (nodeheight+1)));
    hash_h(nodebuffer, nodebuffer, pub_seed, node_addr, XMSS_N);
    nodeheight++;
    treehash->stackusage--;
    state->stackoffset--;
  }
  if (nodeheight == treehash->h) { // this also implies stackusage == 0
    memcpy(treehash->node, nodebuffer, XMSS_N);
    treehash->completed = 1;
  }
  else {
    memcpy(state->stack + state->stackoffset*XMSS_N, nodebuffer, XMSS_N);
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
static char bds_treehash_update(bds_state *state, unsigned int updates, const unsigned char *sk_seed, unsigned char *pub_seed, const uint32_t addr[8]) {
  uint32_t i, j;
  unsigned int level, l_min, low;
  unsigned int used = 0;

  for (j = 0; j < updates; j++) {
    l_min = XMSS_TREEHEIGHT;
    level = XMSS_TREEHEIGHT - XMSS_BDS_K;
    for (i = 0; i < XMSS_TREEHEIGHT - XMSS_BDS_K; i++) {
      if (state->treehash[i].completed) {
        low = XMSS_TREEHEIGHT;
      }
      else if (state->treehash[i].stackusage == 0) {
        low = i;
      }
      else {
        low = treehash_minheight_on_stack(state, &(state->treehash[i]));
      }
      if (low < l_min) {
        level = i;
        l_min = low;
      }
    }
    if (level == XMSS_TREEHEIGHT - XMSS_BDS_K) {
      break;
    }
    treehash_update(&(state->treehash[level]), state, sk_seed, pub_seed, addr);
    used++;
  }
  return updates - used;
}

/**
 * Updates the state (typically NEXT_i) by adding a leaf and updating the stack
 * Returns 1 if all leaf nodes have already been processed
 **/
static char bds_state_update(bds_state *state, const unsigned char *sk_seed, unsigned char *pub_seed, const uint32_t addr[8]) {
  uint32_t ltree_addr[8];
  uint32_t node_addr[8];
  uint32_t ots_addr[8];

  int nodeh;
  int idx = state->next_leaf;
  if (idx == 1 << XMSS_TREEHEIGHT) {
    return 1;
  }

  // only copy layer and tree address parts
  memcpy(ots_addr, addr, 12);
  // type = ots
  setType(ots_addr, 0);
  memcpy(ltree_addr, addr, 12);
  setType(ltree_addr, 1);
  memcpy(node_addr, addr, 12);
  setType(node_addr, 2);
  
  setOTSADRS(ots_addr, idx);
  setLtreeADRS(ltree_addr, idx);

  gen_leaf_wots(state->stack+state->stackoffset*XMSS_N, sk_seed, pub_seed, ltree_addr, ots_addr);

  state->stacklevels[state->stackoffset] = 0;
  state->stackoffset++;
  if (XMSS_TREEHEIGHT - XMSS_BDS_K > 0 && idx == 3) {
    memcpy(state->treehash[0].node, state->stack+state->stackoffset*XMSS_N, XMSS_N);
  }
  while (state->stackoffset>1 && state->stacklevels[state->stackoffset-1] == state->stacklevels[state->stackoffset-2]) {
    nodeh = state->stacklevels[state->stackoffset-1];
    if (idx >> nodeh == 1) {
      memcpy(state->auth + nodeh*XMSS_N, state->stack+(state->stackoffset-1)*XMSS_N, XMSS_N);
    }
    else {
      if (nodeh < XMSS_TREEHEIGHT - XMSS_BDS_K && idx >> nodeh == 3) {
        memcpy(state->treehash[nodeh].node, state->stack+(state->stackoffset-1)*XMSS_N, XMSS_N);
      }
      else if (nodeh >= XMSS_TREEHEIGHT - XMSS_BDS_K) {
        memcpy(state->retain + ((1 << (XMSS_TREEHEIGHT - 1 - nodeh)) + nodeh - XMSS_TREEHEIGHT + (((idx >> nodeh) - 3) >> 1)) * XMSS_N, state->stack+(state->stackoffset-1)*XMSS_N, XMSS_N);
      }
    }
    setTreeHeight(node_addr, state->stacklevels[state->stackoffset-1]);
    setTreeIndex(node_addr, (idx >> (state->stacklevels[state->stackoffset-1]+1)));
    hash_h(state->stack+(state->stackoffset-2)*XMSS_N, state->stack+(state->stackoffset-2)*XMSS_N, pub_seed, node_addr, XMSS_N);

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
static void bds_round(bds_state *state, const unsigned long leaf_idx, const unsigned char *sk_seed, unsigned char *pub_seed, uint32_t addr[8])
{
  unsigned int i;
  unsigned int tau = XMSS_TREEHEIGHT;
  unsigned int startidx;
  unsigned int offset, rowidx;
  unsigned char buf[2 * XMSS_N];

  uint32_t ots_addr[8];
  uint32_t ltree_addr[8];
  uint32_t node_addr[8];
  // only copy layer and tree address parts
  memcpy(ots_addr, addr, 12);
  // type = ots
  setType(ots_addr, 0);
  memcpy(ltree_addr, addr, 12);
  setType(ltree_addr, 1);
  memcpy(node_addr, addr, 12);
  setType(node_addr, 2);

  for (i = 0; i < XMSS_TREEHEIGHT; i++) {
    if (! ((leaf_idx >> i) & 1)) {
      tau = i;
      break;
    }
  }

  if (tau > 0) {
    memcpy(buf,     state->auth + (tau-1) * XMSS_N, XMSS_N);
    // we need to do this before refreshing state->keep to prevent overwriting
    memcpy(buf + XMSS_N, state->keep + ((tau-1) >> 1) * XMSS_N, XMSS_N);
  }
  if (!((leaf_idx >> (tau + 1)) & 1) && (tau < XMSS_TREEHEIGHT - 1)) {
    memcpy(state->keep + (tau >> 1)*XMSS_N, state->auth + tau*XMSS_N, XMSS_N);
  }
  if (tau == 0) {
    setLtreeADRS(ltree_addr, leaf_idx);
    setOTSADRS(ots_addr, leaf_idx);
    gen_leaf_wots(state->auth, sk_seed, pub_seed, ltree_addr, ots_addr);
  }
  else {
    setTreeHeight(node_addr, (tau-1));
    setTreeIndex(node_addr, leaf_idx >> tau);
    hash_h(state->auth + tau * XMSS_N, buf, pub_seed, node_addr, XMSS_N);
    for (i = 0; i < tau; i++) {
      if (i < XMSS_TREEHEIGHT - XMSS_BDS_K) {
        memcpy(state->auth + i * XMSS_N, state->treehash[i].node, XMSS_N);
      }
      else {
        offset = (1 << (XMSS_TREEHEIGHT - 1 - i)) + i - XMSS_TREEHEIGHT;
        rowidx = ((leaf_idx >> i) - 1) >> 1;
        memcpy(state->auth + i * XMSS_N, state->retain + (offset + rowidx) * XMSS_N, XMSS_N);
      }
    }

    for (i = 0; i < ((tau < XMSS_TREEHEIGHT - XMSS_BDS_K) ? tau : (XMSS_TREEHEIGHT - XMSS_BDS_K)); i++) {
      startidx = leaf_idx + 1 + 3 * (1 << i);
      if (startidx < 1U << XMSS_TREEHEIGHT) {
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
int xmss_keypair(unsigned char *pk, unsigned char *sk, bds_state *state)
{
  // Set idx = 0
  sk[0] = 0;
  sk[1] = 0;
  sk[2] = 0;
  sk[3] = 0;
  // Init SK_SEED (n byte), SK_PRF (n byte), and PUB_SEED (n byte)
  randombytes(sk+4, 3*XMSS_N);
  // Copy PUB_SEED to public key
  memcpy(pk+XMSS_N, sk+4+2*XMSS_N, XMSS_N);

  uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  // Compute root
  treehash_setup(pk, XMSS_TREEHEIGHT, 0, state, sk+4, sk+4+2*XMSS_N, addr);
  // copy root to sk
  memcpy(sk+4+3*XMSS_N, pk, XMSS_N);
  return 0;
}

/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmss_sign(unsigned char *sk, bds_state *state, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen)
{
  uint16_t i = 0;

  // Extract SK
  unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
  unsigned char sk_seed[XMSS_N];
  memcpy(sk_seed, sk+4, XMSS_N);
  unsigned char sk_prf[XMSS_N];
  memcpy(sk_prf, sk+4+XMSS_N, XMSS_N);
  unsigned char pub_seed[XMSS_N];
  memcpy(pub_seed, sk+4+2*XMSS_N, XMSS_N);
  
  // index as 32 bytes string
  unsigned char idx_bytes_32[32];
  to_byte(idx_bytes_32, idx, 32);
  
  unsigned char hash_key[3*XMSS_N];
  
  // Update SK
  sk[0] = ((idx + 1) >> 24) & 255;
  sk[1] = ((idx + 1) >> 16) & 255;
  sk[2] = ((idx + 1) >> 8) & 255;
  sk[3] = (idx + 1) & 255;
  // -- Secret key for this non-forward-secure version is now updated.
  // -- A productive implementation should use a file handle instead and write the updated secret key at this point!

  // Init working params
  unsigned char R[XMSS_N];
  unsigned char msg_h[XMSS_N];
  unsigned char ots_seed[XMSS_N];
  uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  // ---------------------------------
  // Message Hashing
  // ---------------------------------

  // Message Hash:
  // First compute pseudorandom value
  prf(R, idx_bytes_32, sk_prf, XMSS_N);
  // Generate hash key (R || root || idx)
  memcpy(hash_key, R, XMSS_N);
  memcpy(hash_key+XMSS_N, sk+4+3*XMSS_N, XMSS_N);
  to_byte(hash_key+2*XMSS_N, idx, XMSS_N);
  // Then use it for message digest
  h_msg(msg_h, msg, msglen, hash_key, 3*XMSS_N, XMSS_N);

  // Start collecting signature
  *sig_msg_len = 0;

  // Copy index to signature
  sig_msg[0] = (idx >> 24) & 255;
  sig_msg[1] = (idx >> 16) & 255;
  sig_msg[2] = (idx >> 8) & 255;
  sig_msg[3] = idx & 255;

  sig_msg += 4;
  *sig_msg_len += 4;

  // Copy R to signature
  for (i = 0; i < XMSS_N; i++)
    sig_msg[i] = R[i];

  sig_msg += XMSS_N;
  *sig_msg_len += XMSS_N;

  // ----------------------------------
  // Now we start to "really sign"
  // ----------------------------------

  // Prepare Address
  setType(ots_addr, 0);
  setOTSADRS(ots_addr, idx);

  // Compute seed for OTS key pair
  get_seed(ots_seed, sk_seed, ots_addr);

  // Compute WOTS signature
  wots_sign(sig_msg, msg_h, ots_seed, pub_seed, ots_addr);

  sig_msg += XMSS_WOTS_KEYSIZE;
  *sig_msg_len += XMSS_WOTS_KEYSIZE;

  // the auth path was already computed during the previous round
  memcpy(sig_msg, state->auth, XMSS_TREEHEIGHT*XMSS_N);

  if (idx < (1U << XMSS_TREEHEIGHT) - 1) {
    bds_round(state, idx, sk_seed, pub_seed, ots_addr);
    bds_treehash_update(state, (XMSS_TREEHEIGHT - XMSS_BDS_K) >> 1, sk_seed, pub_seed, ots_addr);
  }

  sig_msg += XMSS_TREEHEIGHT*XMSS_N;
  *sig_msg_len += XMSS_TREEHEIGHT*XMSS_N;

  memcpy(sig_msg, msg, msglen);
  *sig_msg_len += msglen;

  return 0;
}

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssmt_keypair(unsigned char *pk, unsigned char *sk, bds_state *states, unsigned char *wots_sigs)
{
  unsigned char ots_seed[XMSS_N];
  int i;
  // Set idx = 0
  for (i = 0; i < XMSS_INDEX_LEN; i++) {
    sk[i] = 0;
  }
  // Init SK_SEED (XMSS_N byte), SK_PRF (XMSS_N byte), and PUB_SEED (XMSS_N byte)
  randombytes(sk+XMSS_INDEX_LEN, 3*XMSS_N);
  // Copy PUB_SEED to public key
  memcpy(pk+XMSS_N, sk+XMSS_INDEX_LEN+2*XMSS_N, XMSS_N);

  uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  // Start with the bottom-most layer
  setLayerADRS(addr, 0);
  // Set up state and compute wots signatures for all but topmost tree root
  for (i = 0; i < XMSS_D - 1; i++) {
    // Compute seed for OTS key pair
    treehash_setup(pk, XMSS_TREEHEIGHT, 0, states + i, sk+XMSS_INDEX_LEN, pk+XMSS_N, addr);
    setLayerADRS(addr, (i+1));
    get_seed(ots_seed, sk+XMSS_INDEX_LEN, addr);
    wots_sign(wots_sigs + i*XMSS_WOTS_KEYSIZE, pk, ots_seed, pk+XMSS_N, addr);
  }
  // Address now points to the single tree on layer d-1
  treehash_setup(pk, XMSS_TREEHEIGHT, 0, states + i, sk+XMSS_INDEX_LEN, pk+XMSS_N, addr);
  memcpy(sk+XMSS_INDEX_LEN+3*XMSS_N, pk, XMSS_N);
  return 0;
}

/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmssmt_sign(unsigned char *sk, bds_state *states, unsigned char *wots_sigs, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen)
{
  uint64_t idx_tree;
  uint32_t idx_leaf;
  uint64_t i, j;
  int needswap_upto = -1;
  unsigned int updates;

  unsigned char sk_seed[XMSS_N];
  unsigned char sk_prf[XMSS_N];
  unsigned char pub_seed[XMSS_N];
  // Init working params
  unsigned char R[XMSS_N];
  unsigned char msg_h[XMSS_N];
  unsigned char hash_key[3*XMSS_N];
  unsigned char ots_seed[XMSS_N];
  uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  unsigned char idx_bytes_32[32];
  bds_state tmp;

  // Extract SK 
  unsigned long long idx = 0;
  for (i = 0; i < XMSS_INDEX_LEN; i++) {
    idx |= ((unsigned long long)sk[i]) << 8*(XMSS_INDEX_LEN - 1 - i);
  }

  memcpy(sk_seed, sk+XMSS_INDEX_LEN, XMSS_N);
  memcpy(sk_prf, sk+XMSS_INDEX_LEN+XMSS_N, XMSS_N);
  memcpy(pub_seed, sk+XMSS_INDEX_LEN+2*XMSS_N, XMSS_N);

  // Update SK
  for (i = 0; i < XMSS_INDEX_LEN; i++) {
    sk[i] = ((idx + 1) >> 8*(XMSS_INDEX_LEN - 1 - i)) & 255;
  }
  // -- Secret key for this non-forward-secure version is now updated.
  // -- A productive implementation should use a file handle instead and write the updated secret key at this point!


  // ---------------------------------
  // Message Hashing
  // ---------------------------------

  // Message Hash:
  // First compute pseudorandom value
  to_byte(idx_bytes_32, idx, 32);
  prf(R, idx_bytes_32, sk_prf, XMSS_N);
  // Generate hash key (R || root || idx)
  memcpy(hash_key, R, XMSS_N);
  memcpy(hash_key+XMSS_N, sk+XMSS_INDEX_LEN+3*XMSS_N, XMSS_N);
  to_byte(hash_key+2*XMSS_N, idx, XMSS_N);
  
  // Then use it for message digest
  h_msg(msg_h, msg, msglen, hash_key, 3*XMSS_N, XMSS_N);

  // Start collecting signature
  *sig_msg_len = 0;

  // Copy index to signature
  for (i = 0; i < XMSS_INDEX_LEN; i++) {
    sig_msg[i] = (idx >> 8*(XMSS_INDEX_LEN - 1 - i)) & 255;
  }

  sig_msg += XMSS_INDEX_LEN;
  *sig_msg_len += XMSS_INDEX_LEN;

  // Copy R to signature
  for (i = 0; i < XMSS_N; i++)
    sig_msg[i] = R[i];

  sig_msg += XMSS_N;
  *sig_msg_len += XMSS_N;

  // ----------------------------------
  // Now we start to "really sign"
  // ----------------------------------

  // Handle lowest layer separately as it is slightly different...

  // Prepare Address
  setType(ots_addr, 0);
  idx_tree = idx >> XMSS_TREEHEIGHT;
  idx_leaf = (idx & ((1 << XMSS_TREEHEIGHT)-1));
  setLayerADRS(ots_addr, 0);
  setTreeADRS(ots_addr, idx_tree);
  setOTSADRS(ots_addr, idx_leaf);

  // Compute seed for OTS key pair
  get_seed(ots_seed, sk_seed, ots_addr);

  // Compute WOTS signature
  wots_sign(sig_msg, msg_h, ots_seed, pub_seed, ots_addr);

  sig_msg += XMSS_WOTS_KEYSIZE;
  *sig_msg_len += XMSS_WOTS_KEYSIZE;

  memcpy(sig_msg, states[0].auth, XMSS_TREEHEIGHT*XMSS_N);
  sig_msg += XMSS_TREEHEIGHT*XMSS_N;
  *sig_msg_len += XMSS_TREEHEIGHT*XMSS_N;

  // prepare signature of remaining layers
  for (i = 1; i < XMSS_D; i++) {
    // put WOTS signature in place
    memcpy(sig_msg, wots_sigs + (i-1)*XMSS_WOTS_KEYSIZE, XMSS_WOTS_KEYSIZE);

    sig_msg += XMSS_WOTS_KEYSIZE;
    *sig_msg_len += XMSS_WOTS_KEYSIZE;

    // put AUTH nodes in place
    memcpy(sig_msg, states[i].auth, XMSS_TREEHEIGHT*XMSS_N);
    sig_msg += XMSS_TREEHEIGHT*XMSS_N;
    *sig_msg_len += XMSS_TREEHEIGHT*XMSS_N;
  }

  updates = (XMSS_TREEHEIGHT - XMSS_BDS_K) >> 1;

  setTreeADRS(addr, (idx_tree + 1));
  // mandatory update for NEXT_0 (does not count towards h-k/2) if NEXT_0 exists
  if ((1 + idx_tree) * (1 << XMSS_TREEHEIGHT) + idx_leaf < (1ULL << XMSS_FULLHEIGHT)) {
    bds_state_update(&states[XMSS_D], sk_seed, pub_seed, addr);
  }

  for (i = 0; i < XMSS_D; i++) {
    // check if we're not at the end of a tree
    if (! (((idx + 1) & ((1ULL << ((i+1)*XMSS_TREEHEIGHT)) - 1)) == 0)) {
      idx_leaf = (idx >> (XMSS_TREEHEIGHT * i)) & ((1 << XMSS_TREEHEIGHT)-1);
      idx_tree = (idx >> (XMSS_TREEHEIGHT * (i+1)));
      setLayerADRS(addr, i);
      setTreeADRS(addr, idx_tree);
      if (i == (unsigned int) (needswap_upto + 1)) {
        bds_round(&states[i], idx_leaf, sk_seed, pub_seed, addr);
      }
      updates = bds_treehash_update(&states[i], updates, sk_seed, pub_seed, addr);
      setTreeADRS(addr, (idx_tree + 1));
      // if a NEXT-tree exists for this level;
      if ((1 + idx_tree) * (1 << XMSS_TREEHEIGHT) + idx_leaf < (1ULL << (XMSS_FULLHEIGHT - XMSS_TREEHEIGHT * i))) {
        if (i > 0 && updates > 0 && states[XMSS_D + i].next_leaf < (1ULL << XMSS_FULLHEIGHT)) {
          bds_state_update(&states[XMSS_D + i], sk_seed, pub_seed, addr);
          updates--;
        }
      }
    }
    else if (idx < (1ULL << XMSS_FULLHEIGHT) - 1) {
      memcpy(&tmp, states+XMSS_D + i, sizeof(bds_state));
      memcpy(states+XMSS_D + i, states + i, sizeof(bds_state));
      memcpy(states + i, &tmp, sizeof(bds_state));

      setLayerADRS(ots_addr, (i+1));
      setTreeADRS(ots_addr, ((idx + 1) >> ((i+2) * XMSS_TREEHEIGHT)));
      setOTSADRS(ots_addr, (((idx >> ((i+1) * XMSS_TREEHEIGHT)) + 1) & ((1 << XMSS_TREEHEIGHT)-1)));

      get_seed(ots_seed, sk+XMSS_INDEX_LEN, ots_addr);
      wots_sign(wots_sigs + i*XMSS_WOTS_KEYSIZE, states[i].stack, ots_seed, pub_seed, ots_addr);

      states[XMSS_D + i].stackoffset = 0;
      states[XMSS_D + i].next_leaf = 0;

      updates--; // WOTS-signing counts as one update
      needswap_upto = i;
      for (j = 0; j < XMSS_TREEHEIGHT-XMSS_BDS_K; j++) {
        states[i].treehash[j].completed = 1;
      }
    }
  }

  memcpy(sig_msg, msg, msglen);
  *sig_msg_len += msglen;

  return 0;
}
