/*
xmss_commons.c 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include "xmss_commons.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "wots.h"
#include "hash.h"
#include "hash_address.h"
#include "params.h"

void to_byte(unsigned char *out, unsigned long long in, uint32_t bytes)
{
  int32_t i;
  for (i = bytes-1; i >= 0; i--) {
    out[i] = in & 0xff;
    in = in >> 8;
  }
}

/**
 * Computes the leaf at a given address. First generates the WOTS key pair, then computes leaf using l_tree. As this happens position independent, we only require that addr encodes the right ltree-address.
 */
void gen_leaf_wots(unsigned char *leaf, const unsigned char *sk_seed, const unsigned char *pub_seed, uint32_t ltree_addr[8], uint32_t ots_addr[8])
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
void get_seed(unsigned char *seed, const unsigned char *sk_seed, uint32_t addr[8])
{
  unsigned char bytes[32];
  // Make sure that chain addr, hash addr, and key bit are 0!
  setChainADRS(addr, 0);
  setHashADRS(addr, 0);
  setKeyAndMask(addr, 0);
  // Generate pseudorandom value
  addr_to_byte(bytes, addr);
  prf(seed, bytes, sk_seed, XMSS_N);
}

/**
 * Computes a leaf from a WOTS public key using an L-tree.
 */
void l_tree(unsigned char *leaf, unsigned char *wots_pk, const unsigned char *pub_seed, uint32_t addr[8])
{
  unsigned int l = XMSS_WOTS_LEN;
  uint32_t i = 0;
  uint32_t height = 0;
  uint32_t bound;

  //ADRS.setTreeHeight(0);
  setTreeHeight(addr, height);

  while (l > 1) {
     bound = l >> 1; //floor(l / 2);
     for (i = 0; i < bound; i++) {
       //ADRS.setTreeIndex(i);
       setTreeIndex(addr, i);
       //wots_pk[i] = RAND_HASH(pk[2i], pk[2i + 1], SEED, ADRS);
       hash_h(wots_pk+i*XMSS_N, wots_pk+i*2*XMSS_N, pub_seed, addr);
     }
     //if ( l % 2 == 1 ) {
     if (l & 1) {
       //pk[floor(l / 2) + 1] = pk[l];
       memcpy(wots_pk+(l>>1)*XMSS_N, wots_pk+(l-1)*XMSS_N, XMSS_N);
       //l = ceil(l / 2);
       l=(l>>1)+1;
     }
     else {
       //l = ceil(l / 2);
       l=(l>>1);
     }
     //ADRS.setTreeHeight(ADRS.getTreeHeight() + 1);
     height++;
     setTreeHeight(addr, height);
   }
   //return pk[0];
   memcpy(leaf, wots_pk, XMSS_N);
}

/**
 * Computes a root node given a leaf and an authapth
 */
static void validate_authpath(unsigned char *root, const unsigned char *leaf, unsigned long leafidx, const unsigned char *authpath, const unsigned char *pub_seed, uint32_t addr[8])
{
  uint32_t i, j;
  unsigned char buffer[2*XMSS_N];

  // If leafidx is odd (last bit = 1), current path element is a right child and authpath has to go to the left.
  // Otherwise, it is the other way around
  if (leafidx & 1) {
    for (j = 0; j < XMSS_N; j++)
      buffer[XMSS_N+j] = leaf[j];
    for (j = 0; j < XMSS_N; j++)
      buffer[j] = authpath[j];
  }
  else {
    for (j = 0; j < XMSS_N; j++)
      buffer[j] = leaf[j];
    for (j = 0; j < XMSS_N; j++)
      buffer[XMSS_N+j] = authpath[j];
  }
  authpath += XMSS_N;

  for (i = 0; i < XMSS_TREEHEIGHT-1; i++) {
    setTreeHeight(addr, i);
    leafidx >>= 1;
    setTreeIndex(addr, leafidx);
    if (leafidx&1) {
      hash_h(buffer+XMSS_N, buffer, pub_seed, addr);
      for (j = 0; j < XMSS_N; j++)
        buffer[j] = authpath[j];
    }
    else {
      hash_h(buffer, buffer, pub_seed, addr);
      for (j = 0; j < XMSS_N; j++)
        buffer[j+XMSS_N] = authpath[j];
    }
    authpath += XMSS_N;
  }
  setTreeHeight(addr, (XMSS_TREEHEIGHT-1));
  leafidx >>= 1;
  setTreeIndex(addr, leafidx);
  hash_h(root, buffer, pub_seed, addr);
}

/**
 * Verifies a given message signature pair under a given public key.
 */
int xmss_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
  unsigned long long i, m_len;
  unsigned long idx=0;
  unsigned char wots_pk[XMSS_WOTS_KEYSIZE];
  unsigned char pkhash[XMSS_N];
  unsigned char root[XMSS_N];
  unsigned char msg_h[XMSS_N];
  unsigned char hash_key[3*XMSS_N];

  unsigned char pub_seed[XMSS_N];
  memcpy(pub_seed, pk+XMSS_N, XMSS_N);

  // Init addresses
  uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t ltree_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t node_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  setType(ots_addr, 0);
  setType(ltree_addr, 1);
  setType(node_addr, 2);

  // Extract index
  idx = ((unsigned long)sm[0] << 24) | ((unsigned long)sm[1] << 16) | ((unsigned long)sm[2] << 8) | sm[3];

  // Generate hash key (R || root || idx)
  memcpy(hash_key, sm+4,XMSS_N);
  memcpy(hash_key+XMSS_N, pk, XMSS_N);
  to_byte(hash_key+2*XMSS_N, idx, XMSS_N);

  sm += (XMSS_N+4);
  smlen -= (XMSS_N+4);


  // hash message
  unsigned long long tmp_sig_len = XMSS_WOTS_KEYSIZE+XMSS_TREEHEIGHT*XMSS_N;
  m_len = smlen - tmp_sig_len;
  h_msg(msg_h, sm + tmp_sig_len, m_len, hash_key, 3*XMSS_N);

  //-----------------------
  // Verify signature
  //-----------------------

  // Prepare Address
  setOTSADRS(ots_addr, idx);
  // Check WOTS signature
  wots_pkFromSig(wots_pk, sm, msg_h, pub_seed, ots_addr);

  sm += XMSS_WOTS_KEYSIZE;
  smlen -= XMSS_WOTS_KEYSIZE;

  // Compute Ltree
  setLtreeADRS(ltree_addr, idx);
  l_tree(pkhash, wots_pk, pub_seed, ltree_addr);

  // Compute root
  validate_authpath(root, pkhash, idx, sm, pub_seed, node_addr);

  sm += XMSS_TREEHEIGHT*XMSS_N;
  smlen -= XMSS_TREEHEIGHT*XMSS_N;

  for (i = 0; i < XMSS_N; i++)
    if (root[i] != pk[i])
      goto fail;

  *mlen = smlen;
  for (i = 0; i < *mlen; i++)
    m[i] = sm[i];

  return 0;


fail:
  *mlen = smlen;
  for (i = 0; i < *mlen; i++)
    m[i] = 0;
  *mlen = -1;
  return -1;
}

/**
 * Verifies a given message signature pair under a given public key.
 */
int xmssmt_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
  uint64_t idx_tree;
  uint32_t idx_leaf;

  unsigned long long i, m_len;
  unsigned long long idx=0;
  unsigned char wots_pk[XMSS_WOTS_KEYSIZE];
  unsigned char pkhash[XMSS_N];
  unsigned char root[XMSS_N];
  unsigned char msg_h[XMSS_N];
  unsigned char hash_key[3*XMSS_N];

  unsigned char pub_seed[XMSS_N];
  memcpy(pub_seed, pk+XMSS_N, XMSS_N);

  // Init addresses
  uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t ltree_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t node_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  // Extract index
  for (i = 0; i < XMSS_INDEX_LEN; i++) {
    idx |= ((unsigned long long)sm[i]) << (8*(XMSS_INDEX_LEN - 1 - i));
  }
  sm += XMSS_INDEX_LEN;
  smlen -= XMSS_INDEX_LEN;

  // Generate hash key (R || root || idx)
  memcpy(hash_key, sm,XMSS_N);
  memcpy(hash_key+XMSS_N, pk, XMSS_N);
  to_byte(hash_key+2*XMSS_N, idx, XMSS_N);

  sm += XMSS_N;
  smlen -= XMSS_N;

  // hash message
  unsigned long long tmp_sig_len = (XMSS_D * XMSS_WOTS_KEYSIZE) + (XMSS_FULLHEIGHT * XMSS_N);
  m_len = smlen - tmp_sig_len;
  h_msg(msg_h, sm + tmp_sig_len, m_len, hash_key, 3*XMSS_N);

  //-----------------------
  // Verify signature
  //-----------------------

  // Prepare Address
  idx_tree = idx >> XMSS_TREEHEIGHT;
  idx_leaf = (idx & ((1 << XMSS_TREEHEIGHT)-1));
  setLayerADRS(ots_addr, 0);
  setTreeADRS(ots_addr, idx_tree);
  setType(ots_addr, 0);

  memcpy(ltree_addr, ots_addr, 12);
  setType(ltree_addr, 1);

  memcpy(node_addr, ltree_addr, 12);
  setType(node_addr, 2);

  setOTSADRS(ots_addr, idx_leaf);

  // Check WOTS signature
  wots_pkFromSig(wots_pk, sm, msg_h, pub_seed, ots_addr);

  sm += XMSS_WOTS_KEYSIZE;
  smlen -= XMSS_WOTS_KEYSIZE;

  // Compute Ltree
  setLtreeADRS(ltree_addr, idx_leaf);
  l_tree(pkhash, wots_pk, pub_seed, ltree_addr);

  // Compute root
  validate_authpath(root, pkhash, idx_leaf, sm, pub_seed, node_addr);

  sm += XMSS_TREEHEIGHT*XMSS_N;
  smlen -= XMSS_TREEHEIGHT*XMSS_N;

  for (i = 1; i < XMSS_D; i++) {
    // Prepare Address
    idx_leaf = (idx_tree & ((1 << XMSS_TREEHEIGHT)-1));
    idx_tree = idx_tree >> XMSS_TREEHEIGHT;

    setLayerADRS(ots_addr, i);
    setTreeADRS(ots_addr, idx_tree);
    setType(ots_addr, 0);

    memcpy(ltree_addr, ots_addr, 12);
    setType(ltree_addr, 1);

    memcpy(node_addr, ltree_addr, 12);
    setType(node_addr, 2);

    setOTSADRS(ots_addr, idx_leaf);

    // Check WOTS signature
    wots_pkFromSig(wots_pk, sm, root, pub_seed, ots_addr);

    sm += XMSS_WOTS_KEYSIZE;
    smlen -= XMSS_WOTS_KEYSIZE;

    // Compute Ltree
    setLtreeADRS(ltree_addr, idx_leaf);
    l_tree(pkhash, wots_pk, pub_seed, ltree_addr);

    // Compute root
    validate_authpath(root, pkhash, idx_leaf, sm, pub_seed, node_addr);

    sm += XMSS_TREEHEIGHT*XMSS_N;
    smlen -= XMSS_TREEHEIGHT*XMSS_N;

  }

  for (i = 0; i < XMSS_N; i++)
    if (root[i] != pk[i])
      goto fail;

  *mlen = smlen;
  for (i = 0; i < *mlen; i++)
    m[i] = sm[i];

  return 0;


fail:
  *mlen = smlen;
  for (i = 0; i < *mlen; i++)
    m[i] = 0;
  *mlen = -1;
  return -1;
}
