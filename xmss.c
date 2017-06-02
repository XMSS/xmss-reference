/*
xmss.c version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include "xmss.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "randombytes.h"
#include "wots.h"
#include "hash.h"
//#include "prg.h"
#include "xmss_commons.h"
#include "hash_address.h"
#include "params.h"

// For testing
#include "stdio.h"

/**
 * Used for pseudorandom keygeneration,
 * generates the seed for the WOTS keypair at address addr
 *
 * takes XMSS_N byte sk_seed and returns XMSS_N byte seed using 32 byte address addr.
 */
static void get_seed(unsigned char *seed, const unsigned char *sk_seed, uint32_t addr[8])
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
static void l_tree(unsigned char *leaf, unsigned char *wots_pk, const unsigned char *pub_seed, uint32_t addr[8])
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
       hash_h(wots_pk+i*XMSS_N, wots_pk+i*2*XMSS_N, pub_seed, addr, XMSS_N);
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
 * Computes the leaf at a given address. First generates the WOTS key pair, then computes leaf using l_tree. As this happens position independent, we only require that addr encodes the right ltree-address.
 */
static void gen_leaf_wots(unsigned char *leaf, const unsigned char *sk_seed, const unsigned char *pub_seed, uint32_t ltree_addr[8], uint32_t ots_addr[8])
{
  unsigned char seed[XMSS_N];
  unsigned char pk[XMSS_WOTS_KEYSIZE];

  get_seed(seed, sk_seed, ots_addr);
  wots_pkgen(pk, seed, pub_seed, ots_addr);

  l_tree(leaf, pk, pub_seed, ltree_addr);
}

/**
 * Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
 * Currently only used for key generation.
 *
 */
static void treehash(unsigned char *node, uint16_t height, uint32_t index, const unsigned char *sk_seed, const unsigned char *pub_seed, const uint32_t addr[8])
{
  uint32_t idx = index;
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
  uint16_t stacklevels[height+1];
  unsigned int stackoffset=0;

  lastnode = idx+(1 << height);

  for (; idx < lastnode; idx++) {
    setLtreeADRS(ltree_addr, idx);
    setOTSADRS(ots_addr, idx);
    gen_leaf_wots(stack+stackoffset*XMSS_N, sk_seed, pub_seed, ltree_addr, ots_addr);
    stacklevels[stackoffset] = 0;
    stackoffset++;
    while (stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2]) {
      setTreeHeight(node_addr, stacklevels[stackoffset-1]);
      setTreeIndex(node_addr, (idx >> (stacklevels[stackoffset-1]+1)));
      hash_h(stack+(stackoffset-2)*XMSS_N, stack+(stackoffset-2)*XMSS_N, pub_seed,
          node_addr, XMSS_N);
      stacklevels[stackoffset-2]++;
      stackoffset--;
    }
  }
  for (i=0; i < XMSS_N; i++)
    node[i] = stack[i];
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

  for (i=0; i < XMSS_TREEHEIGHT-1; i++) {
    setTreeHeight(addr, i);
    leafidx >>= 1;
    setTreeIndex(addr, leafidx);
    if (leafidx&1) {
      hash_h(buffer+XMSS_N, buffer, pub_seed, addr, XMSS_N);
      for (j = 0; j < XMSS_N; j++)
        buffer[j] = authpath[j];
    }
    else {
      hash_h(buffer, buffer, pub_seed, addr, XMSS_N);
      for (j = 0; j < XMSS_N; j++)
        buffer[j+XMSS_N] = authpath[j];
    }
    authpath += XMSS_N;
  }
  setTreeHeight(addr, (XMSS_TREEHEIGHT-1));
  leafidx >>= 1;
  setTreeIndex(addr, leafidx);
  hash_h(root, buffer, pub_seed, addr, XMSS_N);
}

/**
 * Computes the authpath and the root. This method is using a lot of space as we build the whole tree and then select the authpath nodes.
 * For more efficient algorithms see e.g. the chapter on hash-based signatures in Bernstein, Buchmann, Dahmen. "Post-quantum Cryptography", Springer 2009.
 * It returns the authpath in "authpath" with the node on level 0 at index 0.
 */
static void compute_authpath_wots(unsigned char *root, unsigned char *authpath, unsigned long leaf_idx, const unsigned char *sk_seed, unsigned char *pub_seed, uint32_t addr[8])
{
  uint32_t i, j, level;

  unsigned char tree[2*(1<<XMSS_TREEHEIGHT)*XMSS_N];

  uint32_t ots_addr[8];
  uint32_t ltree_addr[8];
  uint32_t node_addr[8];

  memcpy(ots_addr, addr, 12);
  setType(ots_addr, 0);
  memcpy(ltree_addr, addr, 12);
  setType(ltree_addr, 1);
  memcpy(node_addr, addr, 12);
  setType(node_addr, 2);

  // Compute all leaves
  for (i = 0; i < (1U << XMSS_TREEHEIGHT); i++) {
    setLtreeADRS(ltree_addr, i);
    setOTSADRS(ots_addr, i);
    gen_leaf_wots(tree+((1<<XMSS_TREEHEIGHT)*XMSS_N + i*XMSS_N), sk_seed, pub_seed, ltree_addr, ots_addr);
  }


  level = 0;
  // Compute tree:
  // Outer loop: For each inner layer
  for (i = (1<<XMSS_TREEHEIGHT); i > 1; i>>=1) {
    setTreeHeight(node_addr, level);
    // Inner loop: for each pair of sibling nodes
    for (j = 0; j < i; j+=2) {
      setTreeIndex(node_addr, j>>1);
      hash_h(tree + (i>>1)*XMSS_N + (j>>1) * XMSS_N, tree + i*XMSS_N + j*XMSS_N, pub_seed, node_addr, XMSS_N);
    }
    level++;
  }

  // copy authpath
  for (i=0; i < XMSS_TREEHEIGHT; i++)
    memcpy(authpath + i*XMSS_N, tree + ((1<<XMSS_TREEHEIGHT)>>i)*XMSS_N + ((leaf_idx >> i) ^ 1) * XMSS_N, XMSS_N);

  // copy root
  memcpy(root, tree+XMSS_N, XMSS_N);
}


/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmss_keypair(unsigned char *pk, unsigned char *sk)
{
  // Set idx = 0
  sk[0] = 0;
  sk[1] = 0;
  sk[2] = 0;
  sk[3] = 0;
  // Init SK_SEED (XMSS_N byte), SK_PRF (XMSS_N byte), and PUB_SEED (XMSS_N byte)
  randombytes(sk+4, 3*XMSS_N);
  // Copy PUB_SEED to public key
  memcpy(pk+XMSS_N, sk+4+2*XMSS_N, XMSS_N);

  uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  // Compute root
  treehash(pk, XMSS_TREEHEIGHT, 0, sk+4, sk+4+2*XMSS_N, addr);
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
int xmss_sign(unsigned char *sk, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen)
{
  uint16_t i = 0;

  // Extract SK
  uint32_t idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
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
  unsigned char root[XMSS_N];
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

  compute_authpath_wots(root, sig_msg, idx, sk_seed, pub_seed, ots_addr);
  sig_msg += XMSS_TREEHEIGHT*XMSS_N;
  *sig_msg_len += XMSS_TREEHEIGHT*XMSS_N;

  //Whipe secret elements?
  //zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

  memcpy(sig_msg, msg, msglen);
  *sig_msg_len += msglen;

  return 0;
}

/**
 * Verifies a given message signature pair under a given public key.
 */
int xmss_sign_open(unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk)
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
  idx = ((unsigned long)sig_msg[0] << 24) | ((unsigned long)sig_msg[1] << 16) | ((unsigned long)sig_msg[2] << 8) | sig_msg[3];
  printf("verify:: idx = %lu\n", idx);
  
  // Generate hash key (R || root || idx)
  memcpy(hash_key, sig_msg+4,XMSS_N);
  memcpy(hash_key+XMSS_N, pk, XMSS_N);
  to_byte(hash_key+2*XMSS_N, idx, XMSS_N);
  
  sig_msg += (XMSS_N+4);
  sig_msg_len -= (XMSS_N+4);
  

  // hash message 
  unsigned long long tmp_sig_len = XMSS_WOTS_KEYSIZE+XMSS_TREEHEIGHT*XMSS_N;
  m_len = sig_msg_len - tmp_sig_len;
  h_msg(msg_h, sig_msg + tmp_sig_len, m_len, hash_key, 3*XMSS_N, XMSS_N);
  
  //-----------------------
  // Verify signature
  //-----------------------

  // Prepare Address
  setOTSADRS(ots_addr, idx);
  // Check WOTS signature
  wots_pkFromSig(wots_pk, sig_msg, msg_h, pub_seed, ots_addr);

  sig_msg += XMSS_WOTS_KEYSIZE;
  sig_msg_len -= XMSS_WOTS_KEYSIZE;

  // Compute Ltree
  setLtreeADRS(ltree_addr, idx);
  l_tree(pkhash, wots_pk, pub_seed, ltree_addr);

  // Compute root
  validate_authpath(root, pkhash, idx, sig_msg, pub_seed, node_addr);

  sig_msg += XMSS_TREEHEIGHT*XMSS_N;
  sig_msg_len -= XMSS_TREEHEIGHT*XMSS_N;

  for (i=0; i < XMSS_N; i++)
    if (root[i] != pk[i])
      goto fail;

  *msglen = sig_msg_len;
  for (i=0; i < *msglen; i++)
    msg[i] = sig_msg[i];

  return 0;


fail:
  *msglen = sig_msg_len;
  for (i=0; i < *msglen; i++)
    msg[i] = 0;
  *msglen = -1;
  return -1;
}

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssmt_keypair(unsigned char *pk, unsigned char *sk)
{
  uint16_t i;
  // Set idx = 0
  for (i = 0; i < XMSS_INDEX_LEN; i++) {
    sk[i] = 0;
  }
  // Init SK_SEED (XMSS_N byte), SK_PRF (XMSS_N byte), and PUB_SEED (XMSS_N byte)
  randombytes(sk+XMSS_INDEX_LEN, 3*XMSS_N);
  // Copy PUB_SEED to public key
  memcpy(pk+XMSS_N, sk+XMSS_INDEX_LEN+2*XMSS_N, XMSS_N);

  // Set address to point on the single tree on layer d-1
  uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  setLayerADRS(addr, (XMSS_D-1));

  // Compute root
  treehash(pk, XMSS_TREEHEIGHT, 0, sk+XMSS_INDEX_LEN, pk+XMSS_N, addr);
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
int xmssmt_sign(unsigned char *sk, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen)
{
  uint64_t idx_tree;
  uint32_t idx_leaf;
  uint64_t i;

  unsigned char sk_seed[XMSS_N];
  unsigned char sk_prf[XMSS_N];
  unsigned char pub_seed[XMSS_N];
  // Init working params
  unsigned char R[XMSS_N];
  unsigned char hash_key[3*XMSS_N];
  unsigned char msg_h[XMSS_N];
  unsigned char root[XMSS_N];
  unsigned char ots_seed[XMSS_N];
  uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  unsigned char idx_bytes_32[32];

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
  for (i=0; i < XMSS_N; i++)
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

  compute_authpath_wots(root, sig_msg, idx_leaf, sk_seed, pub_seed, ots_addr);
  sig_msg += XMSS_TREEHEIGHT*XMSS_N;
  *sig_msg_len += XMSS_TREEHEIGHT*XMSS_N;

  // Now loop over remaining layers...
  unsigned int j;
  for (j = 1; j < XMSS_D; j++) {
    // Prepare Address
    idx_leaf = (idx_tree & ((1 << XMSS_TREEHEIGHT)-1));
    idx_tree = idx_tree >> XMSS_TREEHEIGHT;
    setLayerADRS(ots_addr, j);
    setTreeADRS(ots_addr, idx_tree);
    setOTSADRS(ots_addr, idx_leaf);

    // Compute seed for OTS key pair
    get_seed(ots_seed, sk_seed, ots_addr);

    // Compute WOTS signature
    wots_sign(sig_msg, root, ots_seed, pub_seed, ots_addr);

    sig_msg += XMSS_WOTS_KEYSIZE;
    *sig_msg_len += XMSS_WOTS_KEYSIZE;

    compute_authpath_wots(root, sig_msg, idx_leaf, sk_seed, pub_seed, ots_addr);
    sig_msg += XMSS_TREEHEIGHT*XMSS_N;
    *sig_msg_len += XMSS_TREEHEIGHT*XMSS_N;
  }

  //Whipe secret elements?
  //zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

  memcpy(sig_msg, msg, msglen);
  *sig_msg_len += msglen;

  return 0;
}

/**
 * Verifies a given message signature pair under a given public key.
 */
int xmssmt_sign_open(unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk)
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
    idx |= ((unsigned long long)sig_msg[i]) << (8*(XMSS_INDEX_LEN - 1 - i));
  }
  printf("verify:: idx = %llu\n", idx);
  sig_msg += XMSS_INDEX_LEN;
  sig_msg_len -= XMSS_INDEX_LEN;

  // Generate hash key (R || root || idx)
  memcpy(hash_key, sig_msg,XMSS_N);
  memcpy(hash_key+XMSS_N, pk, XMSS_N);
  to_byte(hash_key+2*XMSS_N, idx, XMSS_N);

  sig_msg += XMSS_N;
  sig_msg_len -= XMSS_N;
  
  // hash message 
  unsigned long long tmp_sig_len = (XMSS_D * XMSS_WOTS_KEYSIZE) + (XMSS_FULLHEIGHT * XMSS_N);
  m_len = sig_msg_len - tmp_sig_len;
  h_msg(msg_h, sig_msg + tmp_sig_len, m_len, hash_key, 3*XMSS_N, XMSS_N);


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
  wots_pkFromSig(wots_pk, sig_msg, msg_h, pub_seed, ots_addr);

  sig_msg += XMSS_WOTS_KEYSIZE;
  sig_msg_len -= XMSS_WOTS_KEYSIZE;

  // Compute Ltree
  setLtreeADRS(ltree_addr, idx_leaf);
  l_tree(pkhash, wots_pk, pub_seed, ltree_addr);

  // Compute root
  validate_authpath(root, pkhash, idx_leaf, sig_msg, pub_seed, node_addr);

  sig_msg += XMSS_TREEHEIGHT*XMSS_N;
  sig_msg_len -= XMSS_TREEHEIGHT*XMSS_N;

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
    wots_pkFromSig(wots_pk, sig_msg, root, pub_seed, ots_addr);

    sig_msg += XMSS_WOTS_KEYSIZE;
    sig_msg_len -= XMSS_WOTS_KEYSIZE;

    // Compute Ltree
    setLtreeADRS(ltree_addr, idx_leaf);
    l_tree(pkhash, wots_pk, pub_seed, ltree_addr);

    // Compute root
    validate_authpath(root, pkhash, idx_leaf, sig_msg, pub_seed, node_addr);

    sig_msg += XMSS_TREEHEIGHT*XMSS_N;
    sig_msg_len -= XMSS_TREEHEIGHT*XMSS_N;

  }

  for (i=0; i < XMSS_N; i++)
    if (root[i] != pk[i])
      goto fail;

  *msglen = sig_msg_len;
  for (i=0; i < *msglen; i++)
    msg[i] = sig_msg[i];

  return 0;


fail:
  *msglen = sig_msg_len;
  for (i=0; i < *msglen; i++)
    msg[i] = 0;
  *msglen = -1;
  return -1;
}