/*
xmss.c version 20160217
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

// For testing
#include "stdio.h"


/**
 * Used for pseudorandom keygeneration,
 * generates the seed for the WOTS keypair at address addr
 *
 * takes n byte sk_seed and returns n byte seed using 32 byte address addr.
 */
static void get_seed(unsigned char *seed, const unsigned char *sk_seed, int n, uint32_t addr[8])
{
  // Make sure that chain addr, hash addr, and key bit are 0!
  setChainADRS(addr,0);
  setHashADRS(addr,0);
  setKeyAndMask(addr,0);
  // Generate pseudorandom value
  prf(seed, (unsigned char*) addr, sk_seed, n);
}

/**
 * Initialize xmss params struct
 * parameter names are the same as in the draft
 */
void xmss_set_params(xmss_params *params, int n, int h, int w)
{
  params->h = h;
  params->n = n;
  wots_params wots_par;
  wots_set_params(&wots_par, n, w);
  params->wots_par = wots_par;
}

/**
 * Initialize xmssmt_params struct
 * parameter names are the same as in the draft
 *
 * Especially h is the total tree height, i.e. the XMSS trees have height h/d
 */
void xmssmt_set_params(xmssmt_params *params, int n, int h, int d, int w)
{
  if (h % d) {
    fprintf(stderr, "d must devide h without remainder!\n");
    return;
  }
  params->h = h;
  params->d = d;
  params->n = n;
  params->index_len = (h + 7) / 8;
  xmss_params xmss_par;
  xmss_set_params(&xmss_par, n, (h/d), w);
  params->xmss_par = xmss_par;
}

/**
 * Computes a leaf from a WOTS public key using an L-tree.
 */
static void l_tree(unsigned char *leaf, unsigned char *wots_pk, const xmss_params *params, const unsigned char *pub_seed, uint32_t addr[8])
{
  unsigned int l = params->wots_par.len;
  unsigned int n = params->n;
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
       hash_h(wots_pk+i*n, wots_pk+i*2*n, pub_seed, addr, n);
     }
     //if ( l % 2 == 1 ) {
     if (l & 1) {
       //pk[floor(l / 2) + 1] = pk[l];
       memcpy(wots_pk+(l>>1)*n, wots_pk+(l-1)*n, n);
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
   memcpy(leaf, wots_pk, n);
}

/**
 * Computes the leaf at a given address. First generates the WOTS key pair, then computes leaf using l_tree. As this happens position independent, we only require that addr encodes the right ltree-address.
 */
static void gen_leaf_wots(unsigned char *leaf, const unsigned char *sk_seed, const xmss_params *params, const unsigned char *pub_seed, uint32_t ltree_addr[8], uint32_t ots_addr[8])
{
  unsigned char seed[params->n];
  unsigned char pk[params->wots_par.keysize];

  get_seed(seed, sk_seed, params->n, ots_addr);
  wots_pkgen(pk, seed, &(params->wots_par), pub_seed, ots_addr);

  l_tree(leaf, pk, params, pub_seed, ltree_addr);
}

/**
 * Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
 * Currently only used for key generation.
 *
 */
static void treehash(unsigned char *node, uint16_t height, uint32_t index, const unsigned char *sk_seed, const xmss_params *params, const unsigned char *pub_seed, const uint32_t addr[8])
{

  uint32_t idx = index;
  uint16_t n = params->n;
  // use three different addresses because at this point we use all three formats in parallel
  uint32_t ots_addr[8];
  uint32_t ltree_addr[8];
  uint32_t  node_addr[8];
  // only copy layer and tree address parts
  memcpy(ots_addr, addr, 12);
  // type = ots
  setType(ots_addr, 0);
  memcpy(ltree_addr, addr, 12);
  setType(ltree_addr, 1);
  memcpy(node_addr, addr, 12);
  setType(node_addr, 2);

  uint32_t lastnode, i;
  unsigned char stack[(height+1)*n];
  uint16_t stacklevels[height+1];
  unsigned int stackoffset=0;

  lastnode = idx+(1 << height);

  for (; idx < lastnode; idx++) {
    setLtreeADRS(ltree_addr, idx);
    setOTSADRS(ots_addr, idx);
    gen_leaf_wots(stack+stackoffset*n, sk_seed, params, pub_seed, ltree_addr, ots_addr);
    stacklevels[stackoffset] = 0;
    stackoffset++;
    while (stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2]) {
      setTreeHeight(node_addr, stacklevels[stackoffset-1]);
      setTreeIndex(node_addr, (idx >> (stacklevels[stackoffset-1]+1)));
      hash_h(stack+(stackoffset-2)*n, stack+(stackoffset-2)*n, pub_seed,
          node_addr, n);
      stacklevels[stackoffset-2]++;
      stackoffset--;
    }
  }
  for (i=0; i < n; i++)
    node[i] = stack[i];
}

/**
 * Computes a root node given a leaf and an authapth
 */
static void validate_authpath(unsigned char *root, const unsigned char *leaf, unsigned long leafidx, const unsigned char *authpath, const xmss_params *params, const unsigned char *pub_seed, uint32_t addr[8])
{
  unsigned int n = params->n;

  uint32_t i, j;
  unsigned char buffer[2*n];

  // If leafidx is odd (last bit = 1), current path element is a right child and authpath has to go to the left.
  // Otherwise, it is the other way around
  if (leafidx & 1) {
    for (j = 0; j < n; j++)
      buffer[n+j] = leaf[j];
    for (j = 0; j < n; j++)
      buffer[j] = authpath[j];
  }
  else {
    for (j = 0; j < n; j++)
      buffer[j] = leaf[j];
    for (j = 0; j < n; j++)
      buffer[n+j] = authpath[j];
  }
  authpath += n;

  for (i=0; i < params->h-1; i++) {
    setTreeHeight(addr, i);
    leafidx >>= 1;
    setTreeIndex(addr, leafidx);
    if (leafidx&1) {
      hash_h(buffer+n, buffer, pub_seed, addr, n);
      for (j = 0; j < n; j++)
        buffer[j] = authpath[j];
    }
    else {
      hash_h(buffer, buffer, pub_seed, addr, n);
      for (j = 0; j < n; j++)
        buffer[j+n] = authpath[j];
    }
    authpath += n;
  }
  setTreeHeight(addr, (params->h-1));
  leafidx >>= 1;
  setTreeIndex(addr, leafidx);
  hash_h(root, buffer, pub_seed, addr, n);
}

/**
 * Computes the authpath and the root. This method is using a lot of space as we build the whole tree and then select the authpath nodes.
 * For more efficient algorithms see e.g. the chapter on hash-based signatures in Bernstein, Buchmann, Dahmen. "Post-quantum Cryptography", Springer 2009.
 * It returns the authpath in "authpath" with the node on level 0 at index 0.
 */
static void compute_authpath_wots(unsigned char *root, unsigned char *authpath, unsigned long leaf_idx, const unsigned char *sk_seed, const xmss_params *params, unsigned char *pub_seed, uint32_t addr[8])
{
  uint32_t i, j, level;
  uint32_t n = params->n;
  uint32_t h = params->h;

  unsigned char tree[2*(1<<h)*n];

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
  for (i = 0; i < (1U << h); i++) {
    setLtreeADRS(ltree_addr, i);
    setOTSADRS(ots_addr, i);
    gen_leaf_wots(tree+((1<<h)*n + i*n), sk_seed, params, pub_seed, ltree_addr, ots_addr);
  }


  level = 0;
  // Compute tree:
  // Outer loop: For each inner layer
  for (i = (1<<h); i > 1; i>>=1) {
    setTreeHeight(node_addr, level);
    // Inner loop: for each pair of sibling nodes
    for (j = 0; j < i; j+=2) {
      setTreeIndex(node_addr, j>>1);
      hash_h(tree + (i>>1)*n + (j>>1) * n, tree + i*n + j*n, pub_seed, node_addr, n);
    }
    level++;
  }

  // copy authpath
  for (i=0; i < h; i++)
    memcpy(authpath + i*n, tree + ((1<<h)>>i)*n + ((leaf_idx >> i) ^ 1) * n, n);

  // copy root
  memcpy(root, tree+n, n);
}


/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmss_keypair(unsigned char *pk, unsigned char *sk, xmss_params *params)
{
  unsigned int n = params->n;
  // Set idx = 0
  sk[0] = 0;
  sk[1] = 0;
  sk[2] = 0;
  sk[3] = 0;
  // Init SK_SEED (n byte), SK_PRF (n byte), and PUB_SEED (n byte)
  randombytes(sk+4, 3*n);
  // Copy PUB_SEED to public key
  memcpy(pk+n, sk+4+2*n, n);

  uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  // Compute root
  treehash(pk, params->h, 0, sk+4, params, sk+4+2*n, addr);
  // copy root to sk
  memcpy(sk+4+3*n, pk, n);
  return 0;
}

/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmss_sign(unsigned char *sk, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen, const xmss_params *params)
{
  uint16_t n = params->n;
  uint16_t i = 0;

  // Extract SK
  uint32_t idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
  unsigned char sk_seed[n];
  memcpy(sk_seed, sk+4, n);
  unsigned char sk_prf[n];
  memcpy(sk_prf, sk+4+n, n);
  unsigned char pub_seed[n];
  memcpy(pub_seed, sk+4+2*n, n);
  
  // index as 32 bytes string
  unsigned char idx_bytes_32[32];
  to_byte(idx_bytes_32, idx, 32);
  
  
  unsigned char hash_key[3*n];
  
  // Update SK
  sk[0] = ((idx + 1) >> 24) & 255;
  sk[1] = ((idx + 1) >> 16) & 255;
  sk[2] = ((idx + 1) >> 8) & 255;
  sk[3] = (idx + 1) & 255;
  // -- Secret key for this non-forward-secure version is now updated.
  // -- A productive implementation should use a file handle instead and write the updated secret key at this point!

  // Init working params
  unsigned char R[n];
  unsigned char msg_h[n];
  unsigned char root[n];
  unsigned char ots_seed[n];
  uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  // ---------------------------------
  // Message Hashing
  // ---------------------------------

  // Message Hash:
  // First compute pseudorandom value
  prf(R, idx_bytes_32, sk_prf, n);
  // Generate hash key (R || root || idx)
  memcpy(hash_key, R, n);
  memcpy(hash_key+n, sk+4+3*n, n);
  to_byte(hash_key+2*n, idx, n);
  // Then use it for message digest
  h_msg(msg_h, msg, msglen, hash_key, 3*n, n);

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
  for (i = 0; i < n; i++)
    sig_msg[i] = R[i];

  sig_msg += n;
  *sig_msg_len += n;

  // ----------------------------------
  // Now we start to "really sign"
  // ----------------------------------

  // Prepare Address
  setType(ots_addr, 0);
  setOTSADRS(ots_addr, idx);

  // Compute seed for OTS key pair
  get_seed(ots_seed, sk_seed, n, ots_addr);

  // Compute WOTS signature
  wots_sign(sig_msg, msg_h, ots_seed, &(params->wots_par), pub_seed, ots_addr);

  sig_msg += params->wots_par.keysize;
  *sig_msg_len += params->wots_par.keysize;

  compute_authpath_wots(root, sig_msg, idx, sk_seed, params, pub_seed, ots_addr);
  sig_msg += params->h*n;
  *sig_msg_len += params->h*n;

  //Whipe secret elements?
  //zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

  memcpy(sig_msg, msg, msglen);
  *sig_msg_len += msglen;

  return 0;
}

/**
 * Verifies a given message signature pair under a given public key.
 */
int xmss_sign_open(unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk, const xmss_params *params)
{
  uint16_t n = params->n;
  
  unsigned long long i, m_len;
  unsigned long idx=0;
  unsigned char wots_pk[params->wots_par.keysize];
  unsigned char pkhash[n];
  unsigned char root[n];
  unsigned char msg_h[n];
  unsigned char hash_key[3*n];

  unsigned char pub_seed[n];
  memcpy(pub_seed, pk+n, n);

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
  memcpy(hash_key, sig_msg+4,n);
  memcpy(hash_key+n, pk, n);
  to_byte(hash_key+2*n, idx, n);
  
  sig_msg += (n+4);
  sig_msg_len -= (n+4);
  

  // hash message 
  unsigned long long tmp_sig_len = params->wots_par.keysize+params->h*n;
  m_len = sig_msg_len - tmp_sig_len;
  h_msg(msg_h, sig_msg + tmp_sig_len, m_len, hash_key, 3*n, n);

  //-----------------------
  // Verify signature
  //-----------------------

  // Prepare Address
  setOTSADRS(ots_addr, idx);
  // Check WOTS signature
  wots_pkFromSig(wots_pk, sig_msg, msg_h, &(params->wots_par), pub_seed, ots_addr);

  sig_msg += params->wots_par.keysize;
  sig_msg_len -= params->wots_par.keysize;

  // Compute Ltree
  setLtreeADRS(ltree_addr, idx);
  l_tree(pkhash, wots_pk, params, pub_seed, ltree_addr);

  // Compute root
  validate_authpath(root, pkhash, idx, sig_msg, params, pub_seed, node_addr);

  sig_msg += params->h*n;
  sig_msg_len -= params->h*n;

  for (i=0; i < n; i++)
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
int xmssmt_keypair(unsigned char *pk, unsigned char *sk, xmssmt_params *params)
{
  unsigned int n = params->n;
  uint16_t i;
  // Set idx = 0
  for (i = 0; i < params->index_len; i++) {
    sk[i] = 0;
  }
  // Init SK_SEED (n byte), SK_PRF (n byte), and PUB_SEED (n byte)
  randombytes(sk+params->index_len, 3*n);
  // Copy PUB_SEED to public key
  memcpy(pk+n, sk+params->index_len+2*n, n);

  // Set address to point on the single tree on layer d-1
  uint32_t addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  setLayerADRS(addr, (params->d-1));

  // Compute root
  treehash(pk, params->xmss_par.h, 0, sk+params->index_len, &(params->xmss_par), pk+n, addr);
  memcpy(sk+params->index_len+3*n, pk, n);
  return 0;
}

/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmssmt_sign(unsigned char *sk, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen, const xmssmt_params *params)
{
  unsigned int n = params->n;
  unsigned int tree_h = params->xmss_par.h;
  unsigned int idx_len = params->index_len;
  uint64_t idx_tree;
  uint32_t idx_leaf;
  uint64_t i;

  unsigned char sk_seed[n];
  unsigned char sk_prf[n];
  unsigned char pub_seed[n];
  // Init working params
  unsigned char R[n];
  unsigned char hash_key[3*n];
  unsigned char msg_h[n];
  unsigned char root[n];
  unsigned char ots_seed[n];
  uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  unsigned char idx_bytes_32[32];

  // Extract SK
  unsigned long long idx = 0;
  for (i = 0; i < idx_len; i++) {
    idx |= ((unsigned long long)sk[i]) << 8*(idx_len - 1 - i);
  }

  memcpy(sk_seed, sk+idx_len, n);
  memcpy(sk_prf, sk+idx_len+n, n);
  memcpy(pub_seed, sk+idx_len+2*n, n);

  // Update SK
  for (i = 0; i < idx_len; i++) {
    sk[i] = ((idx + 1) >> 8*(idx_len - 1 - i)) & 255;
  }
  // -- Secret key for this non-forward-secure version is now updated.
  // -- A productive implementation should use a file handle instead and write the updated secret key at this point!


  // ---------------------------------
  // Message Hashing
  // ---------------------------------

  // Message Hash:
  // First compute pseudorandom value
  to_byte(idx_bytes_32, idx, 32);
  prf(R, idx_bytes_32, sk_prf, n);
  // Generate hash key (R || root || idx)
  memcpy(hash_key, R, n);
  memcpy(hash_key+n, sk+idx_len+3*n, n);
  to_byte(hash_key+2*n, idx, n);
  
  // Then use it for message digest
  h_msg(msg_h, msg, msglen, hash_key, 3*n, n);

  // Start collecting signature
  *sig_msg_len = 0;

  // Copy index to signature
  for (i = 0; i < idx_len; i++) {
    sig_msg[i] = (idx >> 8*(idx_len - 1 - i)) & 255;
  }

  sig_msg += idx_len;
  *sig_msg_len += idx_len;

  // Copy R to signature
  for (i=0; i < n; i++)
    sig_msg[i] = R[i];

  sig_msg += n;
  *sig_msg_len += n;

  // ----------------------------------
  // Now we start to "really sign"
  // ----------------------------------

  // Handle lowest layer separately as it is slightly different...

  // Prepare Address
  setType(ots_addr, 0);
  idx_tree = idx >> tree_h;
  idx_leaf = (idx & ((1 << tree_h)-1));
  setLayerADRS(ots_addr, 0);
  setTreeADRS(ots_addr, idx_tree);
  setOTSADRS(ots_addr, idx_leaf);

  // Compute seed for OTS key pair
  get_seed(ots_seed, sk_seed, n, ots_addr);

  // Compute WOTS signature
  wots_sign(sig_msg, msg_h, ots_seed, &(params->xmss_par.wots_par), pub_seed, ots_addr);

  sig_msg += params->xmss_par.wots_par.keysize;
  *sig_msg_len += params->xmss_par.wots_par.keysize;

  compute_authpath_wots(root, sig_msg, idx_leaf, sk_seed, &(params->xmss_par), pub_seed, ots_addr);
  sig_msg += tree_h*n;
  *sig_msg_len += tree_h*n;

  // Now loop over remaining layers...
  unsigned int j;
  for (j = 1; j < params->d; j++) {
    // Prepare Address
    idx_leaf = (idx_tree & ((1 << tree_h)-1));
    idx_tree = idx_tree >> tree_h;
    setLayerADRS(ots_addr, j);
    setTreeADRS(ots_addr, idx_tree);
    setOTSADRS(ots_addr, idx_leaf);

    // Compute seed for OTS key pair
    get_seed(ots_seed, sk_seed, n, ots_addr);

    // Compute WOTS signature
    wots_sign(sig_msg, root, ots_seed, &(params->xmss_par.wots_par), pub_seed, ots_addr);

    sig_msg += params->xmss_par.wots_par.keysize;
    *sig_msg_len += params->xmss_par.wots_par.keysize;

    compute_authpath_wots(root, sig_msg, idx_leaf, sk_seed, &(params->xmss_par), pub_seed, ots_addr);
    sig_msg += tree_h*n;
    *sig_msg_len += tree_h*n;
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
int xmssmt_sign_open(unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk, const xmssmt_params *params)
{
  unsigned int n = params->n;

  unsigned int tree_h = params->xmss_par.h;
  unsigned int idx_len = params->index_len;
  uint64_t idx_tree;
  uint32_t idx_leaf;

  unsigned long long i, m_len;
  unsigned long long idx=0;
  unsigned char wots_pk[params->xmss_par.wots_par.keysize];
  unsigned char pkhash[n];
  unsigned char root[n];
  unsigned char msg_h[n];
  unsigned char hash_key[3*n];

  unsigned char pub_seed[n];
  memcpy(pub_seed, pk+n, n);

  // Init addresses
  uint32_t ots_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t ltree_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t node_addr[8] = {0, 0, 0, 0, 0, 0, 0, 0};

  // Extract index
  for (i = 0; i < idx_len; i++) {
    idx |= ((unsigned long long)sig_msg[i]) << (8*(idx_len - 1 - i));
  }
  printf("verify:: idx = %llu\n", idx);
  sig_msg += idx_len;
  sig_msg_len -= idx_len;

  // Generate hash key (R || root || idx)
  memcpy(hash_key, sig_msg,n);
  memcpy(hash_key+n, pk, n);
  to_byte(hash_key+2*n, idx, n);

  sig_msg += n;
  sig_msg_len -= n;
  
  // hash message 
  unsigned long long tmp_sig_len = (params->d * params->xmss_par.wots_par.keysize) + (params->h * n);
  m_len = sig_msg_len - tmp_sig_len;
  h_msg(msg_h, sig_msg + tmp_sig_len, m_len, hash_key, 3*n, n);


  //-----------------------
  // Verify signature
  //-----------------------

  // Prepare Address
  idx_tree = idx >> tree_h;
  idx_leaf = (idx & ((1 << tree_h)-1));
  setLayerADRS(ots_addr, 0);
  setTreeADRS(ots_addr, idx_tree);
  setType(ots_addr, 0);

  memcpy(ltree_addr, ots_addr, 12);
  setType(ltree_addr, 1);

  memcpy(node_addr, ltree_addr, 12);
  setType(node_addr, 2);
  
  setOTSADRS(ots_addr, idx_leaf);

  // Check WOTS signature
  wots_pkFromSig(wots_pk, sig_msg, msg_h, &(params->xmss_par.wots_par), pub_seed, ots_addr);

  sig_msg += params->xmss_par.wots_par.keysize;
  sig_msg_len -= params->xmss_par.wots_par.keysize;

  // Compute Ltree
  setLtreeADRS(ltree_addr, idx_leaf);
  l_tree(pkhash, wots_pk, &(params->xmss_par), pub_seed, ltree_addr);

  // Compute root
  validate_authpath(root, pkhash, idx_leaf, sig_msg, &(params->xmss_par), pub_seed, node_addr);

  sig_msg += tree_h*n;
  sig_msg_len -= tree_h*n;

  for (i = 1; i < params->d; i++) {
    // Prepare Address
    idx_leaf = (idx_tree & ((1 << tree_h)-1));
    idx_tree = idx_tree >> tree_h;

    setLayerADRS(ots_addr, i);
    setTreeADRS(ots_addr, idx_tree);
    setType(ots_addr, 0);

    memcpy(ltree_addr, ots_addr, 12);
    setType(ltree_addr, 1);

    memcpy(node_addr, ltree_addr, 12);
    setType(node_addr, 2);

    setOTSADRS(ots_addr, idx_leaf);

    // Check WOTS signature
    wots_pkFromSig(wots_pk, sig_msg, root, &(params->xmss_par.wots_par), pub_seed, ots_addr);

    sig_msg += params->xmss_par.wots_par.keysize;
    sig_msg_len -= params->xmss_par.wots_par.keysize;

    // Compute Ltree
    setLtreeADRS(ltree_addr, idx_leaf);
    l_tree(pkhash, wots_pk, &(params->xmss_par), pub_seed, ltree_addr);

    // Compute root
    validate_authpath(root, pkhash, idx_leaf, sig_msg, &(params->xmss_par), pub_seed, node_addr);

    sig_msg += tree_h*n;
    sig_msg_len -= tree_h*n;

  }

  for (i=0; i < n; i++)
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