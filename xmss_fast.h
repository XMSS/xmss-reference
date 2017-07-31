/*
xmss_fast.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include "wots.h"

#ifndef XMSS_H
#define XMSS_H

typedef struct{
  unsigned int h;
  unsigned int next_idx;
  unsigned int stackusage;
  unsigned char completed;
  unsigned char *node;
} treehash_inst;

typedef struct {
  unsigned char *stack;
  unsigned int stackoffset;
  unsigned char *stacklevels;
  unsigned char *auth;
  unsigned char *keep;
  treehash_inst *treehash;
  unsigned char *retain;
  unsigned int next_leaf;
} bds_state;

/**
 * Initialize BDS state struct
 * parameter names are the same as used in the description of the BDS traversal
 */
void xmss_set_bds_state(bds_state *state, unsigned char *stack, int stackoffset, unsigned char *stacklevels, unsigned char *auth, unsigned char *keep, treehash_inst *treehash, unsigned char *retain, int next_leaf);
/**
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmss_keypair(unsigned char *pk, unsigned char *sk, bds_state *state);
/**
 * Signs a message.
 * Returns 
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 * 
 */
int xmss_sign(unsigned char *sk, bds_state *state, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg,unsigned long long msglen);
/**
 * Verifies a given message signature pair under a given public key.
 * 
 * Note: msg and msglen are pure outputs which carry the message in case verification succeeds. The (input) message is assumed to be within sig_msg which has the form (sig||msg). 
 */
int xmss_sign_open(unsigned char *msg,unsigned long long *msglen, const unsigned char *sig_msg,unsigned long long sig_msg_len, const unsigned char *pk);

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssmt_keypair(unsigned char *pk, unsigned char *sk, bds_state *states, unsigned char *wots_sigs);
/**
 * Signs a message.
 * Returns 
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 * 
 */
int xmssmt_sign(unsigned char *sk, bds_state *state, unsigned char *wots_sigs, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen);
/**
 * Verifies a given message signature pair under a given public key.
 */
int xmssmt_sign_open(unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk);
#endif

