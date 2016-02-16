/*
xmss.h version 20160210
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#include "wots.h"

#ifndef XMSS_H
#define XMSS_H
typedef struct{
  unsigned int level;
  unsigned long long subtree;
  unsigned int subleaf;
} leafaddr;

typedef struct{
  wots_params wots_par;
  unsigned int n;
  unsigned int m;
  unsigned int h;
} xmss_params;

typedef struct{
  xmss_params xmss_par;
  unsigned int n;
  unsigned int m;
  unsigned int h;
  unsigned int d;
  unsigned int index_len;
} xmssmt_params;
/**
 * Initializes parameter set.
 * Needed, for any of the other methods.
 */
void xmss_set_params(xmss_params *params, int m, int n, int h, int w);
/**
 * Initialize xmssmt_params struct
 * parameter names are the same as in the draft
 * 
 * Especially h is the total tree height, i.e. the XMSS trees have height h/d
 */
void xmssmt_set_params(xmssmt_params *params, int m, int n, int h, int d, int w);
/**
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmss_keypair(unsigned char *pk, unsigned char *sk, xmss_params *params);
/**
 * Signs a message.
 * Returns 
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 * 
 */
int xmss_sign(unsigned char *sk, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg,unsigned long long msglen, const xmss_params *params);
/**
 * Verifies a given message signature pair under a given public key.
 * 
 * Note: msg and msglen are pure outputs which carry the message in case verification succeeds. The (input) message is assumed to be within sig_msg which has the form (sig||msg). 
 */
int xmss_sign_open(unsigned char *msg,unsigned long long *msglen, const unsigned char *sig_msg,unsigned long long sig_msg_len, const unsigned char *pk, const xmss_params *params);

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssmt_keypair(unsigned char *pk, unsigned char *sk, xmssmt_params *params);
/**
 * Signs a message.
 * Returns 
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 * 
 */
int xmssmt_sign(unsigned char *sk, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen, const xmssmt_params *params);
/**
 * Verifies a given message signature pair under a given public key.
 */
int xmssmt_sign_open(unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk, const xmssmt_params *params);
#endif

