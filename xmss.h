#include "wots.h"

#ifndef XMSS_H
#define XMSS_H
typedef struct{
  int level;
  unsigned long long subtree;
  int subleaf;
} leafaddr;

typedef struct{
  wots_params *wots_par;
  int n;
  int m;
  int h;
} xmss_params;

/**
 * Initializes parameter set.
 * Needed, for any of the other methods.
 */
void xmss_set_params(xmss_params *params, int m, int n, int h, int w);
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
int xmss_sign(unsigned char *sk, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg,unsigned long long msglen, const xmss_params *params, unsigned char* pk);
/**
 * Verifies a given message signature pair under a given public key.
 * 
 * Note: msg and msglen are pure outputs which carry the message in case verification succeeds. The (input) message is assumed to be within sig_msg which has the form (sig||msg). 
 */
int xmss_sign_open(unsigned char *msg,unsigned long long *msglen, const unsigned char *sig_msg,unsigned long long sig_msg_len, const unsigned char *pk, const xmss_params *params);

#endif

