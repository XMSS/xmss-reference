/*
xmss.h version 20160722
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

/**
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmss_keypair(unsigned char *pk, unsigned char *sk);
/**
 * Signs a message.
 * Returns 
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 * 
 */
int xmss_sign(unsigned char *sk, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen);
/**
 * Verifies a given message signature pair under a given public key.
 * 
 * Note: msg and msglen are pure outputs which carry the message in case verification succeeds. The (input) message is assumed to be within sig_msg which has the form (sig||msg). 
 */
int xmss_sign_open(unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk);

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssmt_keypair(unsigned char *pk, unsigned char *sk);
/**
 * Signs a message.
 * Returns 
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 * 
 */
int xmssmt_sign(unsigned char *sk, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen);
/**
 * Verifies a given message signature pair under a given public key.
 */
int xmssmt_sign_open(unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk);
#endif

