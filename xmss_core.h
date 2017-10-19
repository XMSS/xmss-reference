/*
xmss.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/
#ifndef XMSS_CORE_H
#define XMSS_CORE_H

#include "params.h"

/**
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmss_core_keypair(const xmss_params *params, unsigned char *pk, unsigned char *sk);
/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmss_core_sign(const xmss_params *params, unsigned char *sk, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen);
/**
 * Verifies a given message signature pair under a given public key.
 *
 * Note: msg and msglen are pure outputs which carry the message in case verification succeeds. The (input) message is assumed to be within sig_msg which has the form (sig||msg).
 */
int xmss_core_sign_open(const xmss_params *params, unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk);

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssmt_core_keypair(const xmss_params *params, unsigned char *pk, unsigned char *sk);
/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmssmt_core_sign(const xmss_params *params, unsigned char *sk, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen);
/**
 * Verifies a given message signature pair under a given public key.
 */
int xmssmt_core_sign_open(const xmss_params *params, unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk);
#endif

