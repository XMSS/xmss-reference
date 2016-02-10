/*
wots.h version 20151120
Andreas Hülsing
Public domain.
*/

#ifndef WOTS_H
#define WOTS_H

/**
 * WOTS parameter set
 * 
 * Meaning as defined in draft-irtf-cfrg-xmss-hash-based-signatures-02
 */
typedef struct{
  int len_1;
  int len_2;
  int len;
  int m;
  int n;
  int w;
  int log_w;
  int keysize;
} wots_params;

/**
 * Set the WOTS parameters, 
 * only m, n, w are required as inputs,
 * len, len_1, and len_2 are computed from those.
 *
 * Assumes w is a power of 2
 */
void wots_set_params(wots_params *params, int m, int n, int w);

/**
 * WOTS key generation. Takes a 32byte seed for the secret key, expands it to a full WOTS secret key and computes the corresponding public key. 
 * For this it takes the seed pub_seed which is used to generate bitmasks and hash keys and the address of this WOTS key pair addr
 * 
 * params, must have been initialized before using wots_set params for params ! This is not done in this function
 * 
 * Places the computed public key at address pk.
 */
void wots_pkgen(unsigned char *pk, const unsigned char *sk, const wots_params *params, const unsigned char *pub_seed, unsigned char addr[16]);

/**
 * Takes a m-byte message and the 32-byte seed for the secret key to compute a signature that is placed at "sig".
 *  
 */
void wots_sign(unsigned char *sig, const unsigned char *msg, const unsigned char *sk, const wots_params *params, const unsigned char *pub_seed, unsigned char addr[16]);

/**
 * Takes a WOTS signature, a m-byte message and computes a WOTS public key that it places at pk.
 * 
 */
void wots_pkFromSig(unsigned char *pk, const unsigned char *sig, const unsigned char *msg, const wots_params *params, const unsigned char *pub_seed, unsigned char addr[16]);

#endif
