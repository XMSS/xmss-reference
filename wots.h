/*
wots.h version 20160722
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#ifndef WOTS_H
#define WOTS_H

#include "stdint.h"

/**
 * WOTS key generation. Takes a 32byte seed for the secret key, expands it to a full WOTS secret key and computes the corresponding public key. 
 * For this it takes the seed pub_seed which is used to generate bitmasks and hash keys and the address of this WOTS key pair addr
 *
 * Places the computed public key at address pk.
 */
void wots_pkgen(unsigned char *pk, const unsigned char *sk, const unsigned char *pub_seed, uint32_t addr[8]);

/**
 * Takes a m-byte message and the 32-byte seed for the secret key to compute a signature that is placed at "sig".
 *
 */
void wots_sign(unsigned char *sig, const unsigned char *msg, const unsigned char *sk, const unsigned char *pub_seed, uint32_t addr[8]);

/**
 * Takes a WOTS signature, a m-byte message and computes a WOTS public key that it places at pk.
 *
 */
void wots_pkFromSig(unsigned char *pk, const unsigned char *sig, const unsigned char *msg, const unsigned char *pub_seed, uint32_t addr[8]);

#endif
