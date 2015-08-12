/*
prg.h version 20150811
Andreas Hülsing
Public domain.
*/

#ifndef PRG_H
#define PRG_H
#include <stdlib.h>

/**
 * Generates rlen output bytes using key_len-byte key and places them in r.
 * 
 */
void prg(unsigned char *r, unsigned long long rlen, const unsigned char *key, unsigned int key_len);

/**
 * Generates rlen output bytes using key_len-byte key and hash address addr and places them in r.
 * 
 */
void prg_with_counter(unsigned char *r, unsigned long long rlen, const unsigned char *key, unsigned int key_len, const unsigned char addr[16]);
#endif
