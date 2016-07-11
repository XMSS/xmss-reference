/*
hash.h version 20160217
Andreas Hülsing
Joost Rijneveld
Public domain.
*/

#ifndef HASH_H
#define HASH_H

int prf(unsigned char *out, const unsigned char *in, const unsigned char *key, int keylen);
int h_msg(unsigned char *out,const unsigned char *in,unsigned long long inlen, const unsigned char *key, const int keylen, const int n);
int hash_h(unsigned char *out, const unsigned char *in, const unsigned char *pub_seed, uint32_t addr[8], const unsigned int n);
int hash_f(unsigned char *out, const unsigned char *in, const unsigned char *pub_seed, uint32_t addr[8], const unsigned int n);

#endif
