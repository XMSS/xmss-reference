/*
hash.h version 20150811
Andreas Hülsing
Public domain.
*/

#ifndef HASH_H
#define HASH_H

int prf_m(unsigned char *out, const unsigned char *in, size_t inlen, const unsigned char *key, int keylen);
int hash_m(unsigned char *out,const unsigned char *in,unsigned long long inlen, const unsigned char *key, const int keylen, const int m);
int hash_2n_n(unsigned char *out,const unsigned char *in, const unsigned char *pub_seed, unsigned char addr[16], const int n);
int hash_n_n(unsigned char *out,const unsigned char *in, const unsigned char *pub_seed, unsigned char addr[16], const int n);

#endif
