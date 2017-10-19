#ifndef XMSS_FIPS202_H
#define XMSS_FIPS202_H

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

void shake128(unsigned char *out, unsigned long long outlen,
              const unsigned char *in, unsigned long long inlen);

void shake256(unsigned char *out, unsigned long long outlen,
              const unsigned char *in, unsigned long long inlen);

#endif
