#ifndef FIPS202_H
#define FIPS202_H

#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

void shake128(unsigned char *output, unsigned int outputByteLen, const unsigned char *input, unsigned int inputByteLen);
void shake256(unsigned char *output, unsigned int outputByteLen, const unsigned char *input, unsigned int inputByteLen);

#endif
