#include <stdint.h>

#include "params_runtime.h"
#include "xmss_core.h"

/* This file provides wrapper functions that take keys that include OIDs to
identify the parameter set to be used. After setting the parameters accordingly
it falls back to the regular XMSS core functions. */

int xmss_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid)
{
    unsigned int i;

    if (xmss_parse_oid(oid)) {
        return 1;
    }
    for (i = 0; i < XMSS_OID_LEN; i++) {
        pk[i] = (oid >> (8 * i)) & 0xFF;
        /* For an implementation that uses runtime parameters, it is crucial
        that the OID is part of the secret key as well. */
        sk[i] = (oid >> (8 * i)) & 0xFF;
    }
    return xmss_core_keypair(pk + XMSS_OID_LEN, sk + XMSS_OID_LEN);
}

int xmss_sign(unsigned char *sk,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen)
{
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[i] << (i * 8);
    }
    if (xmss_parse_oid(oid)) {
        return 1;
    }
    return xmss_core_sign(sk + XMSS_OID_LEN, sm, smlen, m, mlen);
}

int xmss_sign_open(unsigned char *m, unsigned long long *mlen,
                   const unsigned char *sm, unsigned long long smlen,
                   const unsigned char *pk)
{
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= pk[i] << (i * 8);
    }
    if (xmss_parse_oid(oid)) {
        return 1;
    }
    return xmss_core_sign_open(m, mlen, sm, smlen, pk + XMSS_OID_LEN);
}

int xmssmt_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid)
{
    unsigned int i;

    if (xmssmt_parse_oid(oid)) {
        return 1;
    }
    for (i = 0; i < XMSS_OID_LEN; i++) {
        pk[i] = (oid >> (8 * i)) & 0xFF;
        sk[i] = (oid >> (8 * i)) & 0xFF;
    }
    return xmssmt_core_keypair(pk + XMSS_OID_LEN, sk + XMSS_OID_LEN);
}

int xmssmt_sign(unsigned char *sk,
                unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen)
{
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[i] << (i * 8);
    }
    if (xmssmt_parse_oid(oid)) {
        return 1;
    }
    return xmssmt_core_sign(sk + XMSS_OID_LEN, sm, smlen, m, mlen);
}

int xmssmt_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= pk[i] << (i * 8);
    }
    if (xmssmt_parse_oid(oid)) {
        return 1;
    }
    return xmssmt_core_sign_open(m, mlen, sm, smlen, pk + XMSS_OID_LEN);
}
