#include <oqs/common.h>
#include <stdio.h>
#include "api.h"
#include "params.h"
#include "nist_params.h"
#include "xmss.h"

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    xmss_params params;
    uint32_t oid;

    if (XMSS_STR_TO_OID(&oid, XMSS_OID))
    {
        printf("Did not recognize %s!\n", XMSS_OID);
        return OQS_ERROR; 
    }
    
    if (XMSS_PARSE_OID(&params, oid))
    {
        printf("Could not parse OID for %s!\n", XMSS_OID);
        return OQS_ERROR;
    }

    if (XMSS_KEYPAIR(pk, sk, oid))
    {
        printf("Error generating keypair\n");
        return OQS_ERROR; 
    }

    return OQS_SUCCESS; 
}

int crypto_sign(unsigned char *sm, unsigned long *smlen,
                const unsigned char *m, unsigned long mlen, unsigned char *sk)
{
    if (XMSS_SIGN(sk, sm, &smlen, m, mlen))
    {
        printf("Error generating signature\n");
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

int crypto_sign_open(unsigned char *m, unsigned long *mlen,
                     const unsigned char *sm, unsigned long smlen, const unsigned char *pk)
{
    if (XMSS_SIGN_OPEN(m, mlen, sm, smlen, pk))
    {
        printf("Error verifying signature\n");
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

int crypto_remain_signatures(unsigned long long *remain,
                             unsigned long long *max, const unsigned char *sk)
{
    if (XMSS_REMAIN_SIG(remain, max, sk))
    {
        printf("Error counting remaining signatures\n");
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}
