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
    int ret = 0;

    ret |= XMSS_STR_TO_OID(&oid, XMSS_OID);
    if (ret)
    {
        printf("Did not recognize %s!\n", XMSS_OID);
        return OQS_ERROR;
    }

    ret |= XMSS_PARSE_OID(&params, oid);
    if (ret)
    {
        printf("Could not parse OID for %s!\n", XMSS_OID);
        return OQS_ERROR;
    }

    ret |= XMSS_KEYPAIR(pk, sk, oid);
    if (ret)
    {
        printf("Error generating keypair %d\n", ret);
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen, unsigned char *sk)
{
    int ret = XMSS_SIGN(sk, sm, smlen, m, mlen);
    if (ret)
    {
        printf("Error generating signature %d\n", ret);
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
    int ret = XMSS_SIGN_OPEN(m, mlen, sm, smlen, pk);
    if (ret)
    {
        printf("Error verifying signature %d\n", ret);
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
