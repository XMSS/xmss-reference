#include <oqs/common.h>
#include <stdio.h>
#include "api.h"
#include "params.h"
#include "nist_params.h"
#include "xmss.h"

/*************************************************
 * Name:        crypto_sign_keypair
 *
 * Description: Generates public and private key.
 *
 * Arguments:   - uint8_t *pk: pointer to output public key (allocated
 *                             array of LMS_CRYPTO_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key (allocated
 *                             array of LMS_CRYPTO_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success), -1 otherwise
 **************************************************/
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
    xmss_params params;
    uint32_t oid;
    int ret = 0;

    ret |= XMSS_STR_TO_OID(&oid, XMSS_OID);
    if (ret)
    {
#if DEBUG
        printf("Did not recognize %s!\n", XMSS_OID);
#endif
        return OQS_ERROR;
    }

    ret |= XMSS_PARSE_OID(&params, oid);
    if (ret)
    {
#if DEBUG
        printf("Could not parse OID for %s!\n", XMSS_OID);
#endif
        return OQS_ERROR;
    }

    ret |= XMSS_KEYPAIR(pk, sk, oid);
    if (ret)
    {
#if DEBUG
        printf("Error generating keypair %d\n", ret);
#endif
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

/*************************************************
 * Name:        crypto_sign
 *
 * Description: Computes signature.
 *
 * Arguments:   - uint8_t *sm:   pointer to output signature (of length CRYPTO_BYTES)
 *              - uint8_t *m:    pointer to message to be signed
 *              - uint8_t *sk:   pointer to bit-packed secret key
 *              - unsigned long long *smlen: pointer to output length of signature
 *              - unsigned long long mlen:   length of message
 *
 * Returns 0 (success), -1 otherwise
 **************************************************/
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen, unsigned char *sk)
{
    int ret = XMSS_SIGN(sk, sm, smlen, m, mlen);
    if (ret)
    {
#if DEBUG
        printf("Error generating signature %d\n", ret);
#endif
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

/*************************************************
 * Name:        crypto_sign_open
 *
 * Description: Verify signed message.
 *
 * Arguments:   - uint8_t *m: pointer to output message (allocated
 *                            array with smlen bytes), can be equal to sm
 *              - const uint8_t *sm: pointer to signed message
 *              - const uint8_t *pk: pointer to bit-packed public key
 *              - unsigned long long *mlen: pointer to output length of message
 *              - unsigned long long smlen: length of signed message
 *
 * Returns 0 if signed message could be verified correctly and -1 otherwise
 **************************************************/
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
    if (XMSS_SIGN_OPEN(m, mlen, sm, smlen, pk))
    {
#if DEBUG
        printf("Error verifying signature %d\n", ret);
#endif
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

/*************************************************
 * Name:        crypto_remain_signatures
 *
 * Description: Return number of signature left
 *
 * Arguments:   - unsigned long long *remain: remaining signatures
 *              - unsigned long long *max: maximum number of possibile signature
 *              - const uint8_t *sk: pointer to bit-packed private key
 *
 * Returns 0 (sucess), -1 otherwise
 **************************************************/
int crypto_remain_signatures(unsigned long long *remain,
                             unsigned long long *max, const unsigned char *sk)
{
    if (XMSS_REMAIN_SIG(remain, max, sk))
    {
#if DEBUG
        printf("Error counting remaining signatures\n");
#endif
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}
