#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"

#define MLEN 32
#define SIGNATURES 16

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
    #define XMSS_VARIANT "XMSS-SHA2_10_256"
#endif

int main()
{
    xmss_params params;
    // TODO test more different OIDs
    uint32_t oid = 0x01000001;
    int i, j;

    XMSS_PARSE_OID(&params, oid);

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *m = malloc(MLEN);
    unsigned char *sm = malloc(params.sig_bytes + MLEN);
    unsigned char *mout = malloc(params.sig_bytes + MLEN);
    unsigned long long smlen;
    unsigned long long mlen;

    randombytes(m, MLEN);

    XMSS_KEYPAIR(pk, sk, oid);

    printf("Testing %d %s signatures.. \n", SIGNATURES, XMSS_VARIANT);

    for (i = 0; i < SIGNATURES; i++) {
        printf("  - iteration #%d:\n", i);

        XMSS_SIGN(sk, sm, &smlen, m, MLEN);

        if (smlen != params.sig_bytes + MLEN) {
            printf("  X smlen incorrect [%llu != %u]!\n",
                   smlen, params.sig_bytes);
        }
        else {
            printf("    smlen as expected [%llu].\n", smlen);
        }

        /* Test if signature is valid. */
        if (XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk)) {
            printf("  X verification failed!\n");
        }
        else {
            printf("    verification succeeded.\n");
        }

        /* Test if the correct message was recovered. */
        if (mlen != MLEN) {
            printf("  X mlen incorrect [%llu != %u]!\n", mlen, MLEN);
        }
        else {
            printf("    mlen as expected [%llu].\n", mlen);
        }
        if (memcmp(m, mout, MLEN)) {
            printf("  X output message incorrect!\n");
        }
        else {
            printf("    output message as expected.\n");
        }

        /* Test if flipping bits invalidates the signature (it should). */

        /* Flip the first bit of the message. Should invalidate. */
        sm[smlen - 1] ^= 1;
        if (!XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk)) {
            printf("  X flipping a bit of m DID NOT invalidate signature!\n");
        }
        else {
            printf("    flipping a bit of m invalidates signature.\n");
        }
        sm[smlen - 1] ^= 1;

        /* Flip one bit per hash; the signature is almost entirely hashes.
           This also flips a bit in the index, which is also a useful test. */
        for (j = 0; j < (int)(smlen - MLEN); j += params.n) {
            sm[j] ^= 1;
            if (!XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk)) {
                printf("  X flipping bit %d DID NOT invalidate sig + m!\n", j);
                sm[j] ^= 1;
                break;
            }
            sm[j] ^= 1;
        }
        if (j >= (int)(smlen - MLEN)) {
            printf("    changing any signature hash invalidates signature.\n");
        }
    }

    free(m);
    free(sm);
    free(mout);

    return 0;
}
