#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"
#include "../utils.h"

#define XMSS_MLEN 32

// #ifndef XMSS_SIGNATURES
//     #define XMSS_SIGNATURES 16
// #endif

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
    #define XMSS_SIGNATURES (1 << 20)
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
    #define XMSS_VARIANT "XMSS-SHA2_10_256"
    #define XMSS_SIGNATURES (1 << 10)
#endif

int main()
{
    xmss_params params;
    uint32_t oid;
    int ret = 0;
    int return_code = 0;
    int i;

    // TODO test more different variants
    XMSS_STR_TO_OID(&oid, XMSS_VARIANT);
    XMSS_PARSE_OID(&params, oid);

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *m = malloc(XMSS_MLEN);
    unsigned char *sm = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *mout = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned long long smlen;
    unsigned long long idx;
    unsigned long long j;

    randombytes(m, XMSS_MLEN);

    XMSS_KEYPAIR(pk, sk, oid);

    printf("Testing %d %s signatures.. \n", XMSS_SIGNATURES, XMSS_VARIANT);

    for (i = 0; i < XMSS_SIGNATURES; i++) {
        if( (i & 1023) == 0)
            printf("  - iteration #%d:\n", i);

        return_code = XMSS_SIGN(sk, sm, &smlen, m, XMSS_MLEN);

        if (return_code != 0) {
            printf("  Error! Return code was %d\n",return_code);
            ret = -1;
        }
    }
    if(ret == 0)
            printf("As expected, return code was 0\n");
    for (; i < (XMSS_SIGNATURES) + 2; i++) {
        printf("  - iteration #%d:\n", i);

        return_code = XMSS_SIGN(sk, sm, &smlen, m, XMSS_MLEN);

        if (return_code == 0) {
                printf("  Error! Return code was %d\n",return_code);
                ret = -1;
        }
        else {
                printf("Return code as expected [%d].\n", return_code);
        }
        
        idx = (unsigned long)bytes_to_ull(sk, params.index_bytes);
        printf("Index: %llu\n", idx);
        printf("Secret key: %llu\n", idx);
        for (j = 0; j < XMSS_OID_LEN + params.sk_bytes;j++)
                printf("%02x", sk[j]);

        printf("\n");
    }
    
    free(m);
    free(sm);
    free(mout);

    return ret;
}
