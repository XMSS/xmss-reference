#include "../params.h"
#include "../xmss_core.h"
#include <stdio.h>

#define MLEN 32

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_CORE_SIGN_OPEN xmssmt_core_sign_open
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_CORE_SIGN_OPEN xmss_core_sign_open
#endif

int main(int argc, char **argv) {
    FILE *keypair;
    xmss_params params;
    uint32_t oid;
    int ret;

    if (argc != 2) {
        fprintf(stderr, "Expected keypair filename as only parameter, "
                        "and the signature + message via stdin.\n"
                        "Keypair file needs only to contain the public key.\n"
                        "The return code 0 indicates verification success.\n");
        return -1;
    }

    keypair = fopen(argv[1], "rb");
    if (keypair == NULL) {
        return -1;
    }

    fread(&oid, 1, XMSS_OID_LEN, keypair);
    XMSS_PARSE_OID(&params, oid);

    unsigned char pk[params.pk_bytes];
    unsigned char sm[params.sig_bytes + MLEN];
    unsigned char m[params.sig_bytes + MLEN];
    unsigned long long mlen;

    fread(pk, 1, params.pk_bytes, keypair);
    fread(sm, 1, params.sig_bytes + MLEN, stdin);

    ret = XMSS_CORE_SIGN_OPEN(&params, m, &mlen, sm, params.sig_bytes + MLEN, pk);

    if (ret) {
        printf("Verification failed!\n");
    }
    else {
        printf("Verification succeeded.\n");
    }

    return ret;
}
