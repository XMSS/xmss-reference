#include "../params.h"
#include "../xmss_core.h"
#include <stdio.h>

#define MLEN 32

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
    xmssmt_parse_oid(&params, oid);

    unsigned char pk[params.publickey_bytes];
    unsigned char sm[params.bytes + MLEN];
    unsigned char m[params.bytes + MLEN];
    unsigned long long mlen;

    fread(pk, 1, params.publickey_bytes, keypair);
    fread(sm, 1, params.bytes + MLEN, stdin);

    ret = xmssmt_core_sign_open(&params, m, &mlen, sm, params.bytes + MLEN, pk);

    if (ret) {
        printf("Verification failed!\n");
    }
    else {
        printf("Verification succeeded.\n");
    }

    return ret;
}
