#include <stdio.h>

#include "../params.h"
#include "../xmss.h"

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_SIGN_OPEN xmssmt_sign_open
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_SIGN_OPEN xmss_sign_open
#endif

int main(int argc, char **argv) {
    FILE *keypair_file;
    FILE *sm_file;

    xmss_params params;
    uint32_t oid;

    unsigned long long smlen;
    int ret;

    if (argc != 3) {
        fprintf(stderr, "Expected keypair and signature + message filenames "
                        "as two parameters.\n"
                        "Keypair file needs only to contain the public key.\n"
                        "The return code 0 indicates verification success.\n");
        return -1;
    }

    keypair_file = fopen(argv[1], "rb");
    if (keypair_file == NULL) {
        fprintf(stderr, "Could not open keypair file.\n");
        return -1;
    }

    sm_file = fopen(argv[2], "rb");
    if (sm_file == NULL) {
        fprintf(stderr, "Could not open signature + message file.\n");
        return -1;
    }

    /* Find out the message length. */
    fseek(sm_file, 0, SEEK_END);
    smlen = ftell(sm_file);

    fread(&oid, 1, XMSS_OID_LEN, keypair_file);
    XMSS_PARSE_OID(&params, oid);

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sm[smlen];
    unsigned char m[smlen];
    unsigned long long mlen;

    fseek(keypair_file, 0, SEEK_SET);
    fseek(sm_file, 0, SEEK_SET);
    fread(pk, 1, XMSS_OID_LEN + params.pk_bytes, keypair_file);
    fread(sm, 1, smlen, sm_file);

    ret = XMSS_SIGN_OPEN(m, &mlen, sm, smlen, pk);

    if (ret) {
        printf("Verification failed!\n");
    }
    else {
        printf("Verification succeeded.\n");
    }

    fclose(keypair_file);
    fclose(sm_file);

    return ret;
}
