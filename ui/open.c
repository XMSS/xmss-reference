#include <stdio.h>
#include <stdlib.h>

#include "../params.h"
#include "../xmss.h"
#include "../utils.h"

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
    uint32_t oid = 0;
    uint8_t buffer[XMSS_OID_LEN];
    int parse_oid_result;

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
        fclose(keypair_file);
        return -1;
    }

    /* Find out the message length. */
    fseek(sm_file, 0, SEEK_END);
    smlen = ftell(sm_file);

    fread(&buffer, 1, XMSS_OID_LEN, keypair_file);
    oid = (uint32_t)bytes_to_ull(buffer, XMSS_OID_LEN);
    parse_oid_result = XMSS_PARSE_OID(&params, oid);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing oid.\n");
        fclose(keypair_file);
        fclose(sm_file);
        return parse_oid_result;
    }

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char *sm = malloc(smlen);
    unsigned char *m = malloc(smlen);
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

    free(m);
    free(sm);

    return ret;
}
