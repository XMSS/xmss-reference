#include "../params.h"
#include "../xmss_core.h"
#include <stdio.h>

#define MLEN 32

int main(int argc, char **argv) {
    FILE *keypair;
    xmss_params params;
    uint32_t oid_pk;
    uint32_t oid_sk;

    if (argc != 2) {
        fprintf(stderr, "Expected keypair filename as only parameter, "
                        "and the message via stdin.\n"
                        "The keypair is updated with the changed state, "
                        "and the message + signature is output via stdout.\n");
        return -1;
    }

    keypair = fopen(argv[1], "rb");
    if (keypair == NULL) {
        fprintf(stderr, "Could not open keypair file.\n");
        return -1;
    }

    // Read the OID from the public key, as we need its length to seek past it
    fread(&oid_pk, 1, XMSS_OID_LEN, keypair);
    xmssmt_parse_oid(&params, oid_pk);

    // fseek past the public key
    fseek(keypair, params.publickey_bytes, SEEK_CUR);
    // This is the OID we're actually going to use. Likely the same, but still.
    fread(&oid_sk, 1, XMSS_OID_LEN, keypair);
    xmssmt_parse_oid(&params, oid_sk);

    unsigned char sk[params.privatekey_bytes];
    unsigned char m[MLEN];
    unsigned char sm[params.bytes + MLEN];
    unsigned long long smlen;

    fread(sk, 1, params.privatekey_bytes, keypair);
    fread(m, 1, MLEN, stdin);
    xmssmt_core_sign(&params, sk, sm, &smlen, m, MLEN);

    fseek(keypair, -params.privatekey_bytes, SEEK_CUR);
    fwrite(sk, 1, params.privatekey_bytes, keypair);
    fwrite(sm, 1, params.bytes + MLEN, stdout);

    fclose(keypair);
    fclose(stdout);
}
