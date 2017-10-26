#include "../params.h"
#include "../xmss.h"
#include <stdio.h>
#include <stdint.h>

#ifdef XMSSMT
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_KEYPAIR xmssmt_keypair
#else
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_KEYPAIR xmss_keypair
#endif

int main(int argc, char **argv)
{
    xmss_params params;
    uint32_t oid;

    if (argc != 2) {
        fprintf(stderr, "Expected parameter string (e.g. 'XMSS-SHA2_10_256')"
                        " as only parameter.\n"
                        "The keypair is written to stdout.\n");
        return -1;
    }

    XMSS_STR_TO_OID(&oid, argv[1]);
    XMSS_PARSE_OID(&params, oid);

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];

    XMSS_KEYPAIR(pk, sk, oid);

    fwrite(pk, 1, XMSS_OID_LEN + params.pk_bytes, stdout);
    fwrite(sk, 1, XMSS_OID_LEN + params.sk_bytes, stdout);

    fclose(stdout);
}
