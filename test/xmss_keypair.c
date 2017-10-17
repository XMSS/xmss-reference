#include "../params.h"
#include "../xmss.h"
#include <stdio.h>
#include <stdint.h>

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

    xmss_str_to_oid(&oid, argv[1]);
    xmss_parse_oid(&params, oid);

    unsigned char pk[XMSS_OID_LEN + params.publickey_bytes];
    unsigned char sk[XMSS_OID_LEN + params.privatekey_bytes];

    xmss_keypair(pk, sk, oid);

    fwrite(pk, 1, XMSS_OID_LEN + params.publickey_bytes, stdout);
    fwrite(sk, 1, XMSS_OID_LEN + params.privatekey_bytes, stdout);

    fclose(stdout);
}
