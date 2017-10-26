#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../params.h"
#include "../xmss.h"
#include "../randombytes.h"

#define MLEN 32

int main()
{
    xmss_params params;
    char *oidstr = "XMSS-SHA2_10_256";
    uint32_t oid;
    unsigned int i;

    fprintf(stderr, "Testing if XMSS-SHA2_10_256 signing is deterministic.. ");

    xmss_str_to_oid(&oid, oidstr);
    xmss_parse_oid(&params, oid);

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char sk2[XMSS_OID_LEN + params.sk_bytes];

    unsigned char m[MLEN];
    unsigned char sm[params.sig_bytes + MLEN];
    unsigned char sm2[params.sig_bytes + MLEN];
    unsigned long long smlen;

    xmss_keypair(pk, sk, oid);

    /* Duplicate the key, because the original will be modified. */
    memcpy(sk2, sk, XMSS_OID_LEN + params.sk_bytes);

    /* Sign a random message (but twice the same one). */
    randombytes(m, MLEN);

    xmss_sign(sk, sm, &smlen, m, MLEN);
    xmss_sign(sk2, sm2, &smlen, m, MLEN);

    /* Compare signature, and, if applicable, print the differences. */
    if (memcmp(sm, sm2, params.sig_bytes + MLEN)) {
        fprintf(stderr, "signatures differ!\n");
        for (i = 0; i < params.sig_bytes + MLEN; i++) {
            fprintf(stderr, (sm[i] != sm2[i] ? "x" : "."));
        }
        fprintf(stderr, "\n");
        return -1;
    }
    else {
        fprintf(stderr, "signatures are identical.\n");
    }

    return 0;
}
