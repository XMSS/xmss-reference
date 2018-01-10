#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../wots.h"
#include "../randombytes.h"
#include "../params.h"

int main()
{
    xmss_params params;
    // TODO test more different OIDs
    uint32_t oid = 0x00000001;

    /* For WOTS it doesn't matter if we use XMSS or XMSSMT. */
    xmss_parse_oid(&params, oid);

    unsigned char seed[params.n];
    unsigned char pub_seed[params.n];
    unsigned char pk1[params.wots_sig_bytes];
    unsigned char pk2[params.wots_sig_bytes];
    unsigned char sig[params.wots_sig_bytes];
    unsigned char m[params.n];
    uint32_t addr[8] = {0};

    randombytes(seed, params.n);
    randombytes(pub_seed, params.n);
    randombytes(m, params.n);
    randombytes((unsigned char *)addr, 8 * sizeof(uint32_t));

    printf("Testing WOTS signature and PK derivation.. ");

    wots_pkgen(&params, pk1, seed, pub_seed, addr);
    wots_sign(&params, sig, m, seed, pub_seed, addr);
    wots_pk_from_sig(&params, pk2, sig, m, pub_seed, addr);

    if (memcmp(pk1, pk2, params.wots_sig_bytes)) {
        printf("failed!\n");
        return -1;
    }
    printf("successful.\n");
    return 0;
}
