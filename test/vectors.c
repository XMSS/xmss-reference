/* 
 * Generate intermediate test vectors useful to test implementations.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../wots.h"
#include "../randombytes.h"
#include "../params.h"
#include "../fips202.h"
#include "../utils.h"
#include "../xmss_commons.h"
#include "../xmss_core.h"

void print_hex(unsigned char *buf, int len) {
    for (int i = 0; i < len; i++) {
        printf("%x%x", buf[i] / 16, buf[i] & 15);
    }
}

void print_hash(unsigned char *buf, int len) {
    unsigned char tmp[10];
    shake128(tmp, 10, buf, len);
    print_hex(tmp, 10);
}

void vectors_xmss(uint32_t oid, int mt) {
    xmss_params params;

    if (mt) {
        xmssmt_parse_oid(&params, oid);
    } else {
        xmss_parse_oid(&params, oid);
    }

    unsigned char seed[params.n * 3];
    unsigned char pk[params.pk_bytes];
    unsigned char sk[params.sk_bytes];
    unsigned char msg[1] = {37};
    unsigned char sm[params.sig_bytes + 1];
    unsigned long long smlen = 0;

    for (unsigned int i = 0; i < 3*params.n; i++) {
        seed[i] = i;
    }

    xmssmt_core_seed_keypair(&params, pk, sk, seed);

    ull_to_bytes(sk, params.index_bytes, 1 << (params.full_height - 1));

    if (mt) {
        xmssmt_core_sign(&params, sk, sm, &smlen, msg, 1);
    } else {
        xmss_core_sign(&params, sk, sm, &smlen, msg, 1);
    }

    if (mt) {
        printf("XMSSMT ");
    } else {
        printf("XMSS ");
    }
    printf("%d ", oid);
    print_hash(pk, params.pk_bytes);
    printf(" ");
    print_hash(sm, params.sig_bytes);
    printf("\n");
}

void vectors_wots(uint32_t oid) {
    xmss_params params;

    xmss_parse_oid(&params, oid);

    unsigned char sk_seed[params.n];
    unsigned char pub_seed[params.n];

    unsigned char pk[params.wots_sig_bytes];
    unsigned char leaf[params.n];

    unsigned char sig[params.wots_sig_bytes];
    unsigned char m[params.n];
    uint32_t addr[8] = {0};
    uint32_t addr2[8] = {0};

    for (unsigned int i = 0; i < 8; i++) {
        addr[i] = 500000000*i;
        addr2[i] = 400000000*i;
    }

    for (unsigned int i = 0; i < params.n; i++) {
        m[i] = 3*i;
        pub_seed[i] = 2*i;
        sk_seed[i] = i;
    }

    wots_pkgen(&params, pk, sk_seed, pub_seed, addr);
    wots_sign(&params, sig, m, sk_seed, pub_seed, addr);

    printf("WOTS+ %d ", oid);
    print_hash(pk, params.wots_sig_bytes);
    printf(" ");
    print_hash(sig, params.wots_sig_bytes);
    printf(" ");

    // Note that this garbles pk
    gen_leaf_wots(&params, leaf, sk_seed, pub_seed, addr, addr2);
    print_hash(leaf, params.n);

    printf("\n");
}

int main() {
    for (uint32_t oid = 1; oid <= 0x15; oid += 3) {
        vectors_wots(oid);
    }
    for (uint32_t oid = 2; oid <= 56; oid += 8) {
        vectors_xmss(oid, 1);
    }
    for (uint32_t oid = 1; oid <= 0x15; oid += 3) {
        vectors_xmss(oid, 0);
    }
}

