#include <stdint.h>
#include "xmss_commons.h"
#include "hash.h"
#include "wots.h"
#include "hash_address.h"
#include "params.h"

/**
 * Helper method for pseudorandom key generation
 * Expands an n-byte array into a len*n byte array
 * this is done using PRF
 */
static void expand_seed(const xmss_params *params,
                        unsigned char *outseeds, const unsigned char *inseed)
{
    uint32_t i;
    unsigned char ctr[32];

    for (i = 0; i < params->wots_len; i++) {
        to_byte(ctr, i, 32);
        prf(params, outseeds + i*params->n, ctr, inseed, params->n);
    }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays
 *
 * interpretes in as start-th value of the chain
 * addr has to contain the address of the chain
 */
static void gen_chain(const xmss_params *params,
                      unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    for (i = 0; i < params->n; i++) {
        out[i] = in[i];
    }

    for (i = start; i < (start+steps) && i < params->wots_w; i++) {
        set_hash_addr(addr, i);
        hash_f(params, out, out, pub_seed, addr);
    }
}

/**
 * base_w algorithm as described in draft.
 */
static void base_w(const xmss_params *params,
                   int *output, const int out_len, const unsigned char *input)
{
    int in = 0;
    int out = 0;
    uint8_t total = 0;
    int bits = 0;
    int i;

    for (i = 0; i < out_len; i++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= params->wots_log_w;
        output[out] = (total >> bits) & (params->wots_w - 1);
        out++;
    }
}

void wots_pkgen(const xmss_params *params,
                unsigned char *pk, const unsigned char *sk,
                const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    expand_seed(params, pk, sk);
    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, pk + i*params->n, pk + i*params->n,
                  0, params->wots_w-1, pub_seed, addr);
    }
}


void wots_sign(const xmss_params *params,
               unsigned char *sig, const unsigned char *msg,
               const unsigned char *sk, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    int basew[params->wots_len];
    int csum = 0;
    unsigned char csum_bytes[((params->wots_len2 * params->wots_log_w) + 7) / 8];
    int csum_basew[params->wots_len2];
    uint32_t i;

    base_w(params, basew, params->wots_len1, msg);

    for (i = 0; i < params->wots_len1; i++) {
        csum += params->wots_w - 1 - basew[i];
    }

    csum = csum << (8 - ((params->wots_len2 * params->wots_log_w) % 8));

    to_byte(csum_bytes, csum, ((params->wots_len2 * params->wots_log_w) + 7) / 8);
    base_w(params, csum_basew, params->wots_len2, csum_bytes);

    for (i = 0; i < params->wots_len2; i++) {
        basew[params->wots_len1 + i] = csum_basew[i];
    }

    expand_seed(params, sig, sk);

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, sig + i*params->n, sig + i*params->n,
                  0, basew[i], pub_seed, addr);
    }
}

void wots_pk_from_sig(const xmss_params *params, unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    int basew[params->wots_len];
    int csum = 0;
    unsigned char csum_bytes[((params->wots_len2 * params->wots_log_w) + 7) / 8];
    int csum_basew[params->wots_len2];
    uint32_t i = 0;

    base_w(params, basew, params->wots_len1, msg);

    for (i=0; i < params->wots_len1; i++) {
        csum += params->wots_w - 1 - basew[i];
    }

    csum = csum << (8 - ((params->wots_len2 * params->wots_log_w) % 8));

    to_byte(csum_bytes, csum, ((params->wots_len2 * params->wots_log_w) + 7) / 8);
    base_w(params, csum_basew, params->wots_len2, csum_bytes);

    for (i = 0; i < params->wots_len2; i++) {
        basew[params->wots_len1 + i] = csum_basew[i];
    }
    for (i=0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, pk + i*params->n, sig + i*params->n,
                  basew[i], params->wots_w-1-basew[i], pub_seed, addr);
    }
}
