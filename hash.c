#include "hash_address.h"
#include "xmss_commons.h"
#include "params.h"
#include "hash.h"
#include "fips202.h"

#include <stdint.h>
#include <openssl/sha.h>

void addr_to_bytes(unsigned char *bytes, const uint32_t addr[8])
{
    int i;
    for (i = 0; i < 8; i++) {
        ull_to_bytes(bytes + i*4, addr[i], 4);
    }
}

static int core_hash(const xmss_params *params,
                     unsigned char *out, const unsigned int type,
                     const unsigned char *key, unsigned int keylen,
                     const unsigned char *in, unsigned long long inlen, int n)
{
    unsigned long long i = 0;
    unsigned char buf[inlen + n + keylen];

    /* We arrange the input into the hash function to be of the form:
     *  toByte(X, 32) || KEY || M
     */

    ull_to_bytes(buf, type, n);

    for (i=0; i < keylen; i++) {
        buf[i+n] = key[i];
    }

    for (i=0; i < inlen; i++) {
        buf[keylen + n + i] = in[i];
    }

    if (n == 32 && params->func == XMSS_SHA2) {
        SHA256(buf, inlen + keylen + n, out);
    }
    else if (n == 32 && params->func == XMSS_SHAKE) {
        shake128(out, 32, buf, inlen + keylen + n);
    }
    else if (n == 64 && params->func == XMSS_SHA2) {
        SHA512(buf, inlen + keylen + n, out);
    }
    else if (n == 64 && params->func == XMSS_SHAKE) {
        shake256(out, 64, buf, inlen + keylen + n);
    }
    else {
        return 1;
    }
    return 0;
}

int prf(const xmss_params *params,
        unsigned char *out, const unsigned char *in,
        const unsigned char *key, unsigned int keylen)
{
    return core_hash(params, out, 3, key, keylen, in, 32, keylen);
}

int h_msg(const xmss_params *params,
          unsigned char *out,
          const unsigned char *in, unsigned long long inlen,
          const unsigned char *key, const unsigned int keylen)
{
    return core_hash(params, out, 2, key, keylen, in, inlen, params->n);
}

/**
 * We assume the left half is in in[0]...in[n-1]
 */
int hash_h(const xmss_params *params,
           unsigned char *out, const unsigned char *in,
           const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buf[2*params->n];
    unsigned char key[params->n];
    unsigned char bitmask[2*params->n];
    unsigned char addr_as_bytes[32];
    unsigned int i;

    /* Generate the n-byte key. */
    set_key_and_mask(addr, 0);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, key, addr_as_bytes, pub_seed, params->n);

    /* Generate the 2n-byte mask. */
    set_key_and_mask(addr, 1);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, bitmask, addr_as_bytes, pub_seed, params->n);

    set_key_and_mask(addr, 2);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, bitmask + params->n, addr_as_bytes, pub_seed, params->n);

    for (i = 0; i < 2*params->n; i++) {
        buf[i] = in[i] ^ bitmask[i];
    }
    return core_hash(params, out, 1, key, params->n, buf, 2*params->n, params->n);
}

int hash_f(const xmss_params *params,
           unsigned char *out, const unsigned char *in,
           const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buf[params->n];
    unsigned char key[params->n];
    unsigned char bitmask[params->n];
    unsigned char addr_as_bytes[32];
    unsigned int i;

    set_key_and_mask(addr, 0);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, key, addr_as_bytes, pub_seed, params->n);

    set_key_and_mask(addr, 1);
    addr_to_bytes(addr_as_bytes, addr);
    prf(params, bitmask, addr_as_bytes, pub_seed, params->n);

    for (i = 0; i < params->n; i++) {
        buf[i] = in[i] ^ bitmask[i];
    }
    return core_hash(params, out, 0, key, params->n, buf, params->n, params->n);
}
