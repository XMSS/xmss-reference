#ifndef XMSS_PARAMS_H
#define XMSS_PARAMS_H

#include <stdint.h>

/* These are merely internal identifiers for the supported hash functions. */
#define XMSS_SHA2 0
#define XMSS_SHAKE 1

/* This is a result of the OID definitions in the draft; needed for parsing. */
#define XMSS_OID_LEN 4

/* This structure will be populated when calling xmss[mt]_parse_oid. */
typedef struct {
    unsigned int func;
    unsigned int n;
    unsigned int wots_w;
    unsigned int wots_log_w;
    unsigned int wots_len1;
    unsigned int wots_len2;
    unsigned int wots_len;
    unsigned int wots_sig_bytes;
    unsigned int full_height;
    unsigned int tree_height;
    unsigned int d;
    unsigned int index_bytes;
    unsigned int sig_bytes;
    unsigned int pk_bytes;
    unsigned int sk_bytes;
    unsigned int bds_k;
} xmss_params;

/**
 * Accepts strings such as "XMSS-SHA2_10_256"
 *  and outputs OIDs such as 0x01000001.
 * Returns 1 when the parameter set is not found, 0 otherwise
 */
int xmss_str_to_oid(uint32_t *oid, const char* s);

/**
 * Accepts takes strings such as "XMSSMT-SHA2_20/2_256"
 *  and outputs OIDs such as 0x01000001.
 * Returns 1 when the parameter set is not found, 0 otherwise
 */
int xmssmt_str_to_oid(uint32_t *oid, const char* s);

/**
 * Accepts OIDs such as 0x01000001, and configures params accordingly.
 * Returns 1 when the OID is not found, 0 otherwise.
 */
int xmss_parse_oid(xmss_params *params, const uint32_t oid);

/**
 * Accepts OIDs such as 0x01000001, and configures params accordingly.
 * Returns 1 when the OID is not found, 0 otherwise.
 */
int xmssmt_parse_oid(xmss_params *params, const uint32_t oid);

#endif
