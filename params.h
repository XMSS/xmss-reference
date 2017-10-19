#ifndef XMSS_PARAMS_H
#define XMSS_PARAMS_H

#include <stdint.h>

// These are merely internal identifiers for the supported hash functions
#define XMSS_SHA2 0
#define XMSS_SHAKE 1

// This is a consequence of the OID definitions in the draft, used for parsing
#define XMSS_OID_LEN 4

// This structure will be populated when calling xmss[mt]_parse_oid
typedef struct {
    unsigned int func;
    unsigned int n;
    unsigned int wots_w;
    unsigned int wots_log_w;
    unsigned int wots_len1;
    unsigned int wots_len2;
    unsigned int wots_len;
    unsigned int wots_keysize;
    unsigned int full_height;
    unsigned int tree_height;
    unsigned int d;
    unsigned int index_len;
    unsigned int bytes;
    unsigned int publickey_bytes;
    unsigned int privatekey_bytes;
    unsigned int bds_k;
} xmss_params;

int xmss_str_to_oid(uint32_t *oid, const char* s);
int xmssmt_str_to_oid(uint32_t *oid, const char* s);

int xmss_parse_oid(xmss_params *params, const uint32_t oid);
int xmssmt_parse_oid(xmss_params *params, const uint32_t oid);

#endif
