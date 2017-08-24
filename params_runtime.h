#ifndef PARAMS_H
#define PARAMS_H

#include <stdint.h>

// These are simply internal identifiers for the supported hash functions
#define XMSS_SHA2 0
#define XMSS_SHAKE 1

// These parameters can be used after calling xmss[mt]_parse_oid(oid).
unsigned int XMSS_FUNC;
unsigned int XMSS_N;
unsigned int XMSS_WOTS_W;
unsigned int XMSS_WOTS_LOG_W;
unsigned int XMSS_WOTS_LEN1;
unsigned int XMSS_WOTS_LEN2;
unsigned int XMSS_WOTS_LEN;
unsigned int XMSS_WOTS_KEYSIZE;
unsigned int XMSS_FULLHEIGHT;
unsigned int XMSS_TREEHEIGHT;
unsigned int XMSS_D;
unsigned int XMSS_INDEX_LEN;
unsigned int XMSS_BYTES;
unsigned int XMSS_PUBLICKEY_BYTES;
unsigned int XMSS_PRIVATEKEY_BYTES;
unsigned int XMSS_OID_LEN;
unsigned int XMSS_BDS_K;

int xmss_parse_oid(uint32_t oid);
int xmssmt_parse_oid(uint32_t oid);

#endif