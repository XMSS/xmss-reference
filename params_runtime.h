#ifndef PARAMS_H
#define PARAMS_H

#include <stdint.h>

// These are simply internal identifiers for the supported hash functions
#define XMSS_SHA2 0
#define XMSS_SHAKE 1

extern unsigned int XMSS_FUNC;
extern unsigned int XMSS_N;
extern unsigned int XMSS_WOTS_W;
extern unsigned int XMSS_WOTS_LOG_W;
extern unsigned int XMSS_WOTS_LEN1;
extern unsigned int XMSS_WOTS_LEN2;
extern unsigned int XMSS_WOTS_LEN;
extern unsigned int XMSS_WOTS_KEYSIZE;
extern unsigned int XMSS_FULLHEIGHT;
extern unsigned int XMSS_TREEHEIGHT;
extern unsigned int XMSS_D;
extern unsigned int XMSS_INDEX_LEN;
extern unsigned int XMSS_BYTES;
extern unsigned int XMSS_PUBLICKEY_BYTES;
extern unsigned int XMSS_PRIVATEKEY_BYTES;
extern unsigned int XMSS_OID_LEN;
extern unsigned int XMSS_BDS_K;

int xmss_parse_oid(uint32_t oid);
int xmssmt_parse_oid(uint32_t oid);

#endif