#ifndef NIST_PARAM_H
#define NIST_PARAM_H

#define NIST_LEVEL 0

#ifndef NIST_LEVEL
#define NIST_LEVEL 0
#endif

/*
 * NIST_LEVEL below does not make sense in term of security
 * I use it as place holder for the total number of signatures
 */

#if NIST_LEVEL == 0

#define XMSS_OID "XMSS-SHA2_10_256"
#define XMSSMT 0

#define XMSS_PUBLICKEYBYTES 64
#define XMSS_SECRETKEYBYTES 132

#define XMSS_SIGNBYTES 2500

#elif NIST_LEVEL == 1

#define XMSS_OID "XMSS-SHA2_16_256"
#define XMSSMT 0

#define XMSS_PUBLICKEYBYTES 64
#define XMSS_SECRETKEYBYTES 132

#define XMSS_SIGNBYTES 2692

#elif NIST_LEVEL == 2

#define XMSS_OID "XMSS-SHA2_20_256"
#define XMSSMT 0

#define XMSS_PUBLICKEYBYTES 64
#define XMSS_SECRETKEYBYTES 132

#define XMSS_SIGNBYTES 2820

#elif NIST_LEVEL == 3

#define XMSS_OID "XMSSMT-SHA2_20/2_256"
#define XMSSMT 1

#define XMSS_PUBLICKEYBYTES 64
#define XMSS_SECRETKEYBYTES 131

#define XMSS_SIGNBYTES 4963

#elif NIST_LEVEL == 4

#define XMSS_OID "XMSSMT-SHA2_40/2_256"
#define XMSSMT 1

#define XMSS_PUBLICKEYBYTES 64
#define XMSS_SECRETKEYBYTES 133

#define XMSS_SIGNBYTES 5605

#elif NIST_LEVEL == 5

#define XMSS_OID "XMSSMT-SHA2_60/3_256"
#define XMSSMT 1

#define XMSS_PUBLICKEYBYTES 64
#define XMSS_SECRETKEYBYTES 136

#define XMSS_SIGNBYTES 8392

#else

#error "Unspecified NIST_LEVEL {0,1,2,3,4,5}"

#endif

#if XMSSMT == 1
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_REMAIN_SIG xmssmt_remain_signatures
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
    #define XMSS_REMAIN_SIG xmss_remain_signatures
#endif

#define CRYPTO_PUBLIC_KEY XMSS_PUBLICKEYBYTES
#define CRYPTO_SECRET_KEY XMSS_SECRETKEYBYTES
#define CRYPTO_BYTES XMSS_SIGNBYTES

#endif
