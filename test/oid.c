#include <stdio.h>

#include "../params.h"

#define CHECK_OID_XMSS(PARAMSET) \
    if (xmss_str_to_oid(&oid, PARAMSET)) {\
        printf("Did not recognize " PARAMSET "!\n");\
        return -1;\
    }\
    if (xmss_parse_oid(&params, oid)) {\
        printf("Could not parse OID for " PARAMSET "!\n");\
        return -1;\
    }

#define CHECK_OID_XMSSMT(PARAMSET) \
    if (xmssmt_str_to_oid(&oid, PARAMSET)) {\
        printf("Did not recognize " PARAMSET "!\n");\
        return -1;\
    }\
    if (xmssmt_parse_oid(&params, oid)) {\
        printf("Could not parse OID for " PARAMSET "!\n");\
        return -1;\
    }

int main()
{
    uint32_t oid;
    xmss_params params;

    printf("Testing if all expected XMSS   parameter sets are recognized.. ");
    CHECK_OID_XMSS("XMSS-SHA2_10_256");
    CHECK_OID_XMSS("XMSS-SHA2_16_256");
    CHECK_OID_XMSS("XMSS-SHA2_20_256");
    CHECK_OID_XMSS("XMSS-SHA2_10_512");
    CHECK_OID_XMSS("XMSS-SHA2_16_512");
    CHECK_OID_XMSS("XMSS-SHA2_20_512");
    CHECK_OID_XMSS("XMSS-SHAKE_10_256");
    CHECK_OID_XMSS("XMSS-SHAKE_16_256");
    CHECK_OID_XMSS("XMSS-SHAKE_20_256");
    CHECK_OID_XMSS("XMSS-SHAKE_10_512");
    CHECK_OID_XMSS("XMSS-SHAKE_16_512");
    CHECK_OID_XMSS("XMSS-SHAKE_20_512");
    printf("successful.\n");

    printf("Testing if all expected XMSSMT parameter sets are recognized.. ");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_20/2_256");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_20/4_256");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_40/2_256");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_40/4_256");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_40/8_256");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_60/3_256");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_60/6_256");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_60/12_256");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_20/2_512");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_20/4_512");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_40/2_512");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_40/4_512");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_40/8_512");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_60/3_512");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_60/6_512");
    CHECK_OID_XMSSMT("XMSSMT-SHA2_60/12_512");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_20/2_256");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_20/4_256");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_40/2_256");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_40/4_256");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_40/8_256");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_60/3_256");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_60/6_256");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_60/12_256");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_20/2_512");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_20/4_512");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_40/2_512");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_40/4_512");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_40/8_512");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_60/3_512");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_60/6_512");
    CHECK_OID_XMSSMT("XMSSMT-SHAKE_60/12_512");
    printf("successful.\n");

    return 0;
}
