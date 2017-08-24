#include <stdint.h>
#include "params_runtime.h"

int xmss_parse_oid(uint32_t oid)
{
    switch (oid) {
        case 0x01000001:
        case 0x02000002:
        case 0x03000003:
        case 0x04000004:
        case 0x05000005:
        case 0x06000006:
            XMSS_FUNC = XMSS_SHA2;
            break;

        case 0x07000007:
        case 0x08000008:
        case 0x09000009:
        case 0x0a00000a:
        case 0x0b00000b:
        case 0x0c00000c:
            XMSS_FUNC = XMSS_SHAKE;
            break;

        default:
            return 1;
    }
    switch (oid) {
        case 0x01000001:
        case 0x02000002:
        case 0x03000003:

        case 0x07000007:
        case 0x08000008:
        case 0x09000009:
            XMSS_N = 32;
            break;

        case 0x04000004:
        case 0x05000005:
        case 0x06000006:

        case 0x0a00000a:
        case 0x0b00000b:
        case 0x0c00000c:
            XMSS_N = 64;
            break;

        default:
            return 1;
    }
    switch (oid) {
        case 0x01000001:
        case 0x04000004:
        case 0x07000007:
        case 0x0a00000a:
            XMSS_FULLHEIGHT = 10;
            break;

        case 0x02000002:
        case 0x05000005:
        case 0x08000008:
        case 0x0b00000b:
            XMSS_FULLHEIGHT = 16;
            break;

        case 0x03000003:
        case 0x06000006:
        case 0x09000009:
        case 0x0c00000c:
            XMSS_FULLHEIGHT = 20;

            break;
        default:
            return 1;
    }
    XMSS_D = 1;
    XMSS_TREEHEIGHT = XMSS_FULLHEIGHT / XMSS_D;
    XMSS_WOTS_W = 16;
    XMSS_WOTS_LOG_W = 4;
    if (XMSS_N == 32) {
        XMSS_WOTS_LEN1 = 64;
    }
    else {
        XMSS_WOTS_LEN1 = 128;
    }
    XMSS_WOTS_LEN2 = 3;
    XMSS_WOTS_LEN = XMSS_WOTS_LEN1 + XMSS_WOTS_LEN2;
    XMSS_WOTS_KEYSIZE = XMSS_WOTS_LEN * XMSS_N;
    XMSS_INDEX_LEN = 4;
    XMSS_BYTES = (XMSS_INDEX_LEN + XMSS_N + XMSS_D*XMSS_WOTS_KEYSIZE
                  + XMSS_FULLHEIGHT*XMSS_N);
    XMSS_PUBLICKEY_BYTES = 2*XMSS_N;
    XMSS_PRIVATEKEY_BYTES = 4*XMSS_N + XMSS_INDEX_LEN;

    XMSS_OID_LEN = 4;

    // TODO figure out sensible and legal values for this based on the above
    XMSS_BDS_K = 0;
    return 0;
}

int xmssmt_parse_oid(uint32_t oid)
{
    switch (oid) {
        case 0x01000001:
        case 0x02000002:
        case 0x03000003:
        case 0x04000004:
        case 0x05000005:
        case 0x06000006:
        case 0x07000007:
        case 0x08000008:
        case 0x09000009:
        case 0x0a00000a:
        case 0x0b00000b:
        case 0x0c00000c:
        case 0x0d00000d:
        case 0x0e00000e:
        case 0x0f00000f:
        case 0x01010101:
            XMSS_FUNC = XMSS_SHA2;
            break;

        case 0x02010102:
        case 0x03010103:
        case 0x04010104:
        case 0x05010105:
        case 0x06010106:
        case 0x07010107:
        case 0x08010108:
        case 0x09010109:
        case 0x0a01010a:
        case 0x0b01010b:
        case 0x0c01010c:
        case 0x0d01010d:
        case 0x0e01010e:
        case 0x0f01010f:
        case 0x01020201:
        case 0x02020202:
            XMSS_FUNC = XMSS_SHAKE;
            break;

        default:
            return 1;
    }
    switch (oid) {
        case 0x01000001:
        case 0x02000002:
        case 0x03000003:
        case 0x04000004:
        case 0x05000005:
        case 0x06000006:
        case 0x07000007:
        case 0x08000008:

        case 0x02010102:
        case 0x03010103:
        case 0x04010104:
        case 0x05010105:
        case 0x06010106:
        case 0x07010107:
        case 0x08010108:
        case 0x09010109:
            XMSS_N = 32;
            break;

        case 0x09000009:
        case 0x0a00000a:
        case 0x0b00000b:
        case 0x0c00000c:
        case 0x0d00000d:
        case 0x0e00000e:
        case 0x0f00000f:
        case 0x01010101:

        case 0x0a01010a:
        case 0x0b01010b:
        case 0x0c01010c:
        case 0x0d01010d:
        case 0x0e01010e:
        case 0x0f01010f:
        case 0x01020201:
        case 0x02020202:
            XMSS_N = 64;
            break;

        default:
            return 1;
    }
    switch (oid) {
        case 0x01000001:
        case 0x02000002:

        case 0x09000009:
        case 0x0a00000a:

        case 0x02010102:
        case 0x03010103:

        case 0x0a01010a:
        case 0x0b01010b:
            XMSS_FULLHEIGHT = 20;
            break;

        case 0x03000003:
        case 0x04000004:
        case 0x05000005:

        case 0x0b00000b:
        case 0x0c00000c:
        case 0x0d00000d:

        case 0x04010104:
        case 0x05010105:
        case 0x06010106:

        case 0x0c01010c:
        case 0x0d01010d:
        case 0x0e01010e:
            XMSS_FULLHEIGHT = 40;
            break;

        case 0x06000006:
        case 0x07000007:
        case 0x08000008:

        case 0x0e00000e:
        case 0x0f00000f:
        case 0x01010101:

        case 0x07010107:
        case 0x08010108:
        case 0x09010109:

        case 0x0f01010f:
        case 0x01020201:
        case 0x02020202:
            XMSS_FULLHEIGHT = 60;
            break;

        default:
            return 1;
    }
    switch (oid) {
        case 0x01000001:
        case 0x03000003:
        case 0x09000009:
        case 0x0b00000b:
        case 0x02010102:
        case 0x04010104:
        case 0x0a01010a:
        case 0x0c01010c:
            XMSS_D = 2;
            break;

        case 0x02000002:
        case 0x04000004:
        case 0x0a00000a:
        case 0x0c00000c:
        case 0x03010103:
        case 0x05010105:
        case 0x0b01010b:
        case 0x0d01010d:
            XMSS_D = 4;
            break;

        case 0x05000005:
        case 0x0d00000d:
        case 0x06010106:
        case 0x0e01010e:
            XMSS_D = 8;
            break;

        case 0x06000006:
        case 0x0e00000e:
        case 0x07010107:
        case 0x0f01010f:
            XMSS_D = 3;
            break;

        case 0x07000007:
        case 0x0f00000f:
        case 0x08010108:
        case 0x01020201:
            XMSS_D = 6;
            break;

        case 0x08000008:
        case 0x01010101:
        case 0x09010109:
        case 0x02020202:
            XMSS_D = 12;
            break;

        default:
            return 1;
    }

    XMSS_TREEHEIGHT = XMSS_FULLHEIGHT / XMSS_D;
    XMSS_WOTS_W = 16;
    XMSS_WOTS_LOG_W = 4;
    if (XMSS_N == 32) {
        XMSS_WOTS_LEN1 = 64;
    }
    else {
        XMSS_WOTS_LEN1 = 128;
    }
    XMSS_WOTS_LEN2 = 3;
    XMSS_WOTS_LEN = XMSS_WOTS_LEN1 + XMSS_WOTS_LEN2;
    XMSS_WOTS_KEYSIZE = XMSS_WOTS_LEN * XMSS_N;
    XMSS_INDEX_LEN = 4;
    XMSS_BYTES = (XMSS_INDEX_LEN + XMSS_N + XMSS_D*XMSS_WOTS_KEYSIZE
                  + XMSS_FULLHEIGHT*XMSS_N);
    XMSS_PUBLICKEY_BYTES = 2*XMSS_N;
    XMSS_PRIVATEKEY_BYTES = 4*XMSS_N + XMSS_INDEX_LEN;

    XMSS_OID_LEN = 4;

    // TODO figure out sensible and legal values for this based on the above
    XMSS_BDS_K = 0;
    return 0;
}
