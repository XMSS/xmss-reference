#include <stdint.h>
#include "params.h"

int xmss_parse_oid(xmss_params *params, const uint32_t oid)
{
    switch (oid) {
        case 0x01000001:
        case 0x02000002:
        case 0x03000003:
        case 0x04000004:
        case 0x05000005:
        case 0x06000006:
            params->func = XMSS_SHA2;
            break;

        case 0x07000007:
        case 0x08000008:
        case 0x09000009:
        case 0x0a00000a:
        case 0x0b00000b:
        case 0x0c00000c:
            params->func = XMSS_SHAKE;
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
            params->n = 32;
            break;

        case 0x04000004:
        case 0x05000005:
        case 0x06000006:

        case 0x0a00000a:
        case 0x0b00000b:
        case 0x0c00000c:
            params->n = 64;
            break;

        default:
            return 1;
    }
    switch (oid) {
        case 0x01000001:
        case 0x04000004:
        case 0x07000007:
        case 0x0a00000a:
            params->full_height = 10;
            break;

        case 0x02000002:
        case 0x05000005:
        case 0x08000008:
        case 0x0b00000b:
            params->full_height = 16;
            break;

        case 0x03000003:
        case 0x06000006:
        case 0x09000009:
        case 0x0c00000c:
            params->full_height = 20;

            break;
        default:
            return 1;
    }
    params->d = 1;
    params->tree_height = params->full_height  / params->d;
    params->wots_w = 16;
    params->wots_log_w = 4;
    if (params->n == 32) {
        params->wots_len1 = 64;
    }
    else {
        params->wots_len1 = 128;
    }
    params->wots_len2 = 3;
    params->wots_len = params->wots_len1 + params->wots_len2;
    params->wots_keysize = params->wots_len * params->n;
    params->index_len = 4;
    params->bytes = (params->index_len + params->n + params->d*params->wots_keysize
                     + params->full_height *params->n);
    params->publickey_bytes = 2*params->n;
    params->privatekey_bytes = 4*params->n + params->index_len;

    // TODO figure out sensible and legal values for this based on the above
    params->bds_k = 0;
    return 0;
}

int xmssmt_parse_oid(xmss_params *params, const uint32_t oid)
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
            params->func = XMSS_SHA2;
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
            params->func = XMSS_SHAKE;
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
            params->n = 32;
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
            params->n = 64;
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
            params->full_height = 20;
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
            params->full_height = 40;
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
            params->full_height = 60;
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
            params->d = 2;
            break;

        case 0x02000002:
        case 0x04000004:
        case 0x0a00000a:
        case 0x0c00000c:
        case 0x03010103:
        case 0x05010105:
        case 0x0b01010b:
        case 0x0d01010d:
            params->d = 4;
            break;

        case 0x05000005:
        case 0x0d00000d:
        case 0x06010106:
        case 0x0e01010e:
            params->d = 8;
            break;

        case 0x06000006:
        case 0x0e00000e:
        case 0x07010107:
        case 0x0f01010f:
            params->d = 3;
            break;

        case 0x07000007:
        case 0x0f00000f:
        case 0x08010108:
        case 0x01020201:
            params->d = 6;
            break;

        case 0x08000008:
        case 0x01010101:
        case 0x09010109:
        case 0x02020202:
            params->d = 12;
            break;

        default:
            return 1;
    }

    params->tree_height = params->full_height  / params->d;
    params->wots_w = 16;
    params->wots_log_w = 4;
    if (params->n == 32) {
        params->wots_len1 = 64;
    }
    else {
        params->wots_len1 = 128;
    }
    params->wots_len2 = 3;
    params->wots_len = params->wots_len1 + params->wots_len2;
    params->wots_keysize = params->wots_len * params->n;
    params->index_len = 4;
    params->bytes = (params->index_len + params->n + params->d*params->wots_keysize
                     + params->full_height *params->n);
    params->publickey_bytes = 2*params->n;
    params->privatekey_bytes = 4*params->n + params->index_len;

    // TODO figure out sensible and legal values for this based on the above
    params->bds_k = 0;
    return 0;
}
