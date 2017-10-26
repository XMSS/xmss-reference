#include <stdint.h>
#include <string.h>

#include "params.h"
#include "xmss_core.h"

int xmss_str_to_oid(uint32_t *oid, const char *s)
{
    if (!strcmp(s, "XMSS-SHA2_10_256")) {
        *oid = 0x01000001;
    }
    else if (!strcmp(s, "XMSS-SHA2_16_256")) {
        *oid = 0x02000002;
    }
    else if (!strcmp(s, "XMSS-SHA2_20_256")) {
        *oid = 0x03000003;
    }
    else if (!strcmp(s, "XMSS-SHA2_10_512")) {
        *oid = 0x04000004;
    }
    else if (!strcmp(s, "XMSS-SHA2_16_512")) {
        *oid = 0x05000005;
    }
    else if (!strcmp(s, "XMSS-SHA2_20_512")) {
        *oid = 0x06000006;
    }
    else if (!strcmp(s, "XMSS-SHAKE_10_256")) {
        *oid = 0x07000007;
    }
    else if (!strcmp(s, "XMSS-SHAKE_16_256")) {
        *oid = 0x08000008;
    }
    else if (!strcmp(s, "XMSS-SHAKE_20_256")) {
        *oid = 0x09000009;
    }
    else if (!strcmp(s, "XMSS-SHAKE_10_512")) {
        *oid = 0x0a00000a;
    }
    else if (!strcmp(s, "XMSS-SHAKE_16_512")) {
        *oid = 0x0b00000b;
    }
    else if (!strcmp(s, "XMSS-SHAKE_20_512")) {
        *oid = 0x0c00000c;
    }
    else {
        return -1;
    }
    return 0;
}

int xmssmt_str_to_oid(uint32_t *oid, const char *s)
{
    if (!strcmp(s, "XMSSMT-SHA2_20/2_256")) {
       *oid = 0x01000001;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_20/4_256")) {
       *oid = 0x02000002;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_40/2_256")) {
       *oid = 0x03000003;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_40/4_256")) {
       *oid = 0x04000004;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_40/8_256")) {
       *oid = 0x05000005;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_60/3_256")) {
       *oid = 0x06000006;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_60/6_256")) {
       *oid = 0x07000007;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_60/12_256")) {
      *oid = 0x08000008;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_20/2_512")) {
       *oid = 0x09000009;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_20/4_512")) {
       *oid = 0x0a00000a;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_40/2_512")) {
       *oid = 0x0b00000b;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_40/4_512")) {
       *oid = 0x0c00000c;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_40/8_512")) {
       *oid = 0x0d00000d;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_60/3_512")) {
       *oid = 0x0e00000e;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_60/6_512")) {
       *oid = 0x0f00000f;
    }
    else if (!strcmp(s, "XMSSMT-SHA2_60/12_512")) {
      *oid = 0x01010101;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_20/2_256")) {
      *oid = 0x02010102;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_20/4_256")) {
      *oid = 0x03010103;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_40/2_256")) {
      *oid = 0x04010104;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_40/4_256")) {
      *oid = 0x05010105;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_40/8_256")) {
      *oid = 0x06010106;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_60/3_256")) {
      *oid = 0x07010107;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_60/6_256")) {
      *oid = 0x08010108;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_60/12_256")) {
     *oid = 0x09010109;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_20/2_512")) {
      *oid = 0x0a01010a;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_20/4_512")) {
      *oid = 0x0b01010b;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_40/2_512")) {
      *oid = 0x0c01010c;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_40/4_512")) {
      *oid = 0x0d01010d;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_40/8_512")) {
      *oid = 0x0e01010e;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_60/3_512")) {
      *oid = 0x0f01010f;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_60/6_512")) {
      *oid = 0x01020201;
    }
    else if (!strcmp(s, "XMSSMT-SHAKE_60/12_512")) {
     *oid = 0x02020202;
    }
    else {
        return -1;
    }
    return 0;
}

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
    params->wots_len1 = 8 * params->n / params->wots_log_w;
    /* len_2 = floor(log(len_1 * (w - 1)) / log(w)) + 1 */
    params->wots_len2 = 3;
    params->wots_len = params->wots_len1 + params->wots_len2;
    params->wots_sig_bytes = params->wots_len * params->n;
    params->index_bytes = 4;
    params->sig_bytes = (params->index_bytes + params->n
                         + params->d * params->wots_sig_bytes
                         + params->full_height * params->n);
    params->pk_bytes = 2 * params->n;
    params->sk_bytes = xmss_core_sk_bytes(params);

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
    params->wots_len1 = 8 * params->n / params->wots_log_w;
    /* len_2 = floor(log(len_1 * (w - 1)) / log(w)) + 1 */
    params->wots_len2 = 3;
    params->wots_len = params->wots_len1 + params->wots_len2;
    params->wots_sig_bytes = params->wots_len * params->n;
    /* Round index_bytes up to nearest byte. */
    params->index_bytes = (params->full_height + 7) / 8;
    params->sig_bytes = (params->index_bytes + params->n
                         + params->d * params->wots_sig_bytes
                         + params->full_height * params->n);
    params->pk_bytes = 2 * params->n;
    params->sk_bytes = xmssmt_core_sk_bytes(params);

    // TODO figure out sensible and legal values for this based on the above
    params->bds_k = 0;
    return 0;
}
