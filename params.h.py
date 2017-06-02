#! /usr/bin/env python3

# This script generates params.h files for the XMSS and XMSSMT parameter sets.
# It takes a single parameter, namely the name of the parameter set.
# Its output matches the following parameter tables.

# +-----------------------+-----------+----+----+-----+----+
# | Name                  | Functions | n  | w  | len | h  |
# +-----------------------+-----------+----+----+-----+----+
# | REQUIRED:             |           |    |    |     |    |
# |                       |           |    |    |     |    |
# | XMSS_SHA2-256_W16_H10 | SHA2-256  | 32 | 16 | 67  | 10 |
# |                       |           |    |    |     |    |
# | XMSS_SHA2-256_W16_H16 | SHA2-256  | 32 | 16 | 67  | 16 |
# |                       |           |    |    |     |    |
# | XMSS_SHA2-256_W16_H20 | SHA2-256  | 32 | 16 | 67  | 20 |
# |                       |           |    |    |     |    |
# | OPTIONAL:             |           |    |    |     |    |
# |                       |           |    |    |     |    |
# | XMSS_SHA2-512_W16_H10 | SHA2-512  | 64 | 16 | 131 | 10 |
# |                       |           |    |    |     |    |
# | XMSS_SHA2-512_W16_H16 | SHA2-512  | 64 | 16 | 131 | 16 |
# |                       |           |    |    |     |    |
# | XMSS_SHA2-512_W16_H20 | SHA2-512  | 64 | 16 | 131 | 20 |
# |                       |           |    |    |     |    |
# | XMSS_SHAKE128_W16_H10 | SHAKE128  | 32 | 16 | 67  | 10 |
# |                       |           |    |    |     |    |
# | XMSS_SHAKE128_W16_H16 | SHAKE128  | 32 | 16 | 67  | 16 |
# |                       |           |    |    |     |    |
# | XMSS_SHAKE128_W16_H20 | SHAKE128  | 32 | 16 | 67  | 20 |
# |                       |           |    |    |     |    |
# | XMSS_SHAKE256_W16_H10 | SHAKE256  | 64 | 16 | 131 | 10 |
# |                       |           |    |    |     |    |
# | XMSS_SHAKE256_W16_H16 | SHAKE256  | 64 | 16 | 131 | 16 |
# |                       |           |    |    |     |    |
# | XMSS_SHAKE256_W16_H20 | SHAKE256  | 64 | 16 | 131 | 20 |
# +-----------------------+-----------+----+----+-----+----+

# +-----------------------------+-----------+----+----+-----+----+----+
# | Name                        | Functions | n  | w  | len | h  | d  |
# +-----------------------------+-----------+----+----+-----+----+----+
# | REQUIRED:                   |           |    |    |     |    |    |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-256_W16_H20_D2  | SHA2-256  | 32 | 16 | 67  | 20 | 2  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-256_W16_H20_D4  | SHA2-256  | 32 | 16 | 67  | 20 | 4  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-256_W16_H40_D2  | SHA2-256  | 32 | 16 | 67  | 40 | 2  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-256_W16_H40_D4  | SHA2-256  | 32 | 16 | 67  | 40 | 4  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-256_W16_H40_D8  | SHA2-256  | 32 | 16 | 67  | 40 | 8  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-256_W16_H60_D3  | SHA2-256  | 32 | 16 | 67  | 60 | 3  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-256_W16_H60_D6  | SHA2-256  | 32 | 16 | 67  | 60 | 6  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-256_W16_H60_D12 | SHA2-256  | 32 | 16 | 67  | 60 | 12 |
# |                             |           |    |    |     |    |    |
# | OPTIONAL:                   |           |    |    |     |    |    |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-512_W16_H20_D2  | SHA2-512  | 64 | 16 | 131 | 20 | 2  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-512_W16_H20_D4  | SHA2-512  | 64 | 16 | 131 | 20 | 4  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-512_W16_H40_D2  | SHA2-512  | 64 | 16 | 131 | 40 | 2  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-512_W16_H40_D4  | SHA2-512  | 64 | 16 | 131 | 40 | 4  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-512_W16_H40_D8  | SHA2-512  | 64 | 16 | 131 | 40 | 8  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-512_W16_H60_D3  | SHA2-512  | 64 | 16 | 131 | 60 | 3  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-512_W16_H60_D6  | SHA2-512  | 64 | 16 | 131 | 60 | 6  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHA2-512_W16_H60_D12 | SHA2-512  | 64 | 16 | 131 | 60 | 12 |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE128_W16_H20_D2  | SHAKE128  | 32 | 16 | 67  | 20 | 2  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE128_W16_H20_D4  | SHAKE128  | 32 | 16 | 67  | 20 | 4  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE128_W16_H40_D2  | SHAKE128  | 32 | 16 | 67  | 40 | 2  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE128_W16_H40_D4  | SHAKE128  | 32 | 16 | 67  | 40 | 4  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE128_W16_H40_D8  | SHAKE128  | 32 | 16 | 67  | 40 | 8  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE128_W16_H60_D3  | SHAKE128  | 32 | 16 | 67  | 60 | 3  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE128_W16_H60_D6  | SHAKE128  | 32 | 16 | 67  | 60 | 6  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE128_W16_H60_D12 | SHAKE128  | 32 | 16 | 67  | 60 | 12 |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE256_W16_H20_D2  | SHAKE256  | 64 | 16 | 131 | 20 | 2  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE256_W16_H20_D4  | SHAKE256  | 64 | 16 | 131 | 20 | 4  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE256_W16_H40_D2  | SHAKE256  | 64 | 16 | 131 | 40 | 2  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE256_W16_H40_D4  | SHAKE256  | 64 | 16 | 131 | 40 | 4  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE256_W16_H40_D8  | SHAKE256  | 64 | 16 | 131 | 40 | 8  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE256_W16_H60_D3  | SHAKE256  | 64 | 16 | 131 | 60 | 3  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE256_W16_H60_D6  | SHAKE256  | 64 | 16 | 131 | 60 | 6  |
# |                             |           |    |    |     |    |    |
# | XMSSMT_SHAKE256_W16_H60_D12 | SHAKE256  | 64 | 16 | 131 | 60 | 12 |
# +-----------------------------+-----------+----+----+-----+----+----+

import sys
from math import log2, ceil, floor

if len(sys.argv) != 2:
    print("Please supply a parameter identifier.", file=sys.stderr)
    sys.exit(1)

param = sys.argv[1].split('_')

print("#ifndef PARAMS_H")
print("#define PARAMS_H")
print("")
print("// This file was automatically generated using params.h.py.")
print("// It matches the parameter set defined as", sys.argv[1], end=".\n")

functions = ["SHA2-256", "SHA2-512", "SHAKE128", "SHAKE256"]
nvalues = {
    "SHA2-256": 32,
    "SHA2-512": 64,
    "SHAKE128": 32,
    "SHAKE256": 64,
}

for i, func in enumerate(functions):
    print("#define XMSS_{} {}".format(func.replace('-', '_'), i))
print("#define XMSS_FUNC", functions.index(param[1]))

XMSS_N = int(nvalues[param[1]])
print("#define XMSS_N", XMSS_N)
XMSS_WOTS_W = int(param[2][1:])
print("#define XMSS_WOTS_W", XMSS_WOTS_W)
WOTS_LOG_W = int(log2(int(param[2][1:])))
WOTS_LEN1 = ceil(((8*XMSS_N) / WOTS_LOG_W))
WOTS_LEN2 = floor(log2(WOTS_LEN1*(XMSS_WOTS_W-1)) / WOTS_LOG_W) + 1
print("#define XMSS_WOTS_LOG_W", WOTS_LOG_W)
print("#define XMSS_WOTS_LEN1", WOTS_LEN1)
print("#define XMSS_WOTS_LEN2", WOTS_LEN2)
print("#define XMSS_WOTS_LEN", WOTS_LEN1 + WOTS_LEN2)
WOTS_KEYSIZE = (WOTS_LEN1 + WOTS_LEN2) * XMSS_N
print("#define XMSS_WOTS_KEYSIZE", WOTS_KEYSIZE)
XMSS_H = int(param[3][1:])
print("#define XMSS_FULLHEIGHT", XMSS_H)
if param[0] == 'XMSSMT':
    XMSS_D = int(param[4][1:])
    XMSS_INDEX_LEN = floor((XMSS_H + 7) / 8)
else:
    XMSS_INDEX_LEN = 4  # TODO fix this in the xmss code
    XMSS_D = 1
if int(param[3][1:]) % XMSS_D != 0:
    print("Make sure that d divides h!", file=sys.stderr)
    sys.exit(1)
print("#define XMSS_TREEHEIGHT", XMSS_H // XMSS_D)
print("#define XMSS_D", XMSS_D)
print("#define XMSS_INDEX_LEN", XMSS_INDEX_LEN)
XMSS_BYTES = XMSS_INDEX_LEN + XMSS_N + XMSS_D*WOTS_KEYSIZE + XMSS_H*XMSS_N;
print("#define XMSS_BYTES", XMSS_BYTES)
print("#define XMSS_PUBLICKEY_BYTES", 2*XMSS_N)
print("#define XMSS_PRIVATEKEY_BYTES", 4*XMSS_N + XMSS_INDEX_LEN)

print("#define XMSS_BDS_K", 2 + ((XMSS_H // XMSS_D) % 2))  # TODO figure out what we should do here

print("#endif")
