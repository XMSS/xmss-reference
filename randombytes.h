/*=============================================================================
 * Copyright (c) 2022 by SandboxAQ Inc
 * Author: Duc Tri Nguyen
 * SPDX-License-Identifier: MIT
=============================================================================*/
#ifndef XMSS_RANDOMBYTES_H
#define XMSS_RANDOMBYTES_H

/*
 * Tries to read xlen bytes from a source of randomness, and writes them to x.
 */
void randombytes(unsigned char *x, unsigned long long xlen);

#endif
