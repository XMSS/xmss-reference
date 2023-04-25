/*=============================================================================
 * Copyright (c) 2022 by SandboxAQ Inc
 * Author: Duc Tri Nguyen
 * SPDX-License-Identifier: MIT
=============================================================================*/
#include <oqs/common.h>
#include <oqs/rand.h>

int runonce(void)
{
    unsigned char buf[48] = {0};
    OQS_randombytes(buf, 48);

    /* Using AES as random generator */
    if (OQS_randombytes_switch_algorithm("NIST-KAT") != OQS_SUCCESS)
    {
        return OQS_ERROR;
    }

    /* Initialize NIST KAT, this time it reads from /dev/urandom */
    OQS_randombytes_nist_kat_init_256bit(buf, NULL);
    return OQS_SUCCESS;
}

void randombytes(unsigned char *x, unsigned long long xlen)
{
    static int initialized = 0;
    if (!initialized)
    {
        if (runonce() == OQS_SUCCESS)
        {
            initialized = 1;
        }
    }
    OQS_randombytes(x, xlen);
}
