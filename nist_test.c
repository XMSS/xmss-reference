#include "api.h"
#include "nist_params.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "xmss.h"

#define XMSS_SIGNATURES 64

unsigned long long t[XMSS_SIGNATURES];

#if DEBUG
static void print_hex(const unsigned char *a, int length, const char *string)
{
    printf("%s[%d] = \n", string, length);
    for (int i = 0; i < length; i++)
    {
        printf("%02x", a[i]);
    }
    printf("\n");
}
#endif

static int cmp_llu(const void *a, const void *b)
{
    if (*(unsigned long long *)a < *(unsigned long long *)b)
        return -1;
    if (*(unsigned long long *)a > *(unsigned long long *)b)
        return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);

    if (llen % 2)
        return l[llen / 2];
    else
        return (l[llen / 2 - 1] + l[llen / 2]) / 2;
}

static unsigned long long average(unsigned long long *t, size_t tlen)
{
    unsigned long long acc = 0;
    size_t i;
    for (i = 0; i < tlen; i++)
    {
        acc += t[i];
    }
    return acc / (tlen);
}

static void print_results(unsigned long long *t, size_t tlen)
{
    size_t i;
    for (i = 0; i < tlen - 1; i++)
    {
        t[i] = t[i + 1] - t[i];
    }
    printf("\tmedian        : %llu us\n", median(t, tlen));
    printf("\taverage       : %llu us\n", average(t, tlen - 1));
    printf("\n");
}

/*
 * Test keygen
 */
int test_keygen(unsigned char *pk, unsigned char *sk)
{
    struct timespec start, stop;
    int ret;
    double result;

    printf("Generating keypair.. %s\n", XMSS_OID);

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    ret = crypto_sign_keypair(pk, sk);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

    result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
    printf("took %lf us (%.2lf sec)\n", result, result / 1e6);

    return ret;
}

/*
 * Test Sign
 */
int test_sign(unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen, unsigned char *sk)
{
    struct timespec start, stop;
    int ret;

    printf("Creating %d signatures..\n", XMSS_SIGNATURES);
    for (int i = 0; i < XMSS_SIGNATURES; i++)
    {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        ret = crypto_sign(sm, smlen, m, mlen, sk);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

        t[i] = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;

        if (*smlen != CRYPTO_BYTES + mlen)
        {
            printf("  X smlen incorrect [%llu != %llu]!\n", *smlen, CRYPTO_BYTES + mlen);
            break;
        }
        if (ret)
        {
            break;
        }
    }
    print_results(t, XMSS_SIGNATURES);

    return ret;
}

/*
 * Test Verify
 */
int test_verify(unsigned char *mout, unsigned long long *moutlen,
                const unsigned char *sm, unsigned long long smlen, const unsigned char *pk,
                unsigned char *m, const unsigned long long mlen)
{
    struct timespec start, stop;
    int ret;

    printf("Verifying %d signatures..\n", XMSS_SIGNATURES);
    for (int i = 0; i < XMSS_SIGNATURES; i++)
    {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        ret = crypto_sign_open(mout, moutlen, sm, smlen, pk);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

        t[i] = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;

        if (*moutlen != mlen)
        {
            printf("  X mlen incorrect [%llu != %llu]!\n", *moutlen, mlen);
            ret = -1;
            break;
        }

        if (memcmp(mout, m, mlen))
        {
            printf("  mout incorrect [%s != %s]\n", mout, m);
            ret = -1;
            break;
        }

        if (ret)
        {
            break;
        }
    }
    print_results(t, XMSS_SIGNATURES);

    return ret;
}

/* 
 * Testing remaining signatures
 */
int test_remain(unsigned char *sk)
{
    unsigned long long remain = 0, max = 0;
    int ret;
    ret = crypto_remain_signatures(&remain, &max, sk);

    printf("used = %lld, remain = %lld, max = %lld\n", max - remain, remain, max);

    // Incorrect count;
    if (max - remain != XMSS_SIGNATURES)
    {
        printf("    Incorrect used signatures\n");
        return 1;
    }

    return ret;
}

int main(void)
{
    // Keygen test
    int ret;
    unsigned char pk[CRYPTO_PUBLIC_KEY], sk[CRYPTO_SECRET_KEY];
    unsigned long long smlen, mlen, mlen_out;

    // Signature test
    unsigned char m[] = "\nThis is a test from SandboxAQ\n";
    mlen = sizeof(m);
    // Verify test
    unsigned char *sm = malloc(CRYPTO_BYTES + mlen);
    unsigned char *mout = malloc(CRYPTO_BYTES + mlen);

    ret = test_keygen(pk, sk);

    if (ret)
    {
        printf("    Unable to generate keypair\n");
        return 1;
    }

#if DEBUG
    print_hex(pk, CRYPTO_PUBLIC_KEY, "pk");
    print_hex(sk, CRYPTO_SECRET_KEY, "sk");
#endif

    ret |= test_sign(sm, &smlen, m, mlen, sk);

    if (ret)
    {
        printf("    Unable to generate signature\n");
        return 1;
    }

#if DEBUG
    print_hex(m, mlen, "message");
    print_hex(sm, smlen, "signature");
#endif

    ret |= test_verify(mout, &mlen_out, sm, smlen, pk, m, mlen);

    if (ret)
    {
        printf("    Unable to verify signature\n");
        return 1;
    }

    ret |= test_remain(sk);

    if (ret)
    {
        printf("    Unable to check remaining signature\n");
        return 1;
    }

    free(sm);
    free(mout);

    return 0;
}
