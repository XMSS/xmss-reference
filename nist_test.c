#include "api.h"
#include "nist_params.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static void print_hex(const unsigned char *a, int length, const char *string)
{
    printf("%s[%d] = \n", string, length);
    for (int i = 0; i < length; i++)
    {
        printf("%02x", a[i]);
    }
    printf("\n");
}

static int cmp_llu(const void *a, const void*b)
{
    if (*(unsigned long long *)a < *(unsigned long long *)b) return -1;
    if (*(unsigned long long *)a > *(unsigned long long *)b) return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);

    if (llen % 2) return l[llen / 2];
    else return (l[llen/2 - 1] + l[llen/2]) / 2;
}

static unsigned long long average(unsigned long long *t, size_t tlen)
{
    unsigned long long acc=0;
    size_t i;
    for(i = 0; i < tlen; i++) {
        acc += t[i];
    }
    return acc/(tlen);
}

static void print_results(unsigned long long *t, size_t tlen)
{
  size_t i;
  for (i = 0; i < tlen-1; i++) {
    t[i] = t[i+1] - t[i];
  }
  printf("\tmedian        : %llu us\n", median(t, tlen));
  printf("\taverage       : %llu us\n", average(t, tlen-1));
  printf("\n");
}


#define XMSS_SIGNATURES 32

int main(void)
{
    // Keygen test
    int ret;
    unsigned char pk[CRYPTO_PUBLIC_KEY], sk[CRYPTO_SECRET_KEY], sig[CRYPTO_BYTES];
    unsigned long pklen = CRYPTO_PUBLIC_KEY, sklen = CRYPTO_SECRET_KEY, siglen = 0, mlen = 0;
    unsigned long long *t = malloc(sizeof(unsigned long long) * XMSS_SIGNATURES);
    double result;
    struct timespec start, stop;

    printf("Generating keypair.. ");
    
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
    ret = crypto_sign_keypair(pk, sk);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

    result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
    printf("took %lf us (%.2lf sec)\n", result, result/1e6);

    if (ret)
    {
        printf("    Unable to generate keypair\n");
        return 1;
    }
#if DEBUG
    print_hex(pk, pklen, "pk");
    print_hex(sk, sklen, "sk");
#endif
    // Signature test
    unsigned char m[] = "\nThis is a test from SandboxAQ\n";
    mlen = sizeof(m);

    printf("Creating %d signatures..\n", XMSS_SIGNATURES/2);
    for (int i = 0; i < XMSS_SIGNATURES/2; i++)
    {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        ret = crypto_sign(sig, &siglen, m, mlen, sk);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

        t[i] = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;

        if (ret)
        {
            printf("    Unable to generate signature\n");
            return 1;
        }
    }
    print_results(t, XMSS_SIGNATURES/2);
    printf("siglen = %ld, mlen = %ld\n", siglen, mlen);

#if DEBUG
    print_hex(m, mlen, "message");
    print_hex(sig, siglen, "signature");
#endif
    printf("Verifying %d signatures..\n", XMSS_SIGNATURES);
    // Verification test
    for (int i = 0; i < XMSS_SIGNATURES; i++)
    {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        ret = crypto_sign_open(m, &mlen, sig, siglen, pk);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

        t[i] = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;

        if (ret)
        {
            printf("    Signature NOT verified\n");
            return 1;
        }
    }
    print_results(t, XMSS_SIGNATURES);

    // print_hex(sk, sklen, "sk");
    printf("siglen = %ld, mlen = %ld\n", siglen, mlen);

    // Remaining signature test
    unsigned long remain = 0, max = 0;
    ret = crypto_remain_signatures(&remain, &max, sk);

    if (ret)
    {
        printf("    Unable to check remaining signature\n");
        return 1;
    }

    printf("used = %ld, remain = %ld, max = %ld\n", max - remain, remain, max);

    // Incorrect count;
    if (max - remain != XMSS_SIGNATURES/2)
    {
        printf("    Incorrect used signatures\n");
        return 1;
    }

    return 0;
}