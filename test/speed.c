#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"

#define XMSS_MLEN 32

#ifndef XMSS_SIGNATURES
    #define XMSS_SIGNATURES 16
#endif

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
#endif

#ifndef XMSS_VARIANT
    #ifdef XMSSMT
        #define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
    #else
        #define XMSS_VARIANT "XMSS-SHA2_10_256"
    #endif
#endif

static unsigned long long cpucycles(void)
{
  unsigned long long result;
//   __asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax"
//     : "=a" (result) ::  "%rdx");
  result = 0;
  return result;
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

int main()
{
    /* Make stdout buffer more responsive. */
    setbuf(stdout, NULL);

    xmss_params params;
    uint32_t oid;
    int ret = 0;
    int i;

    const char *variants[] = {
        "XMSS-SHA2_10_256",
        "XMSS-SHA2_16_256",
        "XMSS-SHA2_20_256",
        "XMSSMT-SHA2_20/2_256",
        "XMSSMT-SHA2_40/2_256",
        "XMSSMT-SHA2_60/3_256",
        };

    for (int var = 0; var < 6; var++)
    {
        const char *p = variants[var];

        // TODO test more different variants
        if (XMSS_STR_TO_OID(&oid, p)) {
    #ifdef XMSSMT
            printf("XMSSMT variant %s not recognized!\n", p);
    #else
            printf("XMSS variant %s not recognized!\n", p);
    #endif
            // return -1;
            continue;
        }
        XMSS_PARSE_OID(&params, oid);

        unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
        unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
        unsigned char *m = malloc(XMSS_MLEN);
        unsigned char *sm = malloc(params.sig_bytes + XMSS_MLEN);
        unsigned char *mout = malloc(params.sig_bytes + XMSS_MLEN);
        unsigned long long smlen;
        unsigned long long mlen;

        unsigned long long t0, t1;
        unsigned long long *t = malloc(sizeof(unsigned long long) * XMSS_SIGNATURES);
        struct timespec start, stop;
        double result;

        randombytes(m, XMSS_MLEN);

        printf("Benchmarking variant %s\n", p);

        printf("Generating keypair.. ");

        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
        t0 = cpucycles();
        XMSS_KEYPAIR(pk, sk, oid);
        t1 = cpucycles();
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
        result = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
        printf("took %lf us (%.2lf sec), %llu cycles\n", result, result / 1e6, t1 - t0);

        printf("Creating %d signatures..\n", XMSS_SIGNATURES);

        for (i = 0; i < XMSS_SIGNATURES; i++) {
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
            XMSS_SIGN(sk, sm, &smlen, m, XMSS_MLEN);
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
            t[i] = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
        }
        print_results(t, XMSS_SIGNATURES);

        printf("Verifying %d signatures..\n", XMSS_SIGNATURES);

        for (i = 0; i < XMSS_SIGNATURES; i++) {
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
            ret |= XMSS_SIGN_OPEN(mout, &mlen, sm, smlen, pk);
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);
            t[i] = (stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3;
        }
        print_results(t, XMSS_SIGNATURES);

        if (ret) {
            printf("DETECTED VERIFICATION ERRORS!\n");
        }

        printf("Signature size: %d (%.2f KiB)\n", params.sig_bytes, params.sig_bytes / 1024.0);
        printf("Public key size: %d (%.2f KiB)\n", params.pk_bytes, params.pk_bytes / 1024.0);
        printf("Secret key size: %llu (%.2f KiB)\n", params.sk_bytes, params.sk_bytes / 1024.0);

        free(m);
        free(sm);
        free(mout);
        free(t);
    }

    return ret;
}
