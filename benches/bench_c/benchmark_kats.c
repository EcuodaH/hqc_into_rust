#define _DEFAULT_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "api.h"
#include "symmetric.h"

#define N_KATS 100

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static long rss_kb(void) {
    long rss = 0;
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%ld", &rss);
            break;
        }
    }
    fclose(f);
    return rss;
}

static long hwm_kb(void) {
    long hwm = 0;
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmHWM:", 6) == 0) {
            sscanf(line + 6, "%ld", &hwm);
            break;
        }
    }
    fclose(f);
    return hwm;
}

int main(void) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss_enc[CRYPTO_BYTES];
    unsigned char ss_dec[CRYPTO_BYTES];

    /* Graine initiale identique au générateur KAT NIST */
    unsigned char entropy[48] = {0};
    for (int i = 0; i < 48; i++) entropy[i] = (unsigned char)i;
    prng_init(entropy, NULL, 48, 0);

    printf("keypair_ns enc_ns dec_ns keypair_rss_kb enc_rss_kb dec_rss_kb\n");

    for (int i = 0; i < N_KATS; i++) {
        uint64_t t0, t1;
        long r0, r1;

        r0 = rss_kb();
        t0 = now_ns();
        crypto_kem_keypair(pk, sk);
        t1 = now_ns();
        r1 = rss_kb();
        uint64_t kp_ns = t1 - t0;
        long kp_rss = r1 - r0;

        r0 = rss_kb();
        t0 = now_ns();
        crypto_kem_enc(ct, ss_enc, pk);
        t1 = now_ns();
        r1 = rss_kb();
        uint64_t enc_ns = t1 - t0;
        long enc_rss = r1 - r0;

        r0 = rss_kb();
        t0 = now_ns();
        crypto_kem_dec(ss_dec, ct, sk);
        t1 = now_ns();
        r1 = rss_kb();
        uint64_t dec_ns = t1 - t0;
        long dec_rss = r1 - r0;

        if (memcmp(ss_enc, ss_dec, CRYPTO_BYTES) != 0) {
            fprintf(stderr, "KAT %d : decapsulation mismatch\n", i);
            return 1;
        }

        printf("%llu %llu %llu %ld %ld %ld\n",
               (unsigned long long)kp_ns,
               (unsigned long long)enc_ns,
               (unsigned long long)dec_ns,
               kp_rss, enc_rss, dec_rss);
    }

    fprintf(stderr, "peak_hwm_kb %ld\n", hwm_kb());
    return 0;
}
