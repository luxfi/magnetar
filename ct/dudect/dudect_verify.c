/*
 * Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
 * See the file LICENSE for licensing terms.
 *
 * dudect_verify.c — dudect main loop driving magnetar.Verify through
 * the cgo bridge in verify_ct.go.
 *
 * Same valid-pool methodology as Pulsar's harness: both classes carry
 * VALID signatures (differing only in per-signing randomness, via
 * FIPS 205 §10.2 SignRandomized). Any timing difference dudect detects
 * is a real signature-content-dependent timing in Verify, not a
 * rejection-path artifact.
 *
 * dudect_compat.h is `-include`-d by the Makefile on AArch64 hosts;
 * on x86 it is a no-op.
 */

#define DUDECT_IMPLEMENTATION
#include "dudect/src/dudect.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Exported by libmagnetar_verify (verify_ct.go). */
extern int    magnetar_verify_ct_setup(void);
extern size_t magnetar_verify_ct_sig_size(void);
extern size_t magnetar_verify_ct_pool_size(void);
extern int    magnetar_verify_ct_copy_pool(size_t idx, uint8_t *dst);
extern void   magnetar_verify_ct(uint8_t *data);

static size_t g_chunk_size = 0;
static size_t g_pool_size  = 0;

/*
 * Populate input_data + classes for one batch. Both classes are
 * VALID signatures from the precomputed pool.
 *   class A: pool[0]              (Welch's t-test requires identical
 *                                   class-A inputs)
 *   class B: pool[rand % K_VALID] (uniformly-drawn valid sig)
 */
void prepare_inputs(dudect_config_t *cfg, uint8_t *input_data, uint8_t *classes) {
    for (size_t i = 0; i < cfg->number_measurements; i++) {
        classes[i] = randombit();
        uint8_t *slot = input_data + (size_t)i * cfg->chunk_size;
        if (classes[i] == 0) {
            (void)magnetar_verify_ct_copy_pool(0, slot);
        } else {
            uint8_t pick_buf[8];
            randombytes(pick_buf, sizeof pick_buf);
            uint64_t pick = 0;
            for (size_t k = 0; k < sizeof pick_buf; k++) {
                pick = (pick << 8) | pick_buf[k];
            }
            (void)magnetar_verify_ct_copy_pool((size_t)(pick % g_pool_size), slot);
        }
    }
}

uint8_t do_one_computation(uint8_t *data) {
    magnetar_verify_ct(data);
    uint8_t acc = 0;
    for (size_t i = 0; i < g_chunk_size; i++) acc ^= data[i];
    return acc;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    int rc = magnetar_verify_ct_setup();
    if (rc != 0) {
        fprintf(stderr, "magnetar_verify_ct_setup failed: rc=%d\n", rc);
        return 1;
    }
    g_chunk_size = magnetar_verify_ct_sig_size();
    if (g_chunk_size == 0) {
        fprintf(stderr, "magnetar_verify_ct_sig_size returned 0\n");
        return 1;
    }
    g_pool_size = magnetar_verify_ct_pool_size();
    if (g_pool_size == 0) {
        fprintf(stderr, "magnetar_verify_ct_pool_size returned 0\n");
        return 1;
    }

    /*
     * SMOKE-TEST default (10 000 samples per batch). The full NIST
     * submission run uses ~10^9 samples on a quiet, CPU-pinned host.
     */
    size_t number_measurements = 10000;
    const char *env_n = getenv("DUDECT_SAMPLES");
    if (env_n) {
        long n = strtol(env_n, NULL, 10);
        if (n > 0) number_measurements = (size_t)n;
    }
    size_t max_batches = 4;
    const char *env_b = getenv("DUDECT_MAX_BATCHES");
    if (env_b) {
        long b = strtol(env_b, NULL, 10);
        if (b > 0) max_batches = (size_t)b;
    }

    dudect_config_t cfg = {
        .chunk_size = g_chunk_size,
        .number_measurements = number_measurements,
    };
    dudect_ctx_t ctx;
    if (dudect_init(&ctx, &cfg) != 0) {
        fprintf(stderr, "dudect_init failed\n");
        return 1;
    }

    fprintf(stderr, "dudect_verify: SLH-DSA-SHAKE-192s, chunk=%zu bytes, batch=%zu samples, max_batches=%zu, pool=%zu valid sigs\n",
            g_chunk_size, number_measurements, max_batches, g_pool_size);

    dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    for (size_t batch = 0; batch < max_batches; batch++) {
        state = dudect_main(&ctx);
        if (state == DUDECT_LEAKAGE_FOUND) break;
    }
    dudect_free(&ctx);

    if (state == DUDECT_LEAKAGE_FOUND) {
        fprintf(stderr, "dudect_verify: LEAKAGE FOUND (t-statistic exceeded threshold)\n");
        return 2;
    }
    fprintf(stderr, "dudect_verify: no leakage evidence after %zu batches of %zu samples\n",
            max_batches, number_measurements);
    return 0;
}
