/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2011-2014 pooler
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include "miner.h"

static const uint32_t keypad[12] = {
        0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000280
};
static const uint32_t innerpad[11] = {
        0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x000004a0
};
static const uint32_t outerpad[8] = {
        0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300
};
static const uint32_t finalblk[16] = {
        0x00000001, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000620
};

static inline void HMAC_SHA256_80_init(const uint32_t *key, uint32_t *tstate, uint32_t *ostate) {
    uint32_t ihash[8];
    uint32_t pad[16];
    int i;

    /* tstate is assumed to contain the midstate of key */
    memcpy(pad, key + 16, 16);
    memcpy(pad + 4, keypad, 48);
    sha256_transform(tstate, pad, 0);
    memcpy(ihash, tstate, 32);

    sha256_init(ostate);
    for (i = 0; i < 8; i++)
        pad[i] = ihash[i] ^ 0x5c5c5c5c;
    for (; i < 16; i++)
        pad[i] = 0x5c5c5c5c;
    sha256_transform(ostate, pad, 0);

    sha256_init(tstate);
    for (i = 0; i < 8; i++)
        pad[i] = ihash[i] ^ 0x36363636;
    for (; i < 16; i++)
        pad[i] = 0x36363636;
    sha256_transform(tstate, pad, 0);
}

static inline void PBKDF2_SHA256_80_128(const uint32_t *tstate,
                                        const uint32_t *ostate, const uint32_t *salt, uint32_t *output) {
    uint32_t istate[8], ostate2[8];
    uint32_t ibuf[16], obuf[16];
    int i, j;

    memcpy(istate, tstate, 32);
    sha256_transform(istate, salt, 0);

    memcpy(ibuf, salt + 16, 16);
    memcpy(ibuf + 5, innerpad, 44);
    memcpy(obuf + 8, outerpad, 32);

    for (i = 0; i < 4; i++) {
        memcpy(obuf, istate, 32);
        ibuf[4] = (uint32_t) (i + 1);
        sha256_transform(obuf, ibuf, 0);

        memcpy(ostate2, ostate, 32);
        sha256_transform(ostate2, obuf, 0);
        for (j = 0; j < 8; j++)
            output[8 * i + j] = swab32(ostate2[j]);
    }
}

static inline void PBKDF2_SHA256_128_32(uint32_t *tstate, uint32_t *ostate, const uint32_t *salt, uint32_t *output) {
    uint32_t buf[16];
    int i;

    sha256_transform(tstate, salt, 1);
    sha256_transform(tstate, salt + 16, 1);
    sha256_transform(tstate, finalblk, 0);
    memcpy(buf, tstate, 32);
    memcpy(buf + 8, outerpad, 32);

    sha256_transform(ostate, buf, 0);
    for (i = 0; i < 8; i++)
        output[i] = swab32(ostate[i]);
}

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16]) {
    uint32_t x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11, x12, x13, x14, x15;
    int i;

    x00 = (B[0] ^= Bx[0]);
    x01 = (B[1] ^= Bx[1]);
    x02 = (B[2] ^= Bx[2]);
    x03 = (B[3] ^= Bx[3]);
    x04 = (B[4] ^= Bx[4]);
    x05 = (B[5] ^= Bx[5]);
    x06 = (B[6] ^= Bx[6]);
    x07 = (B[7] ^= Bx[7]);
    x08 = (B[8] ^= Bx[8]);
    x09 = (B[9] ^= Bx[9]);
    x10 = (B[10] ^= Bx[10]);
    x11 = (B[11] ^= Bx[11]);
    x12 = (B[12] ^= Bx[12]);
    x13 = (B[13] ^= Bx[13]);
    x14 = (B[14] ^= Bx[14]);
    x15 = (B[15] ^= Bx[15]);
    for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
        /* Operate on columns. */
        x04 ^= R(x00 + x12, 7);
        x09 ^= R(x05 + x01, 7);
        x14 ^= R(x10 + x06, 7);
        x03 ^= R(x15 + x11, 7);

        x08 ^= R(x04 + x00, 9);
        x13 ^= R(x09 + x05, 9);
        x02 ^= R(x14 + x10, 9);
        x07 ^= R(x03 + x15, 9);

        x12 ^= R(x08 + x04, 13);
        x01 ^= R(x13 + x09, 13);
        x06 ^= R(x02 + x14, 13);
        x11 ^= R(x07 + x03, 13);

        x00 ^= R(x12 + x08, 18);
        x05 ^= R(x01 + x13, 18);
        x10 ^= R(x06 + x02, 18);
        x15 ^= R(x11 + x07, 18);

        /* Operate on rows. */
        x01 ^= R(x00 + x03, 7);
        x06 ^= R(x05 + x04, 7);
        x11 ^= R(x10 + x09, 7);
        x12 ^= R(x15 + x14, 7);

        x02 ^= R(x01 + x00, 9);
        x07 ^= R(x06 + x05, 9);
        x08 ^= R(x11 + x10, 9);
        x13 ^= R(x12 + x15, 9);

        x03 ^= R(x02 + x01, 13);
        x04 ^= R(x07 + x06, 13);
        x09 ^= R(x08 + x11, 13);
        x14 ^= R(x13 + x12, 13);

        x00 ^= R(x03 + x02, 18);
        x05 ^= R(x04 + x07, 18);
        x10 ^= R(x09 + x08, 18);
        x15 ^= R(x14 + x13, 18);
#undef R
    }
    B[0] += x00;
    B[1] += x01;
    B[2] += x02;
    B[3] += x03;
    B[4] += x04;
    B[5] += x05;
    B[6] += x06;
    B[7] += x07;
    B[8] += x08;
    B[9] += x09;
    B[10] += x10;
    B[11] += x11;
    B[12] += x12;
    B[13] += x13;
    B[14] += x14;
    B[15] += x15;
}

static inline void scrypt_core(uint32_t *X, uint32_t *V, int N) {
    int i;

    for (i = 0; i < N; i++) {
        memcpy(&V[i * 32], X, 128);
        xor_salsa8(&X[0], &X[16]);
        xor_salsa8(&X[16], &X[0]);
    }
    for (i = 0; i < N; i++) {
        uint32_t j = 32 * (X[16] & (N - 1));
        for (uint8_t k = 0; k < 32; k++)
            X[k] ^= V[j + k];
        xor_salsa8(&X[0], &X[16]);
        xor_salsa8(&X[16], &X[0]);
    }
}

unsigned char *scrypt_buffer_alloc(int N) {
    return (uchar *) malloc((size_t) N * 128 + 63);
}

static void scrypt_1024_1_1_256(const uint32_t *input, uint32_t *output, uint32_t *midstate, unsigned char *scratchpad) {
    uint32_t tstate[8], ostate[8];
    uint32_t X[32];
    uint32_t *V;
    applog(LOG_DEBUG, "input:%s", abin2hex((uint8_t *) input, 80));
    V = (uint32_t *) (((uintptr_t) (scratchpad) + 63) & ~(uintptr_t) (63));

    memcpy(tstate, midstate, 32);
    HMAC_SHA256_80_init(input, tstate, ostate);
    applog(LOG_DEBUG, "HMAC_SHA256_80_init:");
    applog(LOG_DEBUG, "tstate:%s", abin2hex((uint8_t *) tstate, 32));
    applog(LOG_DEBUG, "ostate:%s", abin2hex((uint8_t *) ostate, 32));

    PBKDF2_SHA256_80_128(tstate, ostate, input, X);
    applog(LOG_DEBUG, "PBKDF2_SHA256_80_128:");
    applog(LOG_DEBUG, "tstate:%s", abin2hex((uint8_t *) tstate, 32));
    applog(LOG_DEBUG, "ostate:%s", abin2hex((uint8_t *) ostate, 32));
    applog(LOG_DEBUG, "X:%s", abin2hex((uint8_t *) X, 128));

    scrypt_core(X, V, 1024);
    applog(LOG_DEBUG, "scrypt_core:");
    applog(LOG_DEBUG, "X(slat):%s", abin2hex((uint8_t *) X, 128));

    PBKDF2_SHA256_128_32(tstate, ostate, X, output);
    applog(LOG_DEBUG, "PBKDF2_SHA256_128_32:");
    applog(LOG_DEBUG, "tstate:%s", abin2hex((uint8_t *) tstate, 32));
    applog(LOG_DEBUG, "ostate:%s", abin2hex((uint8_t *) ostate, 32));
    applog(LOG_DEBUG, "output:%s", abin2hex((uint8_t *) output, 32));
    
}

extern int scanhash_scrypt(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done) {
    unsigned char *scratchbuf = scrypt_buffer_alloc(1024);
    if (!scratchbuf) {
        applog(LOG_ERR, "scrypt buffer allocation failed");
        pthread_mutex_lock(&applog_lock);
        exit(1);
    }
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t data[20], hash[8];
    uint32_t midstate[8];
    uint32_t n = pdata[19] - 1;
    const uint32_t Htarg = ptarget[7];

    memcpy(data, pdata, 80);
    sha256_init(midstate);
    sha256_transform(midstate, data, 0);

    do {
        data[19] = ++n;
        scrypt_1024_1_1_256(data, hash, midstate, scratchbuf);
        if (unlikely(hash[7] <= Htarg && fulltest(hash, ptarget))) {
            work_set_target_ratio(work, hash);
            *hashes_done = n - pdata[19] + 1;
            pdata[19] = data[19];
            return 1;
        }
    } while (likely(n <= max_nonce && !work_restart[thr_id].restart));

    *hashes_done = n - pdata[19] + 1;
    pdata[19] = n;
    free(scratchbuf);
    return 0;
}

/* simple cpu test (util.c) */
void scrypt_hash(void *output, const void *input) {
    uint32_t midstate[8];
    unsigned char *scratchbuf = scrypt_buffer_alloc(1024);
    memset(output, 0, 32);
    if (!scratchbuf)
        return;
    sha256_init(midstate);
    sha256_transform(midstate, input, 0);
    scrypt_1024_1_1_256((uint32_t *) input, (uint32_t *) output, midstate, scratchbuf);
    free(scratchbuf);
}