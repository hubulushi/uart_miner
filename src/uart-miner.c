/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 Lucas Jones
 * Copyright 2014 Tanguy Pruvot
 * Copyright 2017 Sequencer
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <curl/curl.h>
#include <jansson.h>
#include <getopt.h>
#include "miner.h"

#define LP_SCANTIME        60

#ifndef min
#define min(a, b) (a>b ? b : a)
#endif

enum workio_commands {
    WC_GET_WORK,
    WC_SUBMIT_WORK,
};

struct workio_cmd {
    enum workio_commands cmd;
    struct thr_info *thr;
    union {
        work_t *work;
    } u;
};

bool opt_debug = true;
bool opt_serial_debug = false;
bool opt_stratum_debug = false;
bool opt_uart = false;
bool opt_test = false;
int opt_maxlograte = 5;
long opt_proxy_type;
bool opt_redirect = true;
bool opt_stratum_stats = false;
static int opt_retries = -1;
static uint8_t opt_fail_pause = 10;
int opt_timeout = 300;
enum algos opt_algo;
long nonce_cnt = 1;
char *rpc_url;
char *rpc_userpass;
char *rpc_user, *rpc_pass;
char *cmd_path, *nonce_path;
uint8_t *test_data;
uint8_t *test_target;
uint32_t cmd_speed, nonce_speed;
uint8_t opt_cycle = 78;
char *short_url = NULL;
char *opt_cert;
char *opt_proxy;
struct thr_info *thr_info;
struct work_restart *work_restart = NULL;
struct stratum_ctx stratum;
pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
pthread_mutex_t rpc2_job_lock;
pthread_mutex_t rpc2_login_lock;
uint8_t need_restart = 0;
uint32_t accepted_count = 0L;
uint32_t rejected_count = 0L;
double *thr_hashrates;
uint64_t global_hashrate = 0;
double stratum_diff = 0.;
double net_diff = 0.;
// conditional mining
bool jsonrpc_2 = false;
char rpc2_id[64] = "";
char *rpc2_blob = NULL;
size_t rpc2_bloblen = 0;
uint32_t rpc2_target = 0;
char *rpc2_job_id = NULL;

static char const usage[] = ""
        "[USAGE] " PACKAGE_NAME " config_file(url or path)\n"
        "sample config path:\n"
        "{\n"
        "    \"algo\":\"xmr\",\n"
        "    \"cert\":\"./demo.crt\"\n"
        "    \"url\":\"stratum+tcp://path.to.poll\",\n"
        "    \"userpass\":\"user:pass\",\n"
        "    \"cmd-path\":\"path:baudrate\",\n"
        "    \"nonce-path\":\"path:baudrate\",\n"
        "    \"test_data\":\"0606abd0afce05d0dee05fac0f65305a345a72a5cc39ed588293e8c86ae50f61f11fad4abd0b435700000097c78deccf06247dfec13065cfb51cb395455c39fbc742f65aafed045b70117b08\",\n"
        "    \"test_target\":\"ffffffffffffff00\",\n"
        "    \"debug\":true,\n"
        "    \"serial_debug\":true,\n"
        "    \"stratum_debug\":true\n"
        "}\n";


static struct option const options[] = {
        {"algo",          1, NULL, 1000},

        {"cmd-path",      1, NULL, 1002},
        {"nonce-path",    1, NULL, 1003},
        {"chip_cycle",    1, NULL, 1004},

        {"test_target",   1, NULL, 1005},
        {"test_data",     1, NULL, 1006},

        {"serial_debug",  0, NULL, 1007},
        {"stratum_debug", 0, NULL, 1008},

        {"url",           1, NULL, 1100},
        {"userpass",      1, NULL, 1101},
        {"cert",          1, NULL, 1102},
        {"proxy",         1, NULL, 1103},

        {"retries",       1, NULL, 1010},
        {"retry-pause",   1, NULL, 1011},
        {"debug",         0, NULL, 1015},

        {"timeout",       1, NULL, 1014},
        {0,               0, 0,    0}
};

static work_t g_work = {{0}};
static time_t g_work_time = 0;
static pthread_mutex_t g_work_lock;
static bool submit_old = false;

static void workio_cmd_free(struct workio_cmd *wc);

void proper_exit(int reason) {
    exit(reason);
}

bool rpc2_stratum_job(struct stratum_ctx *sctx, json_t *params) {
    bool ret;
    pthread_mutex_lock(&sctx->work_lock);
    ret = rpc2_job_decode(params, &sctx->work);

    if (ret) {
        work_free(&g_work);
        work_copy(&g_work, &sctx->work);
        g_work_time = 0;
    }

    pthread_mutex_unlock(&sctx->work_lock);

    return ret;
}

bool rpc2_login(CURL *curl) {
    json_t *val;
    bool rc = false;
    struct timeval tv_start, tv_end, diff;
    char s[JSON_BUF_LEN];

    if (!jsonrpc_2)
        return false;

    snprintf(s, JSON_BUF_LEN, "{\"method\": \"login\", \"params\": {"
                     "\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"%s\"}, \"id\": 1}",
             rpc_user, rpc_pass, USER_AGENT);

    gettimeofday(&tv_start, NULL);
    val = json_rpc_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
    gettimeofday(&tv_end, NULL);

    if (!val)
        goto end;

    rc = rpc2_login_decode(val);

    json_t *result = json_object_get(val, "result");

    if (!result)
        goto end;

    json_t *job = json_object_get(result, "job");
    if (!rpc2_job_decode(job, &g_work)) {
        goto end;
    }

    if (opt_debug && rc) {
        timeval_subtract(&diff, &tv_end, &tv_start);
        applog(LOG_DEBUG, "DEBUG: authenticated in %d ms",
               diff.tv_sec * 1000 + diff.tv_usec / 1000);
    }

    json_decref(val);
    end:
    return rc;
}


static int share_result(int result, const char *reason) {
    pthread_mutex_lock(&stats_lock);
    result ? accepted_count++ : rejected_count++;
    pthread_mutex_unlock(&stats_lock);
    applog(LOG_INFO, "accepted: %lu/%lu", accepted_count, accepted_count + rejected_count);
    if (reason) {
        applog(LOG_WARNING, "reject reason: %s", reason);
    }
    return 1;
}

static bool submit_upstream_work(work_t *work) {
    char s[JSON_BUF_LEN];
    bool rc = false;

    /* pass if the previous hash is not the current previous hash */
    if (!submit_old && memcmp(&work->data[1], &g_work.data[1], 32)) {
        if (opt_debug)
            applog(LOG_DEBUG, "DEBUG: stale work detected, discarding");
        return true;
    }

    uint32_t ntime, nonce;
    char ntimestr[9], noncestr[9];
    uchar hash[32];
    if (jsonrpc_2) {
        bin2hex(noncestr, (const unsigned char *) work->data + 39, 4);
        if (opt_uart)
            memcpy(hash, work->hash, 32);
        else
            cryptonight_hash(hash, work->data);
        char *hashhex = abin2hex(hash, 32);
        snprintf(s, JSON_BUF_LEN,
                 "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":4}\r\n",
                 rpc2_id, work->job_id, noncestr, hashhex);
        free(hashhex);
    } else {
        char *xnonce2str;
        le32enc(&ntime, work->data[17]);
        le32enc(&nonce, work->data[19]);

        bin2hex(ntimestr, (const unsigned char *) (&ntime), 4);
        bin2hex(noncestr, (const unsigned char *) (&nonce), 4);
        xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
        snprintf(s, JSON_BUF_LEN,
                 "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
                 rpc_user, work->job_id, xnonce2str, ntimestr, noncestr);
        free(xnonce2str);
    }
    // store to keep/display solved blocks (work struct not linked on accept notification)

    if (opt_test)
        applog(LOG_INFO, "[TESTER_SUBMIT] %s", s);
    else {
        if (unlikely(!stratum_send_line(&stratum, s))) {
            applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
            goto out;
        }
    }
    rc = true;

    out:
    return rc;
}

static bool get_upstream_work(CURL *curl) {
    json_t *val;
    int err;
    struct timeval tv_start, tv_end;

    gettimeofday(&tv_start, NULL);
    char *getwork_req = "{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";
    if (jsonrpc_2) {
        char s[128];
        snprintf(s, 128, "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}\r\n", rpc2_id);
        val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
    } else {
        val = json_rpc_call(curl, rpc_url, rpc_userpass, getwork_req, &err, 0);
    }
    gettimeofday(&tv_end, NULL);

    if (val)
        json_decref(val);
    return true;
}

static void workio_cmd_free(struct workio_cmd *wc) {
    if (!wc)
        return;

    switch (wc->cmd) {
        case WC_SUBMIT_WORK:
            work_free(wc->u.work);
            free(wc->u.work);
            break;
        default: /* do nothing */
            break;
    }

    memset(wc, 0, sizeof(*wc)); /* poison */
    free(wc);
}

static bool workio_get_work(struct workio_cmd *wc, CURL *curl) {
    work_t *ret_work;
    int failures = 0;

    ret_work = (work_t *) calloc(1, sizeof(*ret_work));
    if (!ret_work)
        return false;

    /* obtain new work from bitcoin via JSON-RPC */
    while (!get_upstream_work(curl)) {
        if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
            applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
            free(ret_work);
            return false;
        }

        /* pause, then restart work-request loop */
        applog(LOG_ERR, "json_rpc_call failed, retry after %d seconds", opt_fail_pause);
        sleep(opt_fail_pause);
    }

    /* send work to requesting thread */
    if (!tq_push(wc->thr->q, ret_work))
        free(ret_work);

    return true;
}

static bool workio_submit_work(struct workio_cmd *wc) {
    int failures = 0;

    /* submit solution to bitcoin via JSON-RPC */
    while (!submit_upstream_work(wc->u.work)) {
        if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
            applog(LOG_ERR, "...terminating workio thread");
            return false;
        }
        applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
        sleep(opt_fail_pause);
    }
    return true;
}

static void *workio_thread(void *userdata) {
    struct thr_info *mythr = (struct thr_info *) userdata;
    CURL *curl;
    bool ok = true;

    curl = curl_easy_init();
    if (unlikely(!curl)) {
        applog(LOG_ERR, "CURL initialization failed");
        return NULL;
    }

    while (ok) {
        struct workio_cmd *wc;

        /* wait for workio_cmd sent to us, on our queue */
        wc = (struct workio_cmd *) tq_pop(mythr->q, NULL);
        if (!wc) {
            break;
        }

        /* process workio_cmd */
        switch (wc->cmd) {
            case WC_GET_WORK:
                ok = workio_get_work(wc, curl);
                break;
            case WC_SUBMIT_WORK:
                ok = workio_submit_work(wc);
                break;
            default:        /* should never happen */
                break;
        }

        workio_cmd_free(wc);
    }

    tq_freeze(mythr->q);
    curl_easy_cleanup(curl);

    return NULL;
}

static bool submit_work(struct thr_info *thr, const work_t *work_in) {
    struct workio_cmd *wc;

    /* fill out work request message */
    wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
    if (!wc)
        return false;

    wc->u.work = (work_t *) malloc(sizeof(*work_in));
    if (!wc->u.work)
        goto err_out;

    wc->cmd = WC_SUBMIT_WORK;
    wc->thr = thr;
    work_copy(wc->u.work, work_in);

    /* send solution to workio thread */
    if (!tq_push(thr_info[1].q, wc))
        goto err_out;

    return true;

    err_out:
    workio_cmd_free(wc);
    return false;
}

static void stratum_gen_work(struct stratum_ctx *sctx, work_t *work) {
    uchar merkle_root[64] = {0};
    int i, headersize = 0;

    pthread_mutex_lock(&sctx->work_lock);
    if (jsonrpc_2) {
        work_free(work);
        work_copy(work, &sctx->work);
        pthread_mutex_unlock(&sctx->work_lock);
    } else {
        free(work->job_id);
        work->job_id = strdup(sctx->job.job_id);
        work->xnonce2_len = sctx->xnonce2_size;
        work->xnonce2 = (uchar *) realloc(work->xnonce2, sctx->xnonce2_size);
        memcpy(work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);
        sha256d(merkle_root, sctx->job.coinbase, (int) sctx->job.coinbase_size);

        if (!headersize)
            for (i = 0; i < sctx->job.merkle_count; i++) {
                memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
                sha256d(merkle_root, merkle_root, 64);
            }

//    TODO: xnonce2++ should be more elegant
        for (size_t t = 0; t < sctx->xnonce2_size && !(++sctx->job.xnonce2[t]); t++);

        /* Assemble block header */
        memset(work->data, 0, 128);
        work->data[0] = le32dec(sctx->job.version);
        for (i = 0; i < 8; i++)
            work->data[1 + i] = le32dec((uint32_t *) sctx->job.prevhash + i);
        for (i = 0; i < 8; i++)
            work->data[9 + i] = be32dec((uint32_t *) merkle_root + i);

        work->data[17] = le32dec(sctx->job.ntime);
        work->data[18] = le32dec(sctx->job.nbits);
        // required ?
        work->data[20] = 0x80000000;
        work->data[31] = 0x00000280;

        pthread_mutex_unlock(&sctx->work_lock);

        char *xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
        applog(LOG_DEBUG, "generating new xnonce2: job_id='%s' extranonce2=%s ntime=%08x", work->job_id, xnonce2str, swab32(work->data[17]));
        free(xnonce2str);


        switch (opt_algo) {
            case ALGO_SCRYPT:
                work_set_target(work, sctx->job.diff / 65536.0);
                break;
            default:
                work_set_target(work, sctx->job.diff);
        }

        if (stratum_diff != sctx->job.diff) {
            char sdiff[32] = {0};
            stratum_diff = sctx->job.diff;
            if (opt_debug && work->targetdiff != stratum_diff)
                snprintf(sdiff, 32, " (%.5f)", work->targetdiff);
        }
    }
}

static void *miner_thread(void *userdata) {
    struct thr_info *mythr = (struct thr_info *) userdata;
    int thr_id = mythr->id;
    work_t work;
    uint32_t max_nonce;
    uint32_t end_nonce = 0xffffffffU;
    time_t tm_rate_log = 0;
    time_t firstwork_time = 0;
    char s[16];
    memset(&work, 0, sizeof(work));

    while (1) {
        uint64_t hashes_done;
        struct timeval tv_start, tv_end, diff;
        int64_t max64;
        bool regen_work = false;
        int wkcmp_offset = 0;
        int nonce_oft = 19 * sizeof(uint32_t); // 76
        int wkcmp_sz = nonce_oft;
        int rc = 0;
        if (jsonrpc_2)
            wkcmp_sz = nonce_oft = 39;

        uint32_t *nonceptr = (uint32_t *) (((char *) work.data) + nonce_oft);
        while (!opt_test && !jsonrpc_2 && time(NULL) >= g_work_time + 120)
            sleep(1);
        pthread_mutex_lock(&g_work_lock);

        // to clean: is g_work loaded before the memcmp ?
        regen_work = regen_work || ((*nonceptr) >= end_nonce && !(memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], (size_t) wkcmp_sz) || jsonrpc_2 ? memcmp(((uint8_t *) work.data) + 43, ((uint8_t *) g_work.data) + 43, 33) : 0));
        if (regen_work & !opt_test) {
            stratum_gen_work(&stratum, &g_work);
        }
        if (memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], (size_t) wkcmp_sz) || jsonrpc_2 ? memcmp(((uint8_t *) work.data) + 43, ((uint8_t *) g_work.data) + 43, 33) : 0) {
            work_free(&work);
            work_copy(&work, &g_work);
            nonceptr = (uint32_t *) (((char *) work.data) + nonce_oft);
            *nonceptr = 0xffffffffU;
        } else
            ++(*nonceptr);
        pthread_mutex_unlock(&g_work_lock);
        work_restart[thr_id].restart = 0;

        if (!work.data[0]) {
            sleep(1);
            continue;
        }
        max64 = LP_SCANTIME;


        max64 *= (int64_t) thr_hashrates[thr_id];

        if (max64 <= 0)
            max64 = 0x1fffffLL;
        if ((*nonceptr) + max64 > end_nonce)
            max_nonce = end_nonce;
        else
            max_nonce = (*nonceptr) + (uint32_t) max64;

        hashes_done = 0;
        gettimeofday(&tv_start, NULL);

        if (firstwork_time == 0)
            firstwork_time = time(NULL);

        /* scan nonces for a proof-of-work hash */
        switch (opt_algo) {
            case ALGO_XMR:
                rc = scanhash_cryptonight(thr_id, &work, max_nonce, &hashes_done);
                break;
            case ALGO_X11:
                rc = scanhash_x11(thr_id, &work, max_nonce, &hashes_done);
                break;
            case ALGO_SCRYPT:
                rc = scanhash_scrypt(thr_id, &work, max_nonce, &hashes_done);
                break;
            default:
                goto out;
        }

        /* record scanhash elapsed time */
        gettimeofday(&tv_end, NULL);
        timeval_subtract(&diff, &tv_end, &tv_start);
        if (diff.tv_usec || diff.tv_sec) {
            pthread_mutex_lock(&stats_lock);
            thr_hashrates[thr_id] = hashes_done / (diff.tv_sec + diff.tv_usec * 1e-6);
            pthread_mutex_unlock(&stats_lock);
        }
        if ((time(NULL) - tm_rate_log) > opt_maxlograte) {
            sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.0f" : "%.2f",
                    thr_hashrates[thr_id] / 1e3);
            applog(LOG_INFO, "CPU #%d: %s kH/s", thr_id, s);
            tm_rate_log = time(NULL);
        }
        /* if nonce found, submit work */
        if (rc) {
            if (!submit_work(mythr, &work))
                break;
        }
    }
    out:
    tq_freeze(mythr->q);

    return NULL;
}


static void *uart_miner_thread(void *userdata) {
    start_miner:
    need_restart = 0;
    struct thr_info *mythr = (struct thr_info *) userdata;
    struct timeval tv_start, tv_now, diff;
    work_t zero_work;
    work_free(&zero_work);
    work_t work;
    memset(&work, 0, sizeof(work));
    board_t *board = malloc(sizeof(board_t));
    board->restart_flag = &work_restart[0].restart;
    board_init_chip_array(board);
    work_t work_list[16];
    int work_index = 0;
    work_restart[0].restart = 0;
    gettimeofday(&tv_start, NULL);
    bool regen_work = false;
    uint8_t nonce_offset;
    bool first_enter = true;
    if (jsonrpc_2)
        nonce_offset = 39;
    else
        nonce_offset = 76;

    while (1) {
        while (!opt_test && !jsonrpc_2 && time(NULL) >= g_work_time + 120)
            sleep(1);
        pthread_mutex_lock(&g_work_lock);

        if (unlikely(memcmp(work.target + 6, g_work.target + 6, 8))) {
//        target has changed.
            le32enc(board->chip_array[0].target, g_work.target[6]);
            le32enc(board->chip_array[0].target + 4, g_work.target[7]);
            board_set_target(board);
        }

        regen_work = regen_work || memcmp(&work.data[0], &g_work.data[0], 76);
        if (regen_work) {
            if (!jsonrpc_2 && !opt_test) {
                stratum_gen_work(&stratum, &g_work);
//    verjion 4*1B   prev_hash 4*8B   merkle_root 4*8B   ntime 4*1B   nbits 4*1B
//		data_in has changed
//			  job_id has changed, need to clear fifo.
                if (*board->restart_flag) {
                    board_flush_fifo(board, 0);
                    *board->restart_flag = 0;
                    applog(LOG_DEBUG, "job id: %s came, flushed FIFO", g_work.job_id);
                }
            }
//            copy work from g_work to work
            work_free(&work);
            work_copy(&work, &g_work);
//            DATA_IN_REG
            if (jsonrpc_2)
                memcpy(board->chip_array[0].data_in, work.data, 76);
            else
                for (int i = 0; i < 19; ++i)
                    le32enc(board->chip_array[0].data_in + 4 * i, work.data[18 - i]);
            board_set_data_in(board, 0);

//            WORK_ID_REG
            if (!jsonrpc_2) {
                work_copy(work_list + work_index, &work);
                memcpy(board->chip_array[0].work_id, &work_index, 1);
                applog(LOG_DEBUG, "work_id_index: %d, xnonce2: %s", work_index, abin2hex(work.xnonce2, work.xnonce2_len));
                work_index = (work_index + 1) % 16;
                board_set_workid(board, 0);
            }
            if (!jsonrpc_2 || first_enter)
                board_start(board, 0);
            regen_work = 0;
        }
        first_enter = false;
        pthread_mutex_unlock(&g_work_lock);

        if (board_wait_for_nonce(board)) {
            nonce_cnt++;
            work_t upload_work = jsonrpc_2 ? work : work_list[*board->work_id];
            memcpy(((uint8_t *) upload_work.data + nonce_offset), board->nonce, 4);
            if (jsonrpc_2)
                memcpy(upload_work.hash, board->hash, 32);

            if (opt_test) {
                uchar hash[32];
                switch (opt_algo) {
                    case ALGO_XMR:
                        cryptonight_hash(hash, upload_work.data);
                        break;
                    case ALGO_X11:
                        x11_hash(hash, upload_work.data);
                        break;
                    case ALGO_SCRYPT:
                        scrypt_hash(hash, upload_work.data);
                        break;
                    default:
//                        should never happen
                        exit(-1);
                }
                if (jsonrpc_2)
                    applog(LOG_DEBUG, "nonce, %s, uart: %s, cpu: %s", abin2hex((uint8_t *) upload_work.data + nonce_offset, 4), abin2hex(board->hash, 32), abin2hex(hash, 32));
                else
                    applog(LOG_DEBUG, "nonce, %s, cpu: %s", abin2hex((uint8_t *) upload_work.data + nonce_offset, 4), abin2hex(hash, 32));
            }
            if (!submit_work(mythr, &upload_work))
                break;
        }

//          for every second
        gettimeofday(&tv_now, NULL);
        timeval_subtract(&diff, &tv_now, &tv_start);
        if (diff.tv_sec > 1) {
//            get fifo status
            if (!jsonrpc_2 && !opt_test) {
                for (uint8_t j = 1; j <= board->chip_nums; ++j) {
                    regen_work = (uint8_t) (regen_work || board_get_fifo(board, j));
                }
            }
//            TODO:get hash speed
            gettimeofday(&tv_start, NULL);
        }

        if (unlikely(need_restart))
            goto start_miner;
    }
    return NULL;
}

static bool stratum_handle_response(char *buf) {
    json_t *val, *err_val, *res_val, *id_val;
    json_error_t err;
    bool ret = false;
    bool valid;
    val = JSON_LOADS(buf, &err);
    if (!val) {
        applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
        goto out;
    }

    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");
    id_val = json_object_get(val, "id");

    if (!id_val || json_is_null(id_val))
        goto out;

    if (jsonrpc_2) {
        if (!res_val && !err_val)
            goto out;

        json_t *status = json_object_get(res_val, "status");
        if (status) {
            const char *s = json_string_value(status);
            valid = !strcmp(s, "OK") && json_is_null(err_val);
        } else {
            valid = json_is_null(err_val);
        }
        share_result(valid, err_val ? json_string_value(err_val) : NULL);

    } else {
        if (!res_val || json_integer_value(id_val) < 4)
            goto out;
        valid = json_is_true(res_val);
        share_result(valid, err_val ? json_string_value(json_array_get(err_val, 1)) : NULL);
    }
    ret = true;

    out:
    if (val)
        json_decref(val);

    return ret;
}

void restart_threads(void) {
    work_restart[0].restart = 1;
}

static void *test_stratum_thread(void *userdata) {
    struct thr_info *mythr = (struct thr_info *) userdata;
    free(mythr);
    memcpy(g_work.data, test_data, 76);
    memcpy(g_work.target + 6, test_target, 8);
    return NULL;
}

static void *stratum_thread(void *userdata) {
    struct thr_info *mythr = (struct thr_info *) userdata;
    char *s;

    stratum.url = (char *) tq_pop(mythr->q, NULL);
    if (!stratum.url)
        goto out;
    applog(LOG_INFO, "Starting Stratum on %s", stratum.url);

    while (1) {
        int failures = 0;

        while (!stratum.curl) {
            pthread_mutex_lock(&g_work_lock);
            g_work_time = 0;
            pthread_mutex_unlock(&g_work_lock);
            restart_threads();
            if (!stratum_connect(&stratum, stratum.url)
                || !stratum_subscribe(&stratum)
                || !stratum_authorize(&stratum, rpc_user, rpc_pass)) {
                stratum_disconnect(&stratum);

                if (opt_retries >= 0 && ++failures > opt_retries) {
                    applog(LOG_ERR, "...terminating workio thread");
                    tq_push(thr_info[1].q, NULL);
                    goto out;
                }
                applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
                sleep(opt_fail_pause);
            }

            if (jsonrpc_2) {
                work_free(&g_work);
                work_copy(&g_work, &stratum.work);
            }
        }

        if ((stratum.job.job_id && (!g_work_time || strcmp(stratum.job.job_id, g_work.job_id))) ||
            (stratum.work.job_id && (!g_work_time || strcmp(stratum.work.job_id, g_work.job_id)))) {
            pthread_mutex_lock(&g_work_lock);
            stratum_gen_work(&stratum, &g_work);
            time(&g_work_time);
            pthread_mutex_unlock(&g_work_lock);

            if (stratum.job.clean || jsonrpc_2) {
                static int last_bloc_height;
                if (last_bloc_height != stratum.bloc_height) {
                    last_bloc_height = stratum.bloc_height;
                    if (net_diff > 0.)
                        applog(LOG_INFO, "%s block %d, diff %.3f", algo_names[opt_algo],
                               stratum.bloc_height, net_diff);
                    else
                        applog(LOG_INFO, "%s %s block %d", short_url, algo_names[opt_algo],
                               stratum.bloc_height);
                }
                restart_threads();
            } else if (opt_debug) {
                applog(LOG_INFO, "%s asks job %lu for block %d", short_url,
                       strtoul(stratum.job.job_id, NULL, 16), stratum.bloc_height);
            }
        }

        if (!stratum_socket_full(&stratum, opt_timeout)) {
            applog(LOG_ERR, "Stratum connection timeout");
            s = NULL;
        } else
            s = stratum_recv_line(&stratum);
        if (!s) {
            stratum_disconnect(&stratum);
            applog(LOG_ERR, "Stratum connection interrupted");
            restart_threads();
            continue;
        }
        if (!stratum_handle_method(&stratum, s))
            stratum_handle_response(s);
        free(s);
    }
    out:
    return NULL;
}

static void show_usage_and_exit(int status) {
    printf(usage);
    exit(status);
}

static void strhide(char *s) {
    if (*s) *s++ = 'x';
    while (*s) *s++ = '\0';
}

void parse_arg(int key, char *arg) {
    char *p;
    int v, i;

    switch (key) {
//{ "algo", 1, NULL, 1000 },
        case 1000:
            for (i = 0; i < ALGO_COUNT; i++) {
                v = (int) strlen(algo_names[i]);
                if (v && !strncasecmp(arg, algo_names[i], (size_t) v)) {
                    if (arg[v] == '\0') {
                        opt_algo = (enum algos) i;
                        break;
                    }
                }
            }
            if (i == ALGO_COUNT) {
                if (strstr(arg, ":")) {
                    char *nf = strstr(arg, ":");
                    *nf = '\0';
                }
                show_usage_and_exit(1);
            }
            break;
//{ "cert", 1, NULL, 1102 },
        case 1102:
            free(opt_cert);
            opt_cert = strdup(arg);
            break;
//{ "cmd-path", 1, NULL, 1002 },
        case 1002:
            p = strchr(arg, ':');
            if (!p) {
                applog(LOG_ERR, "invalid path/to/cmd:speed -- '%s'\n", arg);
                show_usage_and_exit(1);
            }
            free(cmd_path);
            cmd_path = (char *) calloc(p - arg + 1, 1);
            strncpy(cmd_path, arg, p - arg);
            cmd_speed = (uint32_t) strtol(strdup(++p), NULL, 10);
            break;
//{ "nonce-path", 1, NULL, 1003},
        case 1003:
            p = strchr(arg, ':');
            if (!p) {
                applog(LOG_ERR, "invalid path/to/nonce:speed -- '%s'\n", arg);
                show_usage_and_exit(1);
            }
            free(nonce_path);
            nonce_path = (char *) calloc(p - arg + 1, 1);
            strncpy(nonce_path, arg, p - arg);
            nonce_speed = (uint32_t) strtol(strdup(++p), NULL, 10);
            break;

//{"chip_cycle",    1, NULL, 1004},
        case 1004:
            opt_cycle = (uint8_t) atoi(arg);
            break;

//{"test_data",       1, NULL, 1006},
        case 1006:
            free(test_data);
            test_data = (uint8_t *) calloc(1, 76);
            hex2bin(test_data, arg, 76);
            opt_test = true;
            break;
//{"test_target",     1, NULL, 1005},
        case 1005:
            free(test_target);
            test_target = (uint8_t *) calloc(1, 8);
            hex2bin(test_target, arg, 8);
            break;
//{ "url", 1, NULL, 1100 },
        case 1100: {            /* --url */
            char *ap, *hp;
            ap = strstr(arg, "://");
            ap = ap ? ap + 3 : arg;
            hp = strrchr(arg, '@');
            if (hp) {
                *hp = '\0';
                p = strchr(ap, ':');
                if (p) {
                    free(rpc_userpass);
                    rpc_userpass = strdup(ap);
                    free(rpc_user);
                    rpc_user = (char *) calloc(p - ap + 1, 1);
                    strncpy(rpc_user, ap, p - ap);
                    free(rpc_pass);
                    rpc_pass = strdup(++p);
                    if (*p) *p++ = 'x';
                    v = (int) strlen(hp + 1) + 1;
                    memmove(p + 1, hp + 1, (size_t) v);
                    memset(p + v, 0, hp - p);
                    hp = p;
                } else {
                    free(rpc_user);
                    rpc_user = strdup(ap);
                }
                *hp++ = '@';
            } else
                hp = ap;
            if (ap != arg) {
                if (strncasecmp(arg, "http://", 7) &&
                    strncasecmp(arg, "https://", 8) &&
                    strncasecmp(arg, "stratum+tcp://", 14)) {
                    applog(LOG_ERR, "unknown protocol -- '%s'\n", arg);
                    show_usage_and_exit(1);
                }
                free(rpc_url);
                rpc_url = strdup(arg);
                strcpy(rpc_url + (ap - arg), hp);
                short_url = &rpc_url[ap - arg];
            } else {
                if (*hp == '\0' || *hp == '/') {
                    applog(LOG_ERR, "invalid URL -- '%s'\n",
                           arg);
                    show_usage_and_exit(1);
                }
                free(rpc_url);
                rpc_url = (char *) malloc(strlen(hp) + 8);
                sprintf(rpc_url, "http://%s", hp);
                short_url = &rpc_url[sizeof("http://") - 1];
            }
            break;
        }
//{ "userpass", 1, NULL, 1101 },
        case 1101:            /* --userpass */
            p = strchr(arg, ':');
            if (!p) {
                applog(LOG_ERR, "invalid username:password pair -- '%s'\n", arg);
                show_usage_and_exit(1);
            }
            free(rpc_userpass);
            rpc_userpass = strdup(arg);
            free(rpc_user);
            rpc_user = (char *) calloc(p - arg + 1, 1);
            strncpy(rpc_user, arg, p - arg);
            free(rpc_pass);
            rpc_pass = strdup(++p);
            strhide(p);
            break;
//{ "proxy", 1, NULL, 1103 },
        case 1103:            /* --proxy */
            if (!strncasecmp(arg, "socks4://", 9))
                opt_proxy_type = CURLPROXY_SOCKS4;
            else if (!strncasecmp(arg, "socks5://", 9))
                opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
            else if (!strncasecmp(arg, "socks4a://", 10))
                opt_proxy_type = CURLPROXY_SOCKS4A;
            else if (!strncasecmp(arg, "socks5h://", 10))
                opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
            else
                opt_proxy_type = CURLPROXY_HTTP;
            free(opt_proxy);
            opt_proxy = strdup(arg);
            break;
//{ "retries", 1, NULL, 1010 },
        case 1010:
            v = atoi(arg);
            if (v < -1 || v > 9999) /* sanity check */
                show_usage_and_exit(1);
            opt_retries = v;
            break;
//{ "retry-pause", 1, NULL, 1011 },
        case 1011:
            v = atoi(arg);
            if (v < 1 || v > 9999) /* sanity check */
                show_usage_and_exit(1);
            opt_fail_pause = (uint8_t) v;
            break;
//{"serial_debug",    0, NULL, 1007},
        case 1007:
            opt_serial_debug = true;
            break;
//{"stratum_debug",   0, NULL, 1008},
        case 1008:
            opt_stratum_debug = true;
            break;
//{ "timeout", 1, NULL, 1014 },
        case 1014:
            v = atoi(arg);
            if (v < 1 || v > 99999) /* sanity check */
                show_usage_and_exit(1);
            opt_timeout = v;
            break;
//{ "debug", 0, NULL, 1015 },
        case 1015:
            opt_debug = true;
            break;
//never happen
        default:
            return;
    }
}

void parse_path(char *arg) {
    json_error_t err;
    json_t *config;
    if (arg && strstr(arg, "://")) {
        config = json_load_url(arg, &err);
    } else {
        config = JSON_LOADF(arg, &err);
    }
    if (!json_is_object(config)) {
        if (err.line < 0)
            applog(LOG_ERR, "%s\n", err.text);
        else
            applog(LOG_ERR, "%s:%d: %s\n", arg, err.line, err.text);
        exit(1);
    } else {
        parse_config(config);
        json_decref(config);
    }
}

void parse_config(json_t *config) {
    int i;
    json_t *val;

    for (i = 0; i < ARRAY_SIZE(options); i++) {
        if (!options[i].name)
            break;

        val = json_object_get(config, options[i].name);
        if (!val)
            continue;
        if (options[i].has_arg && json_is_string(val)) {
            char *s = strdup(json_string_value(val));
            if (!s)
                break;
            parse_arg(options[i].val, s);
            free(s);
        } else if (options[i].has_arg && json_is_integer(val)) {
            char buf[16];
            sprintf(buf, "%d", (int) json_integer_value(val));
            parse_arg(options[i].val, buf);
        } else if (options[i].has_arg && json_is_real(val)) {
            char buf[16];
            sprintf(buf, "%f", json_real_value(val));
            parse_arg(options[i].val, buf);
        } else if (!options[i].has_arg) {
            if (json_is_true(val))
                parse_arg(options[i].val, "");
        } else
            applog(LOG_ERR, "JSON option %s invalid",
                   options[i].name);
    }
}


static void signal_handler(int sig) {
    switch (sig) {
        case SIGHUP:
            applog(LOG_INFO, "SIGHUP received");
            break;
        case SIGINT:
            applog(LOG_INFO, "SIGINT received, exiting");
            proper_exit(0);
            break;
        case SIGTERM:
            applog(LOG_INFO, "SIGTERM received, exiting");
            proper_exit(0);
            break;
        default:
            break;
    }
}

static int thread_create(struct thr_info *thr, void *func) {
    int err = 0;
    pthread_attr_init(&thr->attr);
    err = pthread_create(&thr->pth, &thr->attr, func, thr);
    pthread_attr_destroy(&thr->attr);
    return err;
}

void get_defconfig_path(char *out, size_t bufsize, char *argv0, char *argv1);

int main(int argc, char *argv[]) {
    struct thr_info *thr;
    long flags;
    int err;

    pthread_mutex_init(&applog_lock, NULL);
    if (argc == 1) show_usage_and_exit(1);
    // try default config file in binary folder
    char defconfig[PATH_MAX] = {0};
    get_defconfig_path(defconfig, PATH_MAX, argv[0], argv[1]);
    parse_path(defconfig);

    opt_uart = cmd_speed && nonce_speed;

    if (opt_algo == ALGO_XMR)
        jsonrpc_2 = true;

    pthread_mutex_init(&stats_lock, NULL);
    pthread_mutex_init(&g_work_lock, NULL);
    pthread_mutex_init(&stratum.sock_lock, NULL);
    pthread_mutex_init(&stratum.work_lock, NULL);

    if (jsonrpc_2) {
        pthread_mutex_init(&rpc2_job_lock, NULL);
        pthread_mutex_init(&rpc2_login_lock, NULL);
    }
    if (!opt_test) {
        flags = strncmp(rpc_url, "https:", 6) ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL) : CURL_GLOBAL_ALL;
        if (curl_global_init(flags)) {
            applog(LOG_ERR, "CURL initialization failed");
            return 1;
        }
    }

    /* Always catch Ctrl+C */
    signal(SIGINT, signal_handler);

    work_restart = (struct work_restart *) calloc(1, sizeof(*work_restart));
    thr_info = (struct thr_info *) calloc(3, sizeof(*thr));
    thr_hashrates = (double *) calloc(1, sizeof(double));
    if (rpc_pass && rpc_user)
        opt_stratum_stats = (strstr(rpc_pass, "stats") != NULL) || (strcmp(rpc_user, "benchmark") == 0);

// open workio thread
    thr = &thr_info[1];
    thr->id = 1;
    thr->q = tq_new();
    if (!thr->q)
        return 1;

    if (thread_create(thr, workio_thread)) {
        applog(LOG_ERR, "work thread create failed");
        return 1;
    }

// open stratum thread
    thr = &thr_info[2];
    thr->id = 2;
    thr->q = tq_new();
    if (!thr->q)
        return 1;
    if (opt_test)
        err = thread_create(thr, test_stratum_thread);
    else
        err = thread_create(thr, stratum_thread);
    if (err) {
        applog(LOG_ERR, "stratum thread create failed");
        return 1;
    }
    if (!opt_test)
        tq_push(thr_info[2].q, strdup(rpc_url));

// open miner thread
    thr = &thr_info[0];
    thr->id = 0;
    thr->q = tq_new();
    if (!thr->q)
        return 1;

    if (opt_uart) {
        applog(LOG_DEBUG, "entering UART miner thread.");
        err = thread_create(thr, uart_miner_thread);
    } else {
        err = thread_create(thr, miner_thread);
    }

    if (err) {
        applog(LOG_DEBUG, "entering CPU miner thread.");
        applog(LOG_ERR, "thread %d create failed", 0);
        return 1;
    }

    /* main loop - simply wait for workio thread to exit */
    pthread_join(thr_info[1].pth, NULL);
    applog(LOG_WARNING, "workio thread dead, exiting.");
    return 0;
}