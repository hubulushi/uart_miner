/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 Lucas Jones
 * Copyright 2014 Tanguy Pruvot
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
        struct work *work;
    } u;
};

enum algos {
    ALGO_X11,         /* X11 */
    ALGO_TTY,         /* use tty to connect asic or fpga */
    ALGO_COUNT
};

static const char *algo_names[] = {
        "x11",
        "tty",
        "\0"
};
bool opt_benchmark = false;
bool opt_debug = true;
bool want_stratum = true;
bool allow_mininginfo = true;
bool use_colors = true;
bool opt_tty = false;
bool opt_quiet = false;
int opt_maxlograte = 5;
bool opt_protocol = false;
long opt_proxy_type;
bool opt_redirect = true;
bool opt_stratum_stats = false;
static int opt_retries = -1;
static int opt_fail_pause = 10;
static int opt_time_limit = 0;
int opt_timeout = 300;
static enum algos opt_algo = ALGO_X11;
int opt_priority = 0;
int num_cpus;
char *rpc_url;
char *rpc_userpass;
char *rpc_user, *rpc_pass;
char *tty_path;
uint32_t *tty_speed;
char *short_url = NULL;
char *opt_cert;
char *opt_proxy;
struct thr_info *thr_info;
struct work_restart *work_restart = NULL;
struct stratum_ctx stratum;
double opt_diff_factor = 1.0;
pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;

uint32_t accepted_count = 0L;
uint32_t rejected_count = 0L;
double *thr_hashrates;
uint64_t global_hashrate = 0;
double stratum_diff = 0.;
double net_diff = 0.;
double net_hashrate = 0.;
// conditional mining
bool conditional_state[MAX_CPUS] = {0};
double opt_max_temp = 0.0;
double opt_max_diff = 0.0;
double opt_max_rate = 0.0;


static char const usage[] = "\
Usage:  [OPTIONS]\n\
Options:\n\
  -a, --algo=ALGO       specify the algorithm to use\n\
                          x11          X11\n\
                          tty          TTY\n\
  -z, --tty-path=ttypath:speed  specify the tty port and speed\n\
  -o, --url=URL         URL of mining server\n\
  -O, --userpass=U:P    username:password pair for mining server\n\
      --cert=FILE       certificate for mining server using SSL\n\
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -r, --retries=N       number of times to retry if a network call fails\n\
                          (default: retry indefinitely)\n\
  -R, --retry-pause=N   time to pause between retries, in seconds (default: 30)\n\
      --time-limit=N    maximum time [s] to mine before exiting the program.\n\
  -T, --timeout=N       timeout for long poll and stratum (default: 300 seconds)\n\
  -s, --scantime=N      upper bound on time spent scanning current work when\n\
                          long polling is unavailable, in seconds (default: 5)\n\
      --randomize       Randomize scan range start to reduce duplicates\n\
  -f, --diff-factor     Divide req. difficulty by this factor (std is 1.0)\n\
  -m, --diff-multiplier Multiply difficulty by this factor (std is 1.0)\n\
  -q, --quiet           disable per-thread hashmeter output\n\
  -D, --debug           enable debug output\n\
      --benchmark       run in offline benchmark mode\n\
      --cputest         debug hashes from cpu algorithms\n\
      --max-temp=N      Only mine if cpu temp is less than specified value (linux)\n\
      --max-rate=N[KMG] Only mine if net hashrate is less than specified value\n\
      --max-diff=N      Only mine if net difficulty is less than specified value\n\
  -c, --config=FILE     load a JSON-format configuration file\n\
  -h, --help            display this help text and exit\n\
";

static char const short_options[] = "a:b:Bc:CDf:hm:n:p:Px:qr:R:s:t:T:o:u:O:V";

static struct option const options[] = {
        {"algo",            1, NULL, 'a'},
        {"tty-path",        1, NULL, 'z'},
        {"url",             1, NULL, 'o'},
        {"userpass",        1, NULL, 'O'},
        {"cert",            1, NULL, 1001},
        {"proxy",           1, NULL, 'x'},
        {"retries",         1, NULL, 'r'},
        {"retry-pause",     1, NULL, 'R'},
        {"time-limit",      1, NULL, 1008},
        {"timeout",         1, NULL, 'T'},
        {"scantime",        1, NULL, 's'},
        {"randomize",       0, NULL, 1024},
        {"diff-factor",     1, NULL, 'f'},
        {"diff-multiplier", 1, NULL, 'm'},
        {"quiet",           0, NULL, 'q'},
        {"debug",           0, NULL, 'D'},
        {"benchmark",       0, NULL, 1005},
        {"cputest",         0, NULL, 1006},
        {"max-temp",        1, NULL, 1060},
        {"max-rate",        1, NULL, 1062},
        {"max-diff",        1, NULL, 1061},
        {"config",          1, NULL, 'c'},
        {"help",            0, NULL, 'h'},
        {0,                 0, 0,    0}
};

static struct work g_work = {{0}};
static time_t g_work_time = 0;
static pthread_mutex_t g_work_lock;
static bool submit_old = false;

static void workio_cmd_free(struct workio_cmd *wc);

void proper_exit(int reason) {
    exit(reason);
}

static inline void work_free(struct work *w) {
    if (w->txs) free(w->txs);
    if (w->workid) free(w->workid);
    if (w->job_id) free(w->job_id);
    if (w->xnonce2) free(w->xnonce2);
}

static inline void work_copy(struct work *dest, const struct work *src) {
    memcpy(dest, src, sizeof(struct work));
    if (src->txs)
        dest->txs = strdup(src->txs);
    if (src->workid)
        dest->workid = strdup(src->workid);
    if (src->job_id)
        dest->job_id = strdup(src->job_id);
    if (src->xnonce2) {
        dest->xnonce2 = (uchar *) malloc(src->xnonce2_len);
        memcpy(dest->xnonce2, src->xnonce2, src->xnonce2_len);
    }
}

/* compute nbits to get the network diff */
static void calc_network_diff(struct work *work) {
    uint32_t nbits = swab32(work->data[18]);
    uint32_t bits = (nbits & 0xffffff);
    int16_t shift = (swab32(nbits) & 0xff); // 0x1c = 28
    double d = (double) 0x0000ffff / (double) bits;
    for (int m = shift; m < 29; m++) d *= 256.0;
    for (int m = 29; m < shift; m++) d /= 256.0;
    if (opt_debug)
        applog(LOG_DEBUG, "net diff: %f -> shift %u, bits %08x", d, shift, bits);
    net_diff = d;
}

static bool work_decode(const json_t *val, struct work *work) {
    int i;
    int data_size = 128, target_size = sizeof(work->target);
    int adata_sz = 32, atarget_sz = ARRAY_SIZE(work->target);

    if (unlikely(!jobj_binary(val, "data", work->data, data_size))) {
        applog(LOG_ERR, "JSON invalid data");
        goto err_out;
    }
    if (unlikely(!jobj_binary(val, "target", work->target, target_size))) {
        applog(LOG_ERR, "JSON invalid target");
        goto err_out;
    }

    for (i = 0; i < adata_sz; i++)
        work->data[i] = le32dec(work->data + i);
    for (i = 0; i < atarget_sz; i++)
        work->target[i] = le32dec(work->target + i);

    work->targetdiff = target_to_diff(work->target);

    // for api stats, on longpoll pools
    stratum_diff = work->targetdiff;
    return true;

    err_out:
    return false;
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

static bool submit_upstream_work(CURL *curl, struct work *work) {
    json_t *val, *res, *reason;
    char s[JSON_BUF_LEN];
    int i;
    bool rc = false;

    /* pass if the previous hash is not the current previous hash */
    if (!submit_old && memcmp(&work->data[1], &g_work.data[1], 32)) {
        if (opt_debug)
            applog(LOG_DEBUG, "DEBUG: stale work detected, discarding");
        return true;
    }

    uint32_t ntime, nonce;
    char ntimestr[9], noncestr[9];

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

    // store to keep/display solved blocks (work struct not linked on accept notification)

    if (unlikely(!stratum_send_line(&stratum, s))) {
        applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
        goto out;
    }
    rc = true;

    out:
    return rc;
}

static const char *getwork_req = "{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

static bool get_upstream_work(CURL *curl, struct work *work) {
    json_t *val;
    int err;
    struct timeval tv_start, tv_end;

    gettimeofday(&tv_start, NULL);
    val = json_rpc_call(curl, rpc_url, rpc_userpass, getwork_req, &err, 0);
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
    struct work *ret_work;
    int failures = 0;

    ret_work = (struct work *) calloc(1, sizeof(*ret_work));
    if (!ret_work)
        return false;

    /* obtain new work from bitcoin via JSON-RPC */
    while (!get_upstream_work(curl, ret_work)) {
        if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
            applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
            free(ret_work);
            return false;
        }

        /* pause, then restart work-request loop */
        applog(LOG_ERR, "json_rpc_call failed, retry after %d seconds",
               opt_fail_pause);
        sleep(opt_fail_pause);
    }

    /* send work to requesting thread */
    if (!tq_push(wc->thr->q, ret_work))
        free(ret_work);

    return true;
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl) {
    int failures = 0;

    /* submit solution to bitcoin via JSON-RPC */
    while (!submit_upstream_work(curl, wc->u.work)) {
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
            ok = false;
            break;
        }

        /* process workio_cmd */
        switch (wc->cmd) {
            case WC_GET_WORK:
                ok = workio_get_work(wc, curl);
                break;
            case WC_SUBMIT_WORK:
                ok = workio_submit_work(wc, curl);
                break;
            default:        /* should never happen */
                ok = false;
                break;
        }

        workio_cmd_free(wc);
    }

    tq_freeze(mythr->q);
    curl_easy_cleanup(curl);

    return NULL;
}

static bool submit_work(struct thr_info *thr, const struct work *work_in) {
    struct workio_cmd *wc;

    /* fill out work request message */
    wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
    if (!wc)
        return false;

    wc->u.work = (struct work *) malloc(sizeof(*work_in));
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

static void stratum_gen_work(struct stratum_ctx *sctx, struct work *work) {
    uchar merkle_root[64] = {0};
    int i, headersize = 0;

    pthread_mutex_lock(&sctx->work_lock);

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

    if (opt_debug) {
        char *xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len);
        applog(LOG_DEBUG, "generating new xnonce2: job_id='%s' extranonce2=%s ntime=%08x", work->job_id, xnonce2str, swab32(work->data[17]));
        free(xnonce2str);
    }

    work_set_target(work, sctx->job.diff);

    if (stratum_diff != sctx->job.diff) {
        char sdiff[32] = {0};
        stratum_diff = sctx->job.diff;
        if (opt_debug && work->targetdiff != stratum_diff)
            snprintf(sdiff, 32, " (%.5f)", work->targetdiff);
    }
}

static void *miner_thread(void *userdata) {
    struct thr_info *mythr = (struct thr_info *) userdata;
    int thr_id = mythr->id;
    struct work work;
    uint32_t max_nonce;
    uint32_t end_nonce = 0xffffffffU / -0x20;
    time_t tm_rate_log = 0;
    time_t firstwork_time = 0;
    char s[16];
    int i;

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

        uint32_t *nonceptr = (uint32_t *) (((char *) work.data) + nonce_oft);

        while (time(NULL) >= g_work_time + 120)
            sleep(1);

        pthread_mutex_lock(&g_work_lock);
        // to clean: is g_work loaded before the memcmp ?
        regen_work = regen_work || ((*nonceptr) >= end_nonce &&
                                    !(memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], wkcmp_sz)));
        if (regen_work) {
            stratum_gen_work(&stratum, &g_work);
        }

        if (memcmp(&work.data[wkcmp_offset], &g_work.data[wkcmp_offset], wkcmp_sz)) {
            work_free(&work);
            work_copy(&work, &g_work);
//			push work here
            nonceptr = (uint32_t *) (((char *) work.data) + nonce_oft);
            *nonceptr = 0xffffffffU;
        } else
            ++(*nonceptr);
        pthread_mutex_unlock(&g_work_lock);
        work_restart[thr_id].restart = 0;

        if (!work.data[0] && !opt_benchmark) {
            sleep(1);
            continue;
        }
        /* adjust max_nonce to meet target scan time */
        max64 = LP_SCANTIME;

        /* time limit */
        if (opt_time_limit && firstwork_time) {
            int passed = (int) (time(NULL) - firstwork_time);
            int remain = (int) (opt_time_limit - passed);
            if (remain < 0) {
                if (thr_id != 0) {
                    sleep(1);
                    continue;
                }
                if (opt_benchmark) {
                    char rate[32];
                    format_hashrate((double) global_hashrate, rate);
                    applog(LOG_NOTICE, "Benchmark: %s", rate);
                    fprintf(stderr, "%llu\n", (long long unsigned int) global_hashrate);
                } else {
                    applog(LOG_NOTICE,
                           "Mining timeout of %ds reached, exiting...", opt_time_limit);
                }
                proper_exit(0);
            }
            if (remain < max64) max64 = remain;
        }

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
        rc = scanhash_x11(thr_id, &work, max_nonce, &hashes_done);

        /* record scanhash elapsed time */
        gettimeofday(&tv_end, NULL);
        timeval_subtract(&diff, &tv_end, &tv_start);
        if (diff.tv_usec || diff.tv_sec) {
            pthread_mutex_lock(&stats_lock);
            thr_hashrates[thr_id] =
                    hashes_done / (diff.tv_sec + diff.tv_usec * 1e-6);
            pthread_mutex_unlock(&stats_lock);
        }
        if (!opt_quiet && (time(NULL) - tm_rate_log) > opt_maxlograte) {
            sprintf(s, thr_hashrates[thr_id] >= 1e6 ? "%.0f" : "%.2f",
                    thr_hashrates[thr_id] / 1e3);
            applog(LOG_INFO, "CPU #%d: %s kH/s", thr_id, s);
            tm_rate_log = time(NULL);
        }

        /* if nonce found, submit work */
        if (rc && !opt_benchmark) {
            if (!submit_work(mythr, &work))
                break;
        }
    }

    tq_freeze(mythr->q);
    return NULL;
}


static void *uart_miner_thread(void *userdata) {
    struct thr_info *mythr = (struct thr_info *) userdata;
    struct work zero_work;
    work_free(&zero_work);
    struct work work;
    struct work upload_work;
    memset(&work, 0, sizeof(work));
    board_t *board = malloc(sizeof(board_t));
    board_init_chip_array(board);
    uint8_t need_regen = 0;
    while (!g_work.targetdiff);
    size_t xnonce2_len = g_work.xnonce2_len;
    uint8_t *work_id = malloc(8 * xnonce2_len);
    memset(work_id, 0x00, 8 * xnonce2_len);
//    TODO:work id still have some bugs in RTL
    int work_id_index = 0;
    while (1) {
        pthread_mutex_lock(&g_work_lock);
        if (work.targetdiff != g_work.targetdiff) {
//        g_work diff has changed.
            work.targetdiff = g_work.targetdiff;
            work_set_target(&work, work.targetdiff);
            le32enc(board->chip_array[0].target, work.target[6]);
            le32enc(board->chip_array[0].target + 4, work.target[7]);
            board_set_target(board);
        }
//
        if (need_regen) {
            stratum_gen_work(&stratum, &g_work);
            need_regen = 0;
        }
//    verjion 4*1B   prev_hash 4*8B   merkle_root 4*8B   ntime 4*1B   nbits 4*1B
//		data_in has changed
        if (memcmp(work.data, g_work.data, 76)) {
//			  job_id has changed, need to clear fifo.
            if (work.job_id==NULL||strcmp(work.job_id,g_work.job_id)){
                board_flush_fifo(board, 0);
                applog(LOG_DEBUG, "job id: %s came, flushed FIFO", g_work.job_id);
            }
//            copy work from g_work to work
            work_free(&work);
            work_copy(&work, &g_work);
//            DATA_IN_REG
            for (int i = 0; i < 19; ++i)
                le32enc(board->chip_array[0].data_in + 4 * i, work.data[18 - i]);
            board_set_data_in(board, 0);
//            WORK_ID_REG
            memcpy(work_id + (work_id_index * xnonce2_len), work.xnonce2, xnonce2_len);
            memcpy(board->chip_array[0].work_id, &work_id_index, 1);
            work_id_index = (work_id_index + 1) % 8;
            board_set_workid(board, 0);
            board_start_x11(board, 0);
        }
        pthread_mutex_unlock(&g_work_lock);

//          make sure nonce is not full
        for (uint8_t j = 1; j <= board->chip_nums; ++j)
            need_regen = (uint8_t)(need_regen || board_get_fifo(board, j));

        if (board_wait_for_nonce(board)) {
            work_free(&upload_work);
            work_copy(&upload_work, &work);
            memcpy(upload_work.data + 19, board->nonce, 4);
            memcpy(upload_work.xnonce2, work_id + (*board->work_id * xnonce2_len), xnonce2_len);
            if (!submit_work(mythr, &upload_work)) {
                break;
            }
        }
    }
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


    if (!res_val || json_integer_value(id_val) < 4)
        goto out;
    valid = json_is_true(res_val);
    share_result(valid, err_val ? json_string_value(json_array_get(err_val, 1)) : NULL);

    ret = true;

    out:
    if (val)
        json_decref(val);

    return ret;
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

            if (!stratum_connect(&stratum, stratum.url) || !stratum_subscribe(&stratum) ||
                !stratum_authorize(&stratum, rpc_user, rpc_pass)) {
                stratum_disconnect(&stratum);
                if (opt_retries >= 0 && ++failures > opt_retries) {
                    applog(LOG_ERR, "...terminating workio thread");
                    tq_push(thr_info[1].q, NULL);
                    goto out;
                }
                if (!opt_benchmark)
                    applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
                sleep(opt_fail_pause);
            }

        }

        if (stratum.job.job_id && (!g_work_time || strcmp(stratum.job.job_id, g_work.job_id))) {
            pthread_mutex_lock(&g_work_lock);
            stratum_gen_work(&stratum, &g_work);
            time(&g_work_time);
            pthread_mutex_unlock(&g_work_lock);

            if (stratum.job.clean) {
                static uint32_t last_bloc_height;
                if (!opt_quiet && last_bloc_height != stratum.bloc_height) {
                    last_bloc_height = stratum.bloc_height;
                    if (net_diff > 0.)
                        applog(LOG_INFO, "%s block %d, diff %.3f", algo_names[opt_algo],
                               stratum.bloc_height, net_diff);
                    else
                        applog(LOG_INFO, "%s %s block %d", short_url, algo_names[opt_algo],
                               stratum.bloc_height);
                }
//				restart_threads();
            } else if (opt_debug && !opt_quiet) {
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
    if (status)
        fprintf(stderr, "Try `" PACKAGE_NAME " --help' for more information.\n");
    else
        printf(usage);
    exit(status);
}

static void strhide(char *s) {
    if (*s) *s++ = 'x';
    while (*s) *s++ = '\0';
}

void parse_arg(int key, char *arg) {
//    TODO: need to be more clear
    char *p;
    int v, i;
    uint64_t ul;
    double d;

    switch (key) {
//{ "algo", 1, NULL, 'a' },
        case 'a':
            for (i = 0; i < ALGO_COUNT; i++) {
                v = (int) strlen(algo_names[i]);
                if (v && !strncasecmp(arg, algo_names[i], v)) {
                    if (arg[v] == '\0') {
                        opt_algo = (enum algos) i;
                        break;
                    }
                    if (arg[v] == ':') {
                        char *ep;
                        v = strtol(arg + v + 1, &ep, 10);
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
            }
            if (i == ALGO_COUNT) {
                show_usage_and_exit(1);
            }
            break;
//{ "tty-path", 1, NULL, 'z' },
        case 'z':
            p = strchr(arg, ':');
            if (!p) {
                fprintf(stderr, "invalid path/to/tty:speed -- '%s'\n", arg);
                show_usage_and_exit(1);
            }
            opt_tty = true;
            free(tty_path);
            tty_path = (char *) calloc(p - arg + 1, 1);
            strncpy(tty_path, arg, p - arg);
            free(tty_speed);
            tty_speed = (uint32_t *) strtol(strdup(++p), NULL, 10);
            break;
//{ "url", 1, NULL, 'o' },
        case 'o': {            /* --url */
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
                    memmove(p + 1, hp + 1, v);
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
                    fprintf(stderr, "unknown protocol -- '%s'\n", arg);
                    show_usage_and_exit(1);
                }
                free(rpc_url);
                rpc_url = strdup(arg);
                strcpy(rpc_url + (ap - arg), hp);
                short_url = &rpc_url[ap - arg];
            } else {
                if (*hp == '\0' || *hp == '/') {
                    fprintf(stderr, "invalid URL -- '%s'\n",
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
//{ "userpass", 1, NULL, 'O' },
        case 'O':            /* --userpass */
            p = strchr(arg, ':');
            if (!p) {
                fprintf(stderr, "invalid username:password pair -- '%s'\n", arg);
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
//{ "cert", 1, NULL, 1001 },
        case 1001:
            free(opt_cert);
            opt_cert = strdup(arg);
            break;
//{ "proxy", 1, NULL, 'x' },
        case 'x':            /* --proxy */
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
//{ "retries", 1, NULL, 'r' },
        case 'r':
            v = atoi(arg);
            if (v < -1 || v > 9999) /* sanity check */
                show_usage_and_exit(1);
            opt_retries = v;
            break;
//{ "retry-pause", 1, NULL, 'R' },
        case 'R':
            v = atoi(arg);
            if (v < 1 || v > 9999) /* sanity check */
                show_usage_and_exit(1);
            opt_fail_pause = v;
            break;
//{ "time-limit", 1, NULL, 1008 },
        case 1008:
            opt_time_limit = atoi(arg);
            break;
//{ "timeout", 1, NULL, 'T' },
        case 'T':
            v = atoi(arg);
            if (v < 1 || v > 99999) /* sanity check */
                show_usage_and_exit(1);
            opt_timeout = v;
            break;
//{ "diff-factor", 1, NULL, 'f' },
        case 'f':
            d = atof(arg);
            if (d == 0.)    /* --diff-factor */
                show_usage_and_exit(1);
            opt_diff_factor = d;
            break;
//{ "diff-multiplier", 1, NULL, 'm' },
        case 'm':
            d = atof(arg);
            if (d == 0.)    /* --diff-multiplier */
                show_usage_and_exit(1);
            opt_diff_factor = 1.0 / d;
            break;
//{ "quiet", 0, NULL, 'q' },
        case 'q':
            opt_quiet = true;
            break;
//{ "debug", 0, NULL, 'D' },
        case 'D':
            opt_debug = true;
            break;
//{ "cputest", 0, NULL, 1006 },
        case 1006:
            print_hash_tests();
            exit(0);
//{ "max-temp", 1, NULL, 1060 },
        case 1060: // max-temp
            d = atof(arg);
            opt_max_temp = d;
            break;
//{ "max-rate", 1, NULL, 1062},
        case 1062: // max-rate
            d = atof(arg);
            p = strstr(arg, "K");
            if (p) d *= 1e3;
            p = strstr(arg, "M");
            if (p) d *= 1e6;
            p = strstr(arg, "G");
            if (p) d *= 1e9;
            opt_max_rate = d;
            break;
//{ "max-diff", 1, NULL, 1061 },
        case 1061: // max-diff
            d = atof(arg);
            opt_max_diff = d;
            break;
//{ "config", 1, NULL, 'c' },
        case 'c': {
            json_error_t err;
            json_t *config;
            if (arg && strstr(arg, "://")) {
                config = json_load_url(arg, &err);
            } else {
                config = JSON_LOADF(arg, &err);
            }
            if (!json_is_object(config)) {
                if (err.line < 0)
                    fprintf(stderr, "%s\n", err.text);
                else
                    fprintf(stderr, "%s:%d: %s\n",
                            arg, err.line, err.text);
            } else {
                parse_config(config, arg);
                json_decref(config);
            }
            break;
        }
//{ "help", 0, NULL, 'h' },
        case 'h':
            show_usage_and_exit(0);
        default:
            show_usage_and_exit(1);
    }
}

void parse_config(json_t *config, char *ref) {
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

static void parse_cmdline(int argc, char *argv[]) {
    int key;

    while (1) {
#if HAVE_GETOPT_LONG
        key = getopt_long(argc, argv, short_options, options, NULL);
#else
        key = getopt(argc, argv, short_options);
#endif
        if (key < 0)
            break;

        parse_arg(key, optarg);
    }
    if (optind < argc) {
        fprintf(stderr, "%s: unsupported non-option argument -- '%s'\n",
                argv[0], argv[optind]);
        show_usage_and_exit(1);
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
    }
}

static int thread_create(struct thr_info *thr, void *func) {
    int err = 0;
    pthread_attr_init(&thr->attr);
    err = pthread_create(&thr->pth, &thr->attr, func, thr);
    pthread_attr_destroy(&thr->attr);
    return err;
}

void get_defconfig_path(char *out, size_t bufsize, char *argv0);

int main(int argc, char *argv[]) {
    struct thr_info *thr;
    long flags;
    int err;

    pthread_mutex_init(&applog_lock, NULL);

    /* parse command line */
    // parse_cmdline(argc, argv);

    if (!opt_benchmark && !rpc_url) {
        // try default config file in binary folder
        char defconfig[PATH_MAX] = {0};
        get_defconfig_path(defconfig, PATH_MAX, argv[0]);
        if (strlen(defconfig)) {
            if (opt_debug)
                applog(LOG_DEBUG, "Using config %s", defconfig);
            parse_arg('c', defconfig);
            parse_cmdline(argc, argv);
        }
    }

    pthread_mutex_init(&stats_lock, NULL);
    pthread_mutex_init(&g_work_lock, NULL);
    pthread_mutex_init(&stratum.sock_lock, NULL);
    pthread_mutex_init(&stratum.work_lock, NULL);

    flags = !opt_benchmark && strncmp(rpc_url, "https:", 6) ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL) : CURL_GLOBAL_ALL;
    if (curl_global_init(flags)) {
        applog(LOG_ERR, "CURL initialization failed");
        return 1;
    }

    /* Always catch Ctrl+C */
    signal(SIGINT, signal_handler);

    work_restart = (struct work_restart *) calloc(1, sizeof(*work_restart));
    if (!work_restart)
        return 1;

    thr_info = (struct thr_info *) calloc(3, sizeof(*thr));
    if (!thr_info)
        return 1;
// 每个miner线程算力
    thr_hashrates = (double *) calloc(1, sizeof(double));
    if (!thr_hashrates)
        return 1;

// Benchmark测试使用
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

    err = thread_create(thr, stratum_thread);
    if (err) {
        applog(LOG_ERR, "stratum thread create failed");
        return 1;
    }
    tq_push(thr_info[2].q, strdup(rpc_url));

// open miner thread
    thr = &thr_info[0];
    thr->id = 0;
    thr->q = tq_new();
    if (!thr->q)
        return 1;
    if (opt_algo==ALGO_TTY) {
        err = thread_create(thr, uart_miner_thread);
    } else {
        err = thread_create(thr, miner_thread);
    }

    if (err) {
        applog(LOG_ERR, "thread %d create failed", 0);
        return 1;
    }
    /* main loop - simply wait for workio thread to exit */
    pthread_join(thr_info[1].pth, NULL);
    applog(LOG_WARNING, "workio thread dead, exiting.");
    return 0;
}