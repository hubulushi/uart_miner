//
// Created by sequencer on 10/20/17.
//
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


static bool submit_to_file(work_t *work) {
    char s[JSON_BUF_LEN];
    uint32_t ntime, nonce;
    char ntimestr[9], noncestr[9];
    uchar hash[32], board_hash[32];
    if (jsonrpc_2) {
        bin2hex(noncestr, (const unsigned char *) work->data + 39, 4);
        if (opt_uart) {
            cryptonight_hash(hash, work->data, 76);
            memcpy(board_hash, work->hash, 32);
            applog(LOG_DEBUG, "cpu: %s, uart: %s", abin2hex(hash, 32), abin2hex(board_hash, 32));
        } else
            cryptonight_hash(hash, work->data, 76);
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
}


static void uart_miner(work_t g_work) {
    work_t work;
    memset(&work, 0, sizeof(work));
    work_free(&work);
    work_copy(&work, &g_work);
    board_t *board = malloc(sizeof(board_t));
    uint8_t nonce_offset;
    if (jsonrpc_2)
        nonce_offset = 39;
    else
        nonce_offset = 76;
//  init
    board_init_chip_array(board);
//  target
    le32enc(board->chip_array[0].target, g_work.target[6]);
    le32enc(board->chip_array[0].target + 4, g_work.target[7]);
    board_set_target(board);
//  datain
    for (int i = 0; i < 19; ++i)
        le32enc(board->chip_array[0].data_in + 4 * i, work.data[18 - i]);
    board_set_data_in(board, 0);
//  work_id
    board->chip_array[0].work_id[0] = 0;
    board_set_workid(board, 0);
//  start
    board_start(board, 0);
//  wait from nonce come
    while (1)
        if (board_wait_for_nonce(board))
            break;
    memcpy(((uint8_t *) work.data + nonce_offset), board->nonce, 4);
    if (jsonrpc_2)
        memcpy(work.hash, board->hash, 32);


}

int main(int argc, char *argv[]) {
    board_t *board = malloc(sizeof(board_t));
    board_init_chip_array(board);
    work_t work;

}
