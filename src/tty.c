#include "miner.h"
#include "communication.h"

extern char *tty_path;
extern uint32_t tty_speed;
uint8_t writing_flag=1; //0 不发 1 发
void ttyhash(void *output, void *input, uint8_t *restart)
{
    serial_t serial;	
	uint8_t gnonce[4];

    if (serial_open(&serial, tty_path, tty_speed) < 0) {
        applog(LOG_ERR, "serial_open(): %s\n", serial_errmsg(&serial));
        exit(1);
    }
    uint8_t read_flag = 0;
    if(writing_flag){
    	writing_flag = 0;
    	serial_write(&serial,input,80);
    	applog(LOG_DEBUG,"writing to tty");
    }
    do {
        read_flag = (uint8_t) serial_read(&serial, gnonce, 4, 100);
    } while (!read_flag && !(*restart));
    if (read_flag)
    {
    	applog(LOG_INFO,"nonce found");
    }
	uint32_t hash[8];
    serial_close(&serial);
    uint32_t newinput[20];
    memcpy((void*)newinput,input,76);
	memcpy((void*)&newinput[19],(void*)gnonce,4);
    memcpy(input, newinput, 80);
    x11hash(hash,newinput);
	memcpy(output, hash, 32);
}
//
//int scanhash_tty(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
//{
//	uint32_t _ALIGN(128) hash[8];
//	uint32_t _ALIGN(128) endiandata[20];
//	uint32_t *pdata = work->data;
//	uint32_t *ptarget = work->target;
//	double diff = 1.0/1024;
//	diff_to_target(ptarget,diff);
//	writing_flag = 1;
//	applog(LOG_DEBUG,"open scanhash_tty function");
//	uint8_t zeros = target_to_zeros(ptarget);
//	const uint32_t Htarg = ptarget[7];
//	const uint32_t first_nonce = pdata[19];
//	uint32_t nonce = first_nonce;
//	volatile uint8_t *restart = &(work_restart[thr_id].restart);
//
//	if (opt_benchmark)
//		ptarget[7] = 0x0cff;
//
//	for (int k=0; k < 19; k++)
//		be32enc(&endiandata[k], pdata[k]);
//
//	do {
//		be32enc(&endiandata[19], zeros);
//		ttyhash(hash, endiandata, restart);
//
//		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
//			work_set_target_ratio(work, hash);
//			pdata[19] = nonce;
//			*hashes_done = pdata[19] - first_nonce;
//			applog(LOG_DEBUG,"hash done, going to submit");
//			return 1;
//		} else {
//			applog(LOG_DEBUG,"useless hash from tty");
//		}
//
//	} while (nonce < max_nonce && !(*restart));
//
//	pdata[19] = nonce;
//	*hashes_done = pdata[19] - first_nonce + 1;
//	return 0;
//}
//
//int scanhash_uart(int thr_id, struct work *work, uint32_t max_nonce, board_t *board)
//{
//	uint32_t _ALIGN(128) hash[8];
//	uint32_t _ALIGN(128) endiandata[20];
//	uint32_t *pdata = work->data;
//	uint32_t *ptarget = work->target;
//    volatile uint8_t *restart = &(work_restart[thr_id].restart);
//    board_set_diff(*board, work);
//    board_set_data_in(*board, 0, work);
//
//	do {
//		if (board_wait_for_nonce(*board, work)) {
//			work_set_target_ratio(work, hash);
//			applog(LOG_DEBUG, "hash done, going to submit");
//			return 1;
//		}
//	} while (!(*restart));
//	return 0;
//}
