#ifndef COMMUNICATION_H
#define COMMUNICATION_H
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "serial.h"
typedef enum reg {
    CHIP_ID_REG,
    PLL_REG,
    BAUDRATE_REG,
    CTRL_REG,
    DATA_IN_REG,
    DATA_OUT_REG,
    CORE_SEL_REG,
    START_NONCE_REG,
    STOP_NONCE_REG,
    CYCLES_REG,
    DIFF_REG,
    TARGET_REG,
    DATA_IN_VERSION_REG,
    DATA_IN_PREV_HASH_REG,
    DATA_IN_MERKLE_ROOT_REG,
    DATA_IN_NTIME_REG,
    DATA_IN_NBITS_REG,
    WORK_ID_REG,
    HASH_COUNTER_REG,
    NONCE_COUNTER_REG,
    HASH_RATE_REG,
    NONCE_RATE_REG,
    BAUDRATE_DETECTED_REG,
    HASH_OUT_REG,
    CORE_ENABLE_REG
} reg_t;
typedef struct chip_info {
    uint8_t disable;
    uint16_t chip_id[2];
    uint8_t pll[4];
    uint8_t baudrate[2];
    uint8_t ctrl[2];
    uint8_t data_in[76];
    uint8_t data_out[64];
    uint8_t core_sel[2];
    uint8_t start_nonce[4];
    uint8_t stop_nonce[4];
    uint8_t cycles[1];
    uint8_t diff[1];
    uint8_t target[8];
    uint8_t data_in_version[4];
    uint8_t data_in_prev_hash[32];
    uint8_t data_in_merkle_root[32];
    uint8_t data_in_ntime[4];
    uint8_t data_in_nbits[4];
    uint8_t work_id[1];
    uint8_t hash_counter[6];
    uint8_t nonce_counter[4];
    uint8_t hash_rate[4];
    uint8_t nonce_rate[4];
} chip_t;
typedef struct board_info {
    serial_t cmd_serial;
    serial_t nonce_serial;
    uint16_t chip_nums;
    chip_t chip_array[65535];
    uint8_t nonce[4];
    uint8_t work_id[4];
    uint16_t current_chip;
    uint8_t hash[32];
    volatile uint8_t *restart_flag;
} board_t;
uint8_t board_open_serials(board_t *board, char* cmd_serial_path, uint32_t cmd_serial_speed, char* nonce_serial_path, uint32_t nonce_serial_speed);
uint8_t board_init_chip_array(board_t *board);
uint8_t board_write_reg(board_t *board, uint16_t chip_id, reg_t reg_type, uint8_t *src);
uint8_t board_read_reg(board_t *board, uint16_t chip_id, reg_t reg_type, uint8_t *dst);
uint8_t board_reset(board_t *board, uint16_t chip_id);
uint8_t board_start(board_t *board, uint16_t chip_id);
uint8_t board_assign_nonce(board_t *board);
uint8_t board_get_nonce_state(board_t *board);
uint8_t board_set_target(board_t *board);
uint8_t board_set_workid(board_t *board, uint16_t chip_id);

uint8_t board_enable_subcore(board_t *board, uint16_t chip_id, uint16_t subcore);
uint8_t board_wait_for_nonce(board_t *board);
uint8_t board_set_data_in(board_t *board, uint16_t chip_id);
uint8_t board_choose_chip(board_t *board, uint16_t chip_id);
uint8_t board_get_fifo(board_t *board, uint16_t chip_id);
uint8_t board_display_rate(board_t *board);
uint8_t board_display_counter(board_t *board);
uint8_t board_soft_reset_chip(board_t *board, uint16_t chip_id);
uint8_t board_start_self_test(board_t *board, uint16_t chip_id);
uint8_t board_flush_fifo(board_t *board, uint16_t chip_id);
uint8_t board_debug_chips(board_t *board, uint16_t chip_id, reg_t reg_type);
uint8_t board_hard_reset(board_t *board);
#endif