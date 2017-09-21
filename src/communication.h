#ifndef COMMUNICATION_H
#define COMMUNICATION_H
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

uint8_t board_open_serials(board_t *board, char* cmd_serial_path, uint32_t cmd_serial_speed, char* nonce_serial_path, uint32_t nonce_serial_speed);
uint8_t board_init_chip_array(board_t *board);
uint8_t board_write_reg(board_t *board, uint8_t chip_id, reg_t reg_type, uint8_t* src);
uint8_t board_read_reg(board_t *board, uint8_t chip_id, reg_t reg_type, uint8_t* dst);
uint8_t board_reset_x11(board_t *board, uint8_t chip_id);
uint8_t board_start_x11(board_t *board, uint8_t chip_id);
uint8_t board_assign_nonce(board_t *board);
uint8_t board_get_nonce_state(board_t *board);
uint8_t board_set_target(board_t *board);
uint8_t board_set_workid(board_t *board, uint8_t chip_id);
uint8_t board_wait_for_nonce(board_t *board);
uint8_t board_set_data_in(board_t *board, uint8_t chip_id);
uint8_t board_choose_chip(board_t *board, uint8_t chip_id);
uint8_t board_get_fifo(board_t *board, uint8_t chip_id);
uint8_t board_display_rate(board_t *board);
uint8_t board_display_counter(board_t *board);
uint8_t board_clear_fifo(board_t *board, uint8_t chip_id);
uint8_t board_soft_reset_chip(board_t *board, uint8_t chip_id);
uint8_t board_start_self_test(board_t *board, uint8_t chip_id);
uint8_t board_flush_fifo(board_t *board, uint8_t chip_id);











uint8_t board_debug_chips(board_t *board, uint8_t chip_id, reg_t reg_type);






uint8_t work_id_table_push(uint8_t* work_id_table, uint8_t* xnonce2, size_t xnonce2_len);
uint8_t work_id_table_find(uint8_t* work_id_table, uint8_t work_id, uint8_t* dst_xnonce2, size_t xnonce2_len);


#endif