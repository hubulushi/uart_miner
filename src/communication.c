#include "miner.h"

uint8_t reg_size[24]= {1, 4, 2, 2, 76, 64, 2, 4, 4, 1, 1, 8, 4, 32, 32, 4, 4, 1, 6, 4, 4, 4, 2, 64};
extern long nonce_cnt;
extern char *cmd_path, *nonce_path;
extern uint32_t cmd_speed, nonce_speed;
uint8_t board_choose_chip(board_t *board, uint8_t chip_id){
    // TX: 1 0xxx xxxx (for example 1 0000 0001 is select No.1 chip; 1 0000 0000 means select all lines)
    if (board->current_chip == chip_id)
        return 0;
    applog(LOG_SERIAL, "[SERIAL_CHOSE] chip set to %d", chip_id);
    board->current_chip = chip_id;
    uint8_t buf = 0xFF;
    uint8_t data_in = 0x00;
    data_in += chip_id;
    serial_set_parity(&board->cmd_serial, PARITY_MARK);
    serial_write(&board->cmd_serial, &data_in, 1);
    serial_read(&board->cmd_serial, &buf, 1, -1);
    if (buf != data_in) {
        applog(LOG_ERR, "chip_choose(serial_t *serial, chip_t *chip) error:%02x->%02x", data_in, buf);
        serial_read(&board->cmd_serial, &buf, 32, 100);
        serial_close(&board->cmd_serial);
        serial_close(&board->nonce_serial);
        exit(1);
    } else {
        return 0;
    }
}
uint8_t board_open_serials(board_t *board, char* cmd_serial_path, uint32_t cmd_serial_speed, char* nonce_serial_path, uint32_t nonce_serial_speed){
    if (serial_open_advanced(&board->cmd_serial, cmd_serial_path, cmd_serial_speed, 8, PARITY_MARK, 1, false, false)) {
        applog(LOG_ERR, "cmd_serial error: %s", serial_errmsg(&board->cmd_serial));
        serial_close(&board->cmd_serial);
        serial_close(&board->nonce_serial);
        exit(1);
    }
    if (serial_open_advanced(&board->nonce_serial, nonce_serial_path, nonce_serial_speed, 8, PARITY_MARK, 1, false, false)) {
        applog(LOG_ERR, "nonce_serial error: %s", serial_errmsg(&board->nonce_serial));
        serial_close(&board->cmd_serial);
        serial_close(&board->nonce_serial);
        exit(1);
    }
    return 0;
}
uint8_t board_write_reg(board_t *board, uint8_t chip_id, reg_t reg_type, uint8_t* src){
// read a chip's certain reg
// TX: 0 1000 xxxx
//     0 xxxx xxxx * n
//
    uint8_t len = reg_size[reg_type];
    uint8_t cmd_msg = 0x80;
    board_choose_chip(board,chip_id);
    uint8_t read_buf[len+1];
    cmd_msg += reg_type;
    serial_set_parity(&board->cmd_serial, PARITY_SPACE);
    //send command
    serial_write(&board->cmd_serial, &cmd_msg, 1);
    //send data
    serial_write(&board->cmd_serial, src, len);
    //get by_pass data(command, data) and check
    serial_read(&board->cmd_serial, read_buf, 1+len, -1);
    char* hex = abin2hex((uchar*)read_buf, 1+len);
    if (*read_buf!=cmd_msg) {
        applog(LOG_ERR,"chip_write_reg(serial_t *serial, chip_t* chip, uint8_t* buf_in, uint8_t %d, reg_t %d) error: %02x->%02x", len, reg_type, cmd_msg, *read_buf);
        serial_close(&board->cmd_serial);
        serial_close(&board->nonce_serial);
        exit(1);
    } else {
        applog(LOG_SERIAL, "[SERIAL_WRITE] chip %d reg %d: %s", chip_id, reg_type, hex);
    }
    return 0;
}
uint8_t board_read_reg(board_t *board, uint8_t chip_id, reg_t reg_type, uint8_t* dst){
    // read a certain chip's reg on one serial;
// 0 0000 xxxx
// 0 xxxx xxxx(read data)
    uint8_t len = reg_size[reg_type];
    uint8_t* temp_buf=malloc(len+1);
    board_choose_chip(board, chip_id);
    uint8_t data_in = 0x00;
    data_in += reg_type;
    serial_set_parity(&board->cmd_serial, PARITY_SPACE);
    //write command
    serial_write(&board->cmd_serial, &data_in, 1);
    //read by_pass data(command) and reg data from chip
    serial_read(&board->cmd_serial, temp_buf, 1+len, -1);
    char* hex = abin2hex(temp_buf, 1+len);
    applog(LOG_SERIAL, "[SERIAL_READ ] chip %d reg %d: %s", chip_id, reg_type, hex);
    if (*temp_buf!=data_in) {
        applog(LOG_ERR, "board_read_reg : %02x->%02x", data_in, *temp_buf);
        serial_close(&board->cmd_serial);
        serial_close(&board->nonce_serial);
        exit(1);
    } else {
        if (reg_type == DATA_OUT_REG){
            uint8_t check_xor = *(temp_buf+1);
            for (int i = 2; i < len; ++i) {
                check_xor ^= *(temp_buf+i);
            }
//          confirm the read_xor can't be same with check_xor
            uint8_t read_xor = (uint8_t) (check_xor - 1);
            serial_read(&board->cmd_serial, &read_xor, 1, -1);
            if (read_xor != check_xor) {
                applog(LOG_ERR, "DATA_OUT_REG check failed");
            }
        }
        memcpy(dst,temp_buf+1,len);
        free(temp_buf);
    }
    return 0;
}
uint8_t board_assign_nonce(board_t *board){
//    uint32_t nonce_step = 0xffffffffU / board->chip_nums;
    uint32_t nonce_step = 0x00400000U;
    uint32_t nonce = 0x00000000U;
    for (uint8_t i = 1; i <= board->chip_nums; ++i) {
        le32enc(&board->chip_array[i].start_nonce,nonce);
        nonce+=nonce_step;
        le32enc(&board->chip_array[i].stop_nonce,nonce);
        nonce++;
        board_write_reg(board, i, START_NONCE_REG, board->chip_array[i].start_nonce);
        board_write_reg(board, i, STOP_NONCE_REG, board->chip_array[i].stop_nonce);
    }
    return 0;
}
uint8_t board_init_chip_array(board_t *board){
    board_open_serials(board, cmd_path, cmd_speed, nonce_path, nonce_speed);
    uint8_t data_in = 0x80;
    uint8_t* buf = malloc(1);
    serial_set_parity(&board->cmd_serial, PARITY_MARK);
    board_hard_reset(board);
    serial_write(&board->cmd_serial, &data_in, 1);
    serial_read(&board->cmd_serial, buf, 1, -1);
    board->chip_nums = (uint8_t) (*(buf) - 0x80);
    if (!board->chip_nums) {
        applog(LOG_ERR, "press the button...");
        exit(1);
    }
    applog(LOG_INFO,"miner has %d chips, serial open succeeded", board->chip_nums);
    for (uint8_t i = 0; i < board->chip_nums; ++i) {
//      i = 0 means broadcast address
        *board->chip_array[i].chip_id = i;
    }
//    make sure next choose can choose all chip
    board->current_chip = 0xFF;
    board_reset_x11(board,0);
    uint8_t cycle_reg[1] = {0x4E};
    board_write_reg(board, 0, CYCLES_REG, cycle_reg);
    board_assign_nonce(board);
    uint8_t core_sel[2] = {0x01, 0x00};
    board_write_reg(board, 0, CORE_SEL_REG, core_sel);
    for (uint8_t j = 1; j <= board->chip_nums; ++j) {
        board_start_self_test(board, j);
    }
    board_write_reg(board, 0, CORE_SEL_REG, core_sel);
    return 0;
}
uint8_t board_start_self_test(board_t *board, uint8_t chip_id){
    //CTRL_REG:
    //BYTE1    N_OUTPUT START DIFF_TYPE RESET   TEST    FIFO2   FIFO1   FIFO0
    //             1      0       0       1       1       0       0       0
    //BYTE0     ENABLE   RSV     RSV     RSV     RSV    FLUSH  RESTART   ERR
    //             1      0       0       0       0       0       0       0
    uint8_t test_cmd[2]={0xC8, 0x80};
    board_write_reg(board, chip_id, CTRL_REG, test_cmd);
    sleep(1);
    board_read_reg(board, chip_id, CTRL_REG, test_cmd);
    if (test_cmd[1]&0x01) {
        applog(LOG_ERR, "chip %d error", chip_id);
        uint8_t disable_chip_cmd[2] = {0x80, 0x00};
        board_write_reg(board, chip_id, CTRL_REG, disable_chip_cmd);
        board->chip_array[chip_id].disable = 1;
        } else {
        uint8_t disable_test_cmd[2] = {0x90, 0x80};
        board_write_reg(board, chip_id, CTRL_REG, disable_test_cmd);
    }
}
uint8_t board_set_target(board_t *board){
    board_write_reg(board, 0, TARGET_REG, board->chip_array->target);
    return 0;
}
uint8_t board_set_data_in(board_t *board, uint8_t chip_id){
    board_write_reg(board, chip_id, DATA_IN_REG, board->chip_array[chip_id].data_in);
    return 0;
}
uint8_t board_set_workid(board_t *board, uint8_t chip_id){
    board_write_reg(board, chip_id, WORK_ID_REG, board->chip_array[chip_id].work_id);
    return 0;
}
uint8_t board_reset_x11(board_t *board, uint8_t chip_id){
//    read firstly, use "and" to START bit to combine.
    //CTRL_REG:
    //BYTE1    N_OUTPUT START DIFF_TYPE RESET   TEST    FIFO2   FIFO1   FIFO0
    //             1      0       0       1       0       0       0       0
    //BYTE0     ENABLE   RSV     RSV     RSV     RSV    FLUSH   RESART   ERR
    //             1      0       0       0       0       0       0       0
    uint8_t reset_cmd[2] = {0x90, 0x80};
    board_write_reg(board, chip_id, CTRL_REG, reset_cmd);
}
uint8_t board_start_x11(board_t *board, uint8_t chip_id){
    //CTRL_REG:
    //BYTE1    N_OUTPUT START DIFF_TYPE RESET   TEST    FIFO2   FIFO1   FIFO0
    //             1      1       0       1       0       0       0       0
    //BYTE0     ENABLE   RSV     RSV     RSV     RSV    FLUSH   RESET    ERR
    //             1      0       0       0       0       1       0       0
    uint8_t start_cmd[2] = {0xC0, 0x80};
    board_write_reg(board, chip_id, CTRL_REG, start_cmd);
}
uint8_t board_wait_for_nonce(board_t *board){
    uint8_t nonce_data[7];
    uint32_t nonce;
    uint8_t check_sum=0x00;
    if(serial_read(&board->nonce_serial, nonce_data, 7, 1000)>0){
        for (int i = 1; i < 7; ++i)
            check_sum^=nonce_data[i];
        if (check_sum != nonce_data[0])
            applog(LOG_WARNING, "[SERIAL_NONCE] check sum not match.");
        memcpy(board->work_id, nonce_data, 1);
        nonce = le32dec(nonce_data+2);
        memcpy(board->nonce, &nonce, 4);
        char* nonce_data_str = abin2hex(nonce_data,7);
        char* nonce_hex = abin2hex(board->nonce, 4);
        char* work_id_hex = abin2hex(board->work_id, 1);
        applog(LOG_SERIAL, "[SERIAL_NONCE] nonce_cnt: %d, data: %s, nonce: %s, work_id: %s", nonce_cnt, nonce_data_str, nonce_hex, work_id_hex);
        return 1;
    }
    return 0;
}
uint8_t board_get_fifo(board_t *board, uint8_t chip_id){
    //CTRL_REG:
    //BYTE1    N_OUTPUT START DIFF_TYPE RESET   TEST    FIFO2   FIFO1   FIFO0
    //             1      0       0       1       0       0       0       0
    //BYTE0     ENABLE   RSV     RSV     RSV     RSV    FLUSH  RESTART   ERR
    //             1      0       0       0       0       1       0       0
    uint8_t ctrl_data[2] = {0x00, 0x00};
    board_read_reg(board, chip_id, CTRL_REG, ctrl_data);
    uint8_t fifo_status = (uint8_t) (ctrl_data[0]&0x07);
    applog(LOG_DEBUG, "chip %d fifo has %d data", chip_id, fifo_status);
    if (fifo_status < 3)
        return 1;
    else
        return 0;
}
uint8_t board_display_rate(board_t *board){
    uint8_t hash_rate[4] = {0};
    uint8_t nonce_rate[4] = {0};
    for (uint8_t i = 1; i <= board->chip_nums; ++i) {
        board_read_reg(board, i, HASH_RATE_REG, hash_rate);
        board_read_reg(board, i, NONCE_RATE_REG, nonce_rate);
        applog(LOG_INFO, "HASH rate of chip %d is %d", i, le32dec(hash_rate));
        applog(LOG_INFO, "NONCE rate of chip %d is %d", i, le32dec(nonce_rate));
    }
    return 0;
}
uint8_t board_display_counter(board_t *board){
    uint8_t hash_counter[8] = {0};
    uint8_t nonce_counter[4] = {0};
    for (uint8_t i = 1; i <= board->chip_nums; ++i) {
        board_read_reg(board, i, HASH_COUNTER_REG, hash_counter);
        board_read_reg(board, i, NONCE_COUNTER_REG, nonce_counter);
        applog(LOG_INFO, "HASH count of chip %d is %d", i, le64dec(hash_counter));
        applog(LOG_INFO, "NONCE count of chip %d is %d", i, le32dec(nonce_counter));
    }
    return 0;
}
uint8_t board_flush_fifo(board_t *board, uint8_t chip_id){
    //CTRL_REG:
    //BYTE1    N_OUTPUT START DIFF_TYPE RESET   TEST    FIFO2   FIFO1   FIFO0
    //             1      0       0       0       0       0       0       0
    //BYTE0     ENABLE   RSV     RSV     RSV     RSV    FLUSH  RESTART   ERR
    //             1      0       0       0       0       1       0       0
    uint8_t reset_cmd[2] = {0x80, 0x84};
    board_write_reg(board, chip_id, CTRL_REG, reset_cmd);
    return 0;
}
uint8_t board_soft_reset_chip(board_t *board, uint8_t chip_id){
    //    read firstly, use "and" to START bit to combine.
    //CTRL_REG:
    //BYTE1    N_OUTPUT START DIFF_TYPE RESET   TEST    FIFO2   FIFO1   FIFO0
    //             1      0       0       1       0       0       0       0
    //BYTE0     ENABLE   RSV     RSV     RSV     RSV    FLUSH   RESET    ERR
    //             1      0       0       0       0       1       0       0
    uint8_t reset_cmd[2] = {0x90, 0x80};
    board_write_reg(board, chip_id, CTRL_REG, reset_cmd);
}
uint8_t board_hard_reset(board_t *board){
    //TODO: need to add GPIO to reset whole board.
    return 0;
}