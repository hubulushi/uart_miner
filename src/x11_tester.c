#include <stdio.h>
#include <inttypes.h>
#include <memory.h>
#include <stdlib.h>
#include <stdbool.h>
#include "communication.h"
#include "serial.h"

#include "../sha3/sph_blake.h"
#include "../sha3/sph_bmw.h"
#include "../sha3/sph_groestl.h"
#include "../sha3/sph_jh.h"
#include "../sha3/sph_keccak.h"
#include "../sha3/sph_skein.h"
#include "../sha3/sph_luffa.h"
#include "../sha3/sph_cubehash.h"
#include "../sha3/sph_shavite.h"
#include "../sha3/sph_simd.h"
#include "../sha3/sph_echo.h"

typedef struct chip_info
{
    uint8_t chip_id[1];
    uint8_t pll[4];
    uint8_t baudrate[2];
    uint8_t ctrl[1];
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
    uint8_t	nonce_rate[4];
} chip_t;

typedef struct board_info{
    serial_t cmd_serial;
    serial_t nonce_serial;
    uint8_t chip_nums;
    chip_t chip_array[128];
    uint8_t nonce[4];
    uint8_t work_id[4];
    uint8_t current_chip;
} board_t;

void x11hash(void *output, const void *input)
{
    sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_skein512_context     ctx_skein;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;

    sph_luffa512_context		ctx_luffa1;
    sph_cubehash512_context		ctx_cubehash1;
    sph_shavite512_context		ctx_shavite1;
    sph_simd512_context		ctx_simd1;
    sph_echo512_context		ctx_echo1;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t  hashA[16], hashB[16];

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, 80);
    sph_blake512_close (&ctx_blake, hashA);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, hashA, 64);
    sph_bmw512_close(&ctx_bmw, hashB);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, hashB, 64);
    sph_groestl512_close(&ctx_groestl, hashA);

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, hashA, 64);
    sph_skein512_close (&ctx_skein, hashB);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashB, 64);
    sph_jh512_close(&ctx_jh, hashA);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashA, 64);
    sph_keccak512_close(&ctx_keccak, hashB);

    sph_luffa512_init (&ctx_luffa1);
    sph_luffa512 (&ctx_luffa1, hashB, 64);
    sph_luffa512_close (&ctx_luffa1, hashA);

    sph_cubehash512_init (&ctx_cubehash1);
    sph_cubehash512 (&ctx_cubehash1, hashA, 64);
    sph_cubehash512_close(&ctx_cubehash1, hashB);

    sph_shavite512_init (&ctx_shavite1);
    sph_shavite512 (&ctx_shavite1, hashB, 64);
    sph_shavite512_close(&ctx_shavite1, hashA);

    sph_simd512_init (&ctx_simd1);
    sph_simd512 (&ctx_simd1, hashA, 64);
    sph_simd512_close(&ctx_simd1, hashB);

    sph_echo512_init (&ctx_echo1);
    sph_echo512 (&ctx_echo1, hashB, 64);
    sph_echo512_close(&ctx_echo1, hashA);

    memcpy(output, hashA, 32);
}


bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
    char hex_byte[3];
    char *ep;

    hex_byte[2] = '\0';

    while (*hexstr && len) {
        if (!hexstr[1]) {
            printf("hex2bin str truncated");
            return false;
        }
        hex_byte[0] = hexstr[0];
        hex_byte[1] = hexstr[1];
        *p = (unsigned char) strtol(hex_byte, &ep, 16);
        if (*ep) {
            printf("hex2bin failed on '%s'", hex_byte);
            return false;
        }
        p++;
        hexstr += 2;
        len--;
    }

    return(!len) ? true : false;
/*	return (len == 0 && *hexstr == 0) ? true : false; */
}

char *abin2hex(const unsigned char *p, size_t len)
{
    char *s = (char*) malloc((len * 2) + 1);
    if (!s)
        return NULL;
    bin2hex(s, p, len);
    return s;
}

void bin2hex(char *s, const unsigned char *p, size_t len)
{
    for (size_t i = 0; i < len; i++)
        sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);
}


int main(){
    board_t *board = malloc(sizeof(board_t));
    board_soft_reset_chip(board,0);
    board_init_chip_array(board);

    uint8_t data_in[76] = {0x00, 0x00, 0x00, 0x20, 0xa2, 0xb1, 0x75, 0x4b, 0x4f, 0x8e, 0x65, 0x26, 0x8e, 0xd6, 0x8b, 0x48, 0xec, 0xe2, 0xdc, 0x66, 0xb9, 0x16, 0x9b, 0xf7, 0xb7, 0xad, 0x02, 0xb3, 0x1d, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0xeb, 0x33, 0x31, 0x48, 0x67, 0x50, 0x55, 0x3c, 0x77, 0x28, 0xd2, 0xb3, 0xa5, 0x29, 0x97, 0x35, 0x0e, 0xcd, 0x6f, 0x88, 0x9c, 0x4f, 0x91, 0x53, 0xdd, 0xb4, 0x2a, 0x5c, 0x0f, 0xf7, 0x66, 0x4f, 0x52, 0x95, 0x59, 0xa4, 0x78, 0x16, 0x1a};
    for (int k = 0; k < 38; ++k) {
        uint8_t temp = data_in[75-k];
        data_in[75-k] = data_in[k];
        data_in[k] = temp;
    }
    memcpy(board->chip_array->data_in, data_in, 76);

}