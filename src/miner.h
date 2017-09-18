#ifndef __MINER_H__
#define __MINER_H__

#include "miner-config.h"
#include "serial.h"

#define _ALIGN(x) __attribute__ ((aligned(x)))

#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))


#define USER_AGENT PACKAGE_NAME "/" PACKAGE_VERSION
#define MAX_CPUS 16

#ifdef _MSC_VER

#undef USE_ASM  /* to fix */

#ifdef NOASM
#undef USE_ASM
#endif

/* missing arch defines for msvc */
#if defined(_M_X64)
#define __i386__ 1
#define __x86_64__ 1
#elif defined(_M_X86)
#define __i386__ 1
#endif

#endif /* _MSC_VER */

#include <stdbool.h>
#include <inttypes.h>
#include <sys/time.h>

#include <pthread.h>
#include <jansson.h>
#include <curl/curl.h>

#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif

#ifdef HAVE_ALLOCA_H
# include <alloca.h>
#elif !defined alloca
# ifdef __GNUC__
#  define alloca __builtin_alloca
# elif defined _AIX
#  define alloca __alloca
# elif defined _MSC_VER
#  include <malloc.h>
#  define alloca _alloca
# elif !defined HAVE_ALLOCA
#  ifdef  __cplusplus
extern "C"
#  endif
void *alloca (size_t);
# endif
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#define LOG_BLUE 0x10 /* unique value */
#else

enum {
	LOG_ERR,
	LOG_WARNING,
	LOG_NOTICE,
	LOG_INFO,
	LOG_DEBUG,
	LOG_SERIAL,
	/* custom notices */
	LOG_BLUE = 0x10,

};
#endif

#include "compat.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

static inline bool is_windows(void) {
#ifdef WIN32
	return 1;
#else
	return 0;
#endif
}

#if ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define WANT_BUILTIN_BSWAP
#else
#define bswap_32(x) ((((x) << 24) & 0xff000000u) | (((x) << 8) & 0x00ff0000u) \
                   | (((x) >> 8) & 0x0000ff00u) | (((x) >> 24) & 0x000000ffu))
#endif

static inline uint32_t swab32(uint32_t v)
{
#ifdef WANT_BUILTIN_BSWAP
	return __builtin_bswap32(v);
#else
	return bswap_32(v);
#endif
}

#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

typedef unsigned char uchar;

#if !HAVE_DECL_BE32DEC
static inline uint32_t be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
	    ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}
#endif

#if !HAVE_DECL_LE32DEC
static inline uint32_t le32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
	    ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}
#endif

static inline uint64_t le64dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;
    return ((uint64_t)(p[0]) + ((uint64_t)(p[1]) << 8) + ((uint64_t)(p[2]) << 16) + ((uint64_t)(p[3]) << 24) + ((uint64_t)(p[4]) << 32)+ ((uint64_t)(p[5]) << 40)+ ((uint64_t)(p[6]) << 48)+ ((uint64_t)(p[7]) << 56));
}


#if !HAVE_DECL_BE32ENC
static inline void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}
#endif

#if !HAVE_DECL_LE32ENC
static inline void le32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
}
#endif

#if !HAVE_DECL_LE16DEC
static inline uint16_t le16dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint16_t)(p[0]) + ((uint16_t)(p[1]) << 8));
}
#endif

#if !HAVE_DECL_LE16ENC
static inline void le16enc(void *pp, uint16_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
}
#endif

#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads(str, 0, err_ptr)
#define JSON_LOADF(path, err_ptr) json_load_file(path, 0, err_ptr)
#else
#define JSON_LOADS(str, err_ptr) json_loads(str, err_ptr)
#define JSON_LOADF(path, err_ptr) json_load_file(path, err_ptr)
#endif

json_t* json_load_url(char* cfg_url, json_error_t *err);

void sha256_init(uint32_t *state);
void sha256_transform(uint32_t *state, const uint32_t *block, int swap);
void sha256d(unsigned char *hash, const unsigned char *data, int len);

#ifdef USE_ASM
#if defined(__ARM_NEON__) || defined(__i386__) || defined(__x86_64__)
#define HAVE_SHA256_4WAY 1
int sha256_use_4way();
void sha256_init_4way(uint32_t *state);
void sha256_transform_4way(uint32_t *state, const uint32_t *block, int swap);
#endif
#if defined(__x86_64__) && defined(USE_AVX2)
#define HAVE_SHA256_8WAY 1
int sha256_use_8way();
void sha256_init_8way(uint32_t *state);
void sha256_transform_8way(uint32_t *state, const uint32_t *block, int swap);
#endif
#endif

struct work;

int scanhash_x11(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);


typedef enum reg{
    CHIP_ID_REG,            //1				0
    PLL_REG,                //4				1
    BAUDRATE_REG,           //2				2
    CTRL_REG,               //2				3

    DATA_IN_REG,            //76			4
    DATA_OUT_REG,           //64			5
    CORE_SEL_REG,           //2				6
    START_NONCE_REG,        //4				7

    STOP_NONCE_REG,         //4				8
    CYCLES_REG,             //1				9
    DIFF_REG,               //1(6bit)		10
    TARGET_REG,             //8				11

    DATA_IN_VERSION_REG,    //4				12
    DATA_IN_PREV_HASH_REG,  //32			13
    DATA_IN_MERKLE_ROOT_REG,//32			14
    DATA_IN_NTIME_REG,      //4				15

    DATA_IN_NBITS_REG,      //4				16
    WORK_ID_REG,            //1				17
    HASH_COUNTER_REG,       //6				18
    NONCE_COUNTER_REG,      //4				19

    HASH_RATE_REG,			//4				20
    NONCE_RATE_REG,			//4				21
    BAUDRATE_DETECTED_REG,  //2				22
    HASH_OUT_REG,           //64			23
} reg_t;

typedef struct work_id_table{
	uint8_t nxt_work_id;
	uint8_t* work_id_table;
} work_id_table_t;


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



struct cpu_info {
	int thr_id;
	int accepted;
	int rejected;
	double khashes;
	bool has_monitoring;
	float cpu_temp;
	int cpu_fan;
	uint32_t cpu_clock;
};

struct thr_api {
	int id;
	pthread_t pth;
	struct thread_q	*q;
};
/* end of api */
#include "communication.h"
struct thr_info {
    int id;
    pthread_t pth;
    pthread_attr_t attr;
    struct thread_q	*q;
    struct cpu_info cpu;
    board_t board;
};


struct work_restart {
	volatile uint8_t restart;
	char padding[128 - sizeof(uint8_t)];
};

extern bool opt_debug;
extern bool opt_benchmark;
extern bool opt_protocol;
extern bool opt_showdiff;
extern bool opt_quiet;
extern bool opt_redirect;
extern int opt_priority;
extern int opt_timeout;
extern bool want_longpoll;
extern bool have_longpoll;
extern bool have_gbt;
extern bool allow_getwork;
extern bool want_stratum;
extern bool have_stratum;
extern bool opt_stratum_stats;
extern char *opt_cert;
extern char *opt_proxy;
extern long opt_proxy_type;
extern bool use_syslog;
extern bool use_colors;
extern pthread_mutex_t applog_lock;
extern struct thr_info *thr_info;
extern int longpoll_thr_id;
extern int api_thr_id;
extern int opt_n_threads;
extern int num_cpus;
extern struct work_restart *work_restart;
extern uint32_t opt_work_size;
extern double *thr_hashrates;
extern uint64_t global_hashrate;
extern double stratum_diff;
extern double net_diff;
extern double net_hashrate;

#define JSON_RPC_LONGPOLL	(1 << 0)
#define JSON_RPC_QUIET_404	(1 << 1)
#define JSON_RPC_IGNOREERR  (1 << 2)

#define JSON_BUF_LEN 512

#define CL_N    "\x1B[0m"
#define CL_RED  "\x1B[31m"
#define CL_GRN  "\x1B[32m"
#define CL_YLW  "\x1B[33m"
#define CL_BLU  "\x1B[34m"
#define CL_MAG  "\x1B[35m"
#define CL_CYN  "\x1B[36m"

#define CL_BLK  "\x1B[22;30m" /* black */
#define CL_RD2  "\x1B[22;31m" /* red */
#define CL_GR2  "\x1B[22;32m" /* green */
#define CL_BRW  "\x1B[22;33m" /* brown */
#define CL_BL2  "\x1B[22;34m" /* blue */
#define CL_MA2  "\x1B[22;35m" /* magenta */
#define CL_CY2  "\x1B[22;36m" /* cyan */
#define CL_SIL  "\x1B[22;37m" /* gray */

#ifdef WIN32
#define CL_GRY  "\x1B[01;30m" /* dark gray */
#else
#define CL_GRY  "\x1B[90m"    /* dark gray selectable in putty */
#endif
#define CL_LRD  "\x1B[01;31m" /* light red */
#define CL_LGR  "\x1B[01;32m" /* light green */
#define CL_YL2  "\x1B[01;33m" /* yellow */
#define CL_LBL  "\x1B[01;34m" /* light blue */
#define CL_LMA  "\x1B[01;35m" /* light magenta */
#define CL_LCY  "\x1B[01;36m" /* light cyan */

#define CL_WHT  "\x1B[01;37m" /* white */

void applog(int prio, const char *fmt, ...);
void restart_threads(void);
extern json_t *json_rpc_call(CURL *curl, const char *url, const char *userpass,
	const char *rpc_req, int *curl_err, int flags);
void bin2hex(char *s, const unsigned char *p, size_t len);
char *abin2hex(const unsigned char *p, size_t len);
bool hex2bin(unsigned char *p, const char *hexstr, size_t len);
bool jobj_binary(const json_t *obj, const char *key, void *buf, size_t buflen);
int varint_encode(unsigned char *p, uint64_t n);
size_t address_to_script(unsigned char *out, size_t outsz, const char *addr);
int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y);
bool fulltest(const uint32_t *hash, const uint32_t *target);
void work_set_target(struct work* work, double diff);
double target_to_diff(uint32_t* target);
void diff_to_target(uint32_t *target, double diff);
uint8_t target_to_zeros(uint32_t* target);

double hash_target_ratio(uint32_t* hash, uint32_t* target);
void work_set_target_ratio(struct work* work, uint32_t* hash);

void get_currentalgo(char* buf, int sz);
bool has_aes_ni(void);
void cpu_bestfeature(char *outbuf, size_t maxsz);
void cpu_getname(char *outbuf, size_t maxsz);
void cpu_getmodelid(char *outbuf, size_t maxsz);
float cpu_temp(int core);

struct work {
	uint32_t data[48];
	uint32_t target[8];

	double targetdiff;
	double shareratio;
	double sharediff;
	uint32_t resnonce;

	int height;
	char *txs;
	char *workid;

	char *job_id;
	size_t xnonce2_len;
	unsigned char *xnonce2;
};

struct stratum_job {
	char *job_id;
	unsigned char prevhash[32];
	size_t coinbase_size;
	unsigned char *coinbase;
	unsigned char *xnonce2;
	int merkle_count;
	unsigned char **merkle;
	unsigned char version[4];
	unsigned char nbits[4];
	unsigned char ntime[4];
	unsigned char claim[32]; // lbry
	bool clean;
	double diff;
};

struct stratum_ctx {
	char *url;

	CURL *curl;
	char *curl_url;
	char curl_err_str[CURL_ERROR_SIZE];
	curl_socket_t sock;
	size_t sockbuf_size;
	char *sockbuf;
	pthread_mutex_t sock_lock;

	double next_diff;
	double sharediff;

	char *session_id;
	size_t xnonce1_size;
	unsigned char *xnonce1;
	size_t xnonce2_size;
	struct stratum_job job;
	struct work work;
	pthread_mutex_t work_lock;

	int bloc_height;
};

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout);
bool stratum_send_line(struct stratum_ctx *sctx, char *s);
char *stratum_recv_line(struct stratum_ctx *sctx);
bool stratum_connect(struct stratum_ctx *sctx, const char *url);
void stratum_disconnect(struct stratum_ctx *sctx);
bool stratum_subscribe(struct stratum_ctx *sctx);
bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass);
bool stratum_handle_method(struct stratum_ctx *sctx, const char *s);

/* rpc 2.0 (xmr) */
extern bool jsonrpc_2;
extern bool aes_ni_supported;
extern char rpc2_id[64];
extern char *rpc2_blob;
extern size_t rpc2_bloblen;
extern uint32_t rpc2_target;
extern char *rpc2_job_id;

json_t *json_rpc2_call(CURL *curl, const char *url, const char *userpass, const char *rpc_req, int *curl_err, int flags);
bool rpc2_login(CURL *curl);
bool rpc2_login_decode(const json_t *val);
bool rpc2_workio_login(CURL *curl);
bool rpc2_stratum_job(struct stratum_ctx *sctx, json_t *params);
bool rpc2_job_decode(const json_t *job, struct work *work);

struct thread_q;

struct thread_q *tq_new(void);
void tq_free(struct thread_q *tq);
bool tq_push(struct thread_q *tq, void *data);
void *tq_pop(struct thread_q *tq, const struct timespec *abstime);
void tq_freeze(struct thread_q *tq);
void tq_thaw(struct thread_q *tq);

void parse_arg(int key, char *arg);
void parse_config(json_t *config, char *ref);
void proper_exit(int reason);

void applog_compare_hash(void *hash, void *hash_ref);
void applog_hex(void *data, int len);
void applog_hash(void *hash);
void applog_hash64(void *hash);
void format_hashrate(double hashrate, char *output);
void print_hash_tests(void);

void sha256d(unsigned char *hash, const unsigned char *data, int len);
void x11hash(void *output, const void *input);

#endif /* __MINER_H__ */