/*
 */


#include <nginx.h>
#include "ngx_http_upstream_check_module.h"

#include "../ngx_common/ngx_common_util.h"

#if (NGX_HTTP_UPSTREAM_XFDF_IP_HASH)
#include "ngx_http_upstream_xfdf_ip_hash_module.h"
#endif

typedef struct ngx_http_upstream_check_peer_s ngx_http_upstream_check_peer_t;
typedef struct ngx_http_upstream_check_srv_conf_s
    ngx_http_upstream_check_srv_conf_t;


#pragma pack(push, 1)

typedef struct {
    u_char                                   major;
    u_char                                   minor;
} ngx_ssl_protocol_version_t;


typedef struct {
    u_char                                   msg_type;
    ngx_ssl_protocol_version_t               version;
    uint16_t                                 length;

    u_char                                   handshake_type;
    u_char                                   handshake_length[3];
    ngx_ssl_protocol_version_t               hello_version;

    time_t                                   time;
    u_char                                   random[28];

    u_char                                   others[0];
} ngx_ssl_server_hello_t;


typedef struct {
    u_char                                   packet_length[3];
    u_char                                   packet_number;

    u_char                                   protocol_version;
    u_char                                   others[0];
} ngx_mysql_handshake_init_t;


typedef struct {
    uint16_t                                 preamble;
    uint16_t                                 length;
    u_char                                   type;
} ngx_ajp_raw_packet_t;

#pragma pack()


typedef struct {
    ngx_buf_t                                send;
    ngx_buf_t                                recv;

    ngx_uint_t                               state;
    ngx_http_status_t                        status;

    size_t                                   padding;
    size_t                                   length;
} ngx_http_upstream_check_ctx_t;

#define var_max_count  20

struct vars_hash_t{
    ngx_uint_t name_hash[var_max_count] ;
    ngx_uint_t count ;
} vars_hash ;

typedef struct {
	ngx_str_t  var_name ;
    ngx_str_t  f_conf ;
} var_hash_conf_t;

struct vars_hash_conf_t{
	var_hash_conf_t                          v_fs[var_max_count];
    ngx_uint_t                               count ;
} vars_hash_conf;

typedef struct {
    ngx_shmtx_t                              mutex;
#if (nginx_version >= 1002000)
    ngx_shmtx_sh_t                           lock;
#else
    ngx_atomic_t                             lock;
#endif

    ngx_pid_t                                owner;

    ngx_msec_t                               access_time;

    ngx_uint_t                               fall_count;
    ngx_uint_t                               rise_count;

    ngx_uint_t                               busyness;
    ngx_uint_t                               access_count;

    struct sockaddr                         *sockaddr;
    socklen_t                                socklen;

    ngx_atomic_t                             down;

    u_char                                   padding[64];
    //by zgk , force the server down, it is invalid for check , if ==1 only forcedown , if ==2 forcedown and output error log
    ngx_atomic_t                             force_down;
    //by zgk , the weight of server
    ngx_atomic_t                             weight;
    //the varialty of weight of the peer
    ngx_atomic_i_t                           v_weight;
    //the varialty of total_weight,only in 1st peer of upstream
    ngx_atomic_i_t                           v_total_weight;
    //upstream name in hash code
    ngx_uint_t                                upstream_name;

} ngx_http_upstream_check_peer_shm_t;


#define    var_name_max_len      100
#define    var_hash_max_count    50
#define    var_list_max_count    20
#define    var_group_max_count   20
#define    var_max_access_ip    50

typedef struct {
	//name of nginx variable
	u_char                                   var_name[var_name_max_len];
	//the value of nginx variable list
	ngx_uint_t                               values_hash[var_hash_max_count];//不保存名称而只使用哈希值是因为占用预留空间过大
} ngx_variables_item;

typedef struct {
	//nginx variable list
    ngx_variables_item                       var_items[var_list_max_count];
} ngx_variables_item_list;

typedef struct {// a user variable point to a nginx variable list
	//user variable hash name
	ngx_uint_t                               var_name_hash;
	//nginx variable list
	ngx_variables_item_list                  variable;
	//nginx variable group , for "and" operation
	ngx_variables_item_list                  variable_group[var_group_max_count];
} ngx_variable ;

typedef struct {
    in_addr_t         mask;
    in_addr_t         addr;
    ngx_uint_t        deny;      /* unsigned  deny:1; */
} ngx_http_access_rule_t;

typedef struct {
    ngx_uint_t                               generation;
    ngx_uint_t                               checksum;
    ngx_uint_t                               number;
    //how many user variables
    ngx_variable                            vars[var_max_count];

    //deny or allow ips
    ngx_http_access_rule_t                  ips[var_max_access_ip];

    /* ngx_http_upstream_check_status_peer_t */
    ngx_http_upstream_check_peer_shm_t       peers[1];
} ngx_http_upstream_check_peers_shm_t;


#define NGX_HTTP_CHECK_CONNECT_DONE          0x0001
#define NGX_HTTP_CHECK_SEND_DONE             0x0002
#define NGX_HTTP_CHECK_RECV_DONE             0x0004
#define NGX_HTTP_CHECK_ALL_DONE              0x0008


typedef ngx_int_t (*ngx_http_upstream_check_packet_init_pt)
    (ngx_http_upstream_check_peer_t *peer);
typedef ngx_int_t (*ngx_http_upstream_check_packet_parse_pt)
    (ngx_http_upstream_check_peer_t *peer);
typedef void (*ngx_http_upstream_check_packet_clean_pt)
    (ngx_http_upstream_check_peer_t *peer);

struct ngx_http_upstream_check_peer_s {
    ngx_flag_t                               state;
    ngx_pool_t                              *pool;
    ngx_uint_t                               index;
    ngx_uint_t                               max_busy;
    ngx_str_t                               *upstream_name;
    ngx_addr_t                              *check_peer_addr;
    ngx_addr_t                              *peer_addr;
    ngx_event_t                              check_ev;
    ngx_event_t                              check_timeout_ev;
    ngx_peer_connection_t                    pc;

    void                                    *check_data;
    ngx_event_handler_pt                     send_handler;
    ngx_event_handler_pt                     recv_handler;

    ngx_http_upstream_check_packet_init_pt   init;
    ngx_http_upstream_check_packet_parse_pt  parse;
    ngx_http_upstream_check_packet_clean_pt  reinit;

    ngx_http_upstream_check_peer_shm_t      *shm;
    ngx_http_upstream_check_srv_conf_t      *conf;
    //the real peer address
    ngx_http_upstream_rr_peer_t             *peer_mem_addr;
    //init weight of peer
    ngx_uint_t                              weight;

};


typedef struct {
    ngx_str_t                                check_shm_name;
    ngx_uint_t                               checksum;
    ngx_array_t                              peers;

    ngx_http_upstream_check_peers_shm_t     *peers_shm;
} ngx_http_upstream_check_peers_t;


#define NGX_HTTP_CHECK_TCP                   0x0001
#define NGX_HTTP_CHECK_HTTP                  0x0002
#define NGX_HTTP_CHECK_SSL_HELLO             0x0004
#define NGX_HTTP_CHECK_MYSQL                 0x0008
#define NGX_HTTP_CHECK_AJP                   0x0010

#define NGX_CHECK_HTTP_2XX                   0x0002
#define NGX_CHECK_HTTP_3XX                   0x0004
#define NGX_CHECK_HTTP_4XX                   0x0008
#define NGX_CHECK_HTTP_5XX                   0x0010
#define NGX_CHECK_HTTP_ERR                   0x8000

typedef struct {
    ngx_uint_t                               type;

    ngx_str_t                                name;

    ngx_str_t                                default_send;

    /* HTTP */
    ngx_uint_t                               default_status_alive;

    ngx_event_handler_pt                     send_handler;
    ngx_event_handler_pt                     recv_handler;

    ngx_http_upstream_check_packet_init_pt   init;
    ngx_http_upstream_check_packet_parse_pt  parse;
    ngx_http_upstream_check_packet_clean_pt  reinit;

    unsigned need_pool;
    unsigned need_keepalive;
} ngx_check_conf_t;


typedef void (*ngx_http_upstream_check_status_format_pt) (ngx_buf_t *b,
    ngx_http_upstream_check_peers_t *peers, ngx_uint_t flag);

typedef struct {
    ngx_str_t                                format;
    ngx_str_t                                content_type;

    ngx_http_upstream_check_status_format_pt output;
} ngx_check_status_conf_t;


#define NGX_CHECK_STATUS_DOWN                0x0001
#define NGX_CHECK_STATUS_UP                  0x0002

typedef struct {
    ngx_check_status_conf_t                 *format;
    ngx_flag_t                               flag;
} ngx_http_upstream_check_status_ctx_t;


typedef ngx_int_t (*ngx_http_upstream_check_status_command_pt)
    (ngx_http_upstream_check_status_ctx_t *ctx, ngx_str_t *value);

typedef struct {
    ngx_str_t                                 name;
    ngx_http_upstream_check_status_command_pt handler;
} ngx_check_status_command_t;


typedef struct {
    ngx_uint_t                               shm_size;
    ngx_http_upstream_check_peers_t         *peers;
} ngx_http_upstream_check_main_conf_t;


struct ngx_http_upstream_check_srv_conf_s {
    ngx_uint_t                               port;
    ngx_uint_t                               fall_count;
    ngx_uint_t                               rise_count;
    ngx_msec_t                               check_interval;
    ngx_msec_t                               check_timeout;
    ngx_uint_t                               check_keepalive_requests;

    ngx_check_conf_t                        *check_type_conf;
    ngx_str_t                                send;

    union {
        ngx_uint_t                           return_code;
        ngx_uint_t                           status_alive;
    } code;

    ngx_array_t                             *fastcgi_params;

    ngx_uint_t                               default_down;
    
    //by zgk , directive check is valid
    ngx_uint_t                              check_cmd_on;
};


typedef struct {
    ngx_check_status_conf_t                 *format;
} ngx_http_upstream_check_loc_conf_t;


typedef struct {
    u_char  version;
    u_char  type;
    u_char  request_id_hi;
    u_char  request_id_lo;
    u_char  content_length_hi;
    u_char  content_length_lo;
    u_char  padding_length;
    u_char  reserved;
} ngx_http_fastcgi_header_t;


typedef struct {
    u_char  role_hi;
    u_char  role_lo;
    u_char  flags;
    u_char  reserved[5];
} ngx_http_fastcgi_begin_request_t;


typedef struct {
    u_char  version;
    u_char  type;
    u_char  request_id_hi;
    u_char  request_id_lo;
} ngx_http_fastcgi_header_small_t;


typedef struct {
    ngx_http_fastcgi_header_t         h0;
    ngx_http_fastcgi_begin_request_t  br;
    ngx_http_fastcgi_header_small_t   h1;
} ngx_http_fastcgi_request_start_t;


#define NGX_HTTP_FASTCGI_RESPONDER      1

#define NGX_HTTP_FASTCGI_KEEP_CONN      1

#define NGX_HTTP_FASTCGI_BEGIN_REQUEST  1
#define NGX_HTTP_FASTCGI_ABORT_REQUEST  2
#define NGX_HTTP_FASTCGI_END_REQUEST    3
#define NGX_HTTP_FASTCGI_PARAMS         4
#define NGX_HTTP_FASTCGI_STDIN          5
#define NGX_HTTP_FASTCGI_STDOUT         6
#define NGX_HTTP_FASTCGI_STDERR         7
#define NGX_HTTP_FASTCGI_DATA           8


typedef enum {
    ngx_http_fastcgi_st_version = 0,
    ngx_http_fastcgi_st_type,
    ngx_http_fastcgi_st_request_id_hi,
    ngx_http_fastcgi_st_request_id_lo,
    ngx_http_fastcgi_st_content_length_hi,
    ngx_http_fastcgi_st_content_length_lo,
    ngx_http_fastcgi_st_padding_length,
    ngx_http_fastcgi_st_reserved,
    ngx_http_fastcgi_st_data,
    ngx_http_fastcgi_st_padding
} ngx_http_fastcgi_state_e;


static ngx_http_fastcgi_request_start_t  ngx_http_fastcgi_request_start = {
    { 1,                                               /* version */
      NGX_HTTP_FASTCGI_BEGIN_REQUEST,                  /* type */
      0,                                               /* request_id_hi */
      1,                                               /* request_id_lo */
      0,                                               /* content_length_hi */
      sizeof(ngx_http_fastcgi_begin_request_t),        /* content_length_lo */
      0,                                               /* padding_length */
      0 },                                             /* reserved */

    { 0,                                               /* role_hi */
      NGX_HTTP_FASTCGI_RESPONDER,                      /* role_lo */
      0, /* NGX_HTTP_FASTCGI_KEEP_CONN */              /* flags */
      { 0, 0, 0, 0, 0 } },                             /* reserved[5] */

    { 1,                                               /* version */
      NGX_HTTP_FASTCGI_PARAMS,                         /* type */
      0,                                               /* request_id_hi */
      1 },                                             /* request_id_lo */

};


static ngx_int_t ngx_http_upstream_check_add_timers(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_upstream_check_peek_one_byte(ngx_connection_t *c);

static void ngx_http_upstream_check_begin_handler(ngx_event_t *event);
static void ngx_http_upstream_check_connect_handler(ngx_event_t *event);

static void ngx_http_upstream_check_peek_handler(ngx_event_t *event);

static void ngx_http_upstream_check_send_handler(ngx_event_t *event);
static void ngx_http_upstream_check_recv_handler(ngx_event_t *event);

static void ngx_http_upstream_check_discard_handler(ngx_event_t *event);
static void ngx_http_upstream_check_dummy_handler(ngx_event_t *event);

static ngx_int_t ngx_http_upstream_check_http_init(
    ngx_http_upstream_check_peer_t *peer);
static ngx_int_t ngx_http_upstream_check_http_parse(
    ngx_http_upstream_check_peer_t *peer);
static ngx_int_t ngx_http_upstream_check_parse_status_line(
    ngx_http_upstream_check_ctx_t *ctx, ngx_buf_t *b,
    ngx_http_status_t *status);
static void ngx_http_upstream_check_http_reinit(
    ngx_http_upstream_check_peer_t *peer);

static ngx_buf_t *ngx_http_upstream_check_create_fastcgi_request(
    ngx_pool_t *pool, ngx_str_t *params, ngx_uint_t num);

static ngx_int_t ngx_http_upstream_check_fastcgi_parse(
    ngx_http_upstream_check_peer_t *peer);
static ngx_int_t ngx_http_upstream_check_fastcgi_process_record(
    ngx_http_upstream_check_ctx_t *ctx, ngx_buf_t *b,
    ngx_http_status_t *status);
static ngx_int_t ngx_http_upstream_check_parse_fastcgi_status(
    ngx_http_upstream_check_ctx_t *ctx, ngx_buf_t *b,
    ngx_http_status_t *status);

static ngx_int_t ngx_http_upstream_check_ssl_hello_init(
    ngx_http_upstream_check_peer_t *peer);
static ngx_int_t ngx_http_upstream_check_ssl_hello_parse(
    ngx_http_upstream_check_peer_t *peer);
static void ngx_http_upstream_check_ssl_hello_reinit(
    ngx_http_upstream_check_peer_t *peer);

static ngx_int_t ngx_http_upstream_check_mysql_init(
    ngx_http_upstream_check_peer_t *peer);
static ngx_int_t ngx_http_upstream_check_mysql_parse(
    ngx_http_upstream_check_peer_t *peer);
static void ngx_http_upstream_check_mysql_reinit(
    ngx_http_upstream_check_peer_t *peer);

static ngx_int_t ngx_http_upstream_check_ajp_init(
    ngx_http_upstream_check_peer_t *peer);
static ngx_int_t ngx_http_upstream_check_ajp_parse(
    ngx_http_upstream_check_peer_t *peer);
static void ngx_http_upstream_check_ajp_reinit(
    ngx_http_upstream_check_peer_t *peer);

static void ngx_http_upstream_check_status_update(
    ngx_http_upstream_check_peer_t *peer,
    ngx_int_t result);

static void ngx_http_upstream_check_clean_event(
    ngx_http_upstream_check_peer_t *peer);

static void ngx_http_upstream_check_timeout_handler(ngx_event_t *event);
static void ngx_http_upstream_check_finish_handler(ngx_event_t *event);

static ngx_int_t ngx_http_upstream_check_need_exit();
static void ngx_http_upstream_check_clear_all_events();

static ngx_int_t ngx_http_upstream_check_status_handler(
    ngx_http_request_t *r);

static void ngx_http_upstream_check_status_parse_args(ngx_http_request_t *r,
    ngx_http_upstream_check_status_ctx_t *ctx);

static ngx_int_t ngx_http_upstream_check_status_command_format(
    ngx_http_upstream_check_status_ctx_t *ctx, ngx_str_t *value);
static ngx_int_t ngx_http_upstream_check_status_command_status(
    ngx_http_upstream_check_status_ctx_t *ctx, ngx_str_t *value);

static void ngx_http_upstream_check_status_html_format(ngx_buf_t *b,
    ngx_http_upstream_check_peers_t *peers, ngx_uint_t flag);
static void ngx_http_upstream_check_status_csv_format(ngx_buf_t *b,
    ngx_http_upstream_check_peers_t *peers, ngx_uint_t flag);
static void ngx_http_upstream_check_status_json_format(ngx_buf_t *b,
    ngx_http_upstream_check_peers_t *peers, ngx_uint_t flag);

static ngx_int_t ngx_http_upstream_check_addr_change_port(ngx_pool_t *pool,
    ngx_addr_t *dst, ngx_addr_t *src, ngx_uint_t port);

static ngx_check_conf_t *ngx_http_get_check_type_conf(ngx_str_t *str);

static char *ngx_http_upstream_check(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_upstream_check_keepalive_requests(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_upstream_check_http_send(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_upstream_check_http_expect_alive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static char *ngx_http_upstream_check_fastcgi_params(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static char *ngx_http_upstream_check_shm_size(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static ngx_check_status_conf_t *ngx_http_get_check_status_format_conf(
    ngx_str_t *str);
static char *ngx_http_upstream_check_status(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static void *ngx_http_upstream_check_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_check_init_main_conf(ngx_conf_t *cf,
    void *conf);

static void *ngx_http_upstream_check_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_check_init_srv_conf(ngx_conf_t *cf, void *conf);

static void *ngx_http_upstream_check_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_upstream_check_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_upstream_modify_conf(ngx_conf_t *cf);

#define SHM_NAME_LEN 256

static char *ngx_http_upstream_check_init_shm(ngx_conf_t *cf, void *conf);

static ngx_int_t ngx_http_upstream_check_get_shm_name(ngx_str_t *shm_name,
    ngx_pool_t *pool, ngx_uint_t generation);
static ngx_shm_zone_t *ngx_shared_memory_find(ngx_cycle_t *cycle,
    ngx_str_t *name, void *tag);
static ngx_http_upstream_check_peer_shm_t *
ngx_http_upstream_check_find_shm_peer(ngx_http_upstream_check_peers_shm_t *peers_shm,
    ngx_addr_t *addr ,ngx_str_t *upname);

static ngx_int_t ngx_http_upstream_check_init_shm_peer(
    ngx_http_upstream_check_peer_shm_t *peer_shm,
    ngx_http_upstream_check_peer_shm_t *opeer_shm,
    ngx_uint_t init_down, ngx_pool_t *pool, ngx_str_t *peer_name);

static ngx_int_t ngx_http_upstream_check_init_shm_zone(
    ngx_shm_zone_t *shm_zone, void *data);


static ngx_int_t ngx_http_upstream_check_init_process(ngx_cycle_t *cycle);

static void custom_variable_set_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t custom_variable_get_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);


static ngx_conf_bitmask_t  ngx_check_http_expect_alive_masks[] = {
    { ngx_string("http_2xx"), NGX_CHECK_HTTP_2XX },
    { ngx_string("http_3xx"), NGX_CHECK_HTTP_3XX },
    { ngx_string("http_4xx"), NGX_CHECK_HTTP_4XX },
    { ngx_string("http_5xx"), NGX_CHECK_HTTP_5XX },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_upstream_check_commands[] = {

    { ngx_string("check"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_check,
      0,
      0,
      NULL },

    { ngx_string("check_keepalive_requests"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_check_keepalive_requests,
      0,
      0,
      NULL },

    { ngx_string("check_http_send"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_check_http_send,
      0,
      0,
      NULL },

    { ngx_string("check_http_expect_alive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_check_http_expect_alive,
      0,
      0,
      NULL },

    { ngx_string("check_fastcgi_param"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE2,
      ngx_http_upstream_check_fastcgi_params,
      0,
      0,
      NULL },

    { ngx_string("shm_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_check_shm_size,
      0,
      0,
      NULL },

    { ngx_string("check_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1|NGX_CONF_NOARGS,
      ngx_http_upstream_check_status,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_check_module_ctx = {
    NULL,                                     /* preconfiguration */
	ngx_http_upstream_modify_conf,                                    /* postconfiguration */

    ngx_http_upstream_check_create_main_conf,/* create main configuration */
    ngx_http_upstream_check_init_main_conf,  /* init main configuration */

    ngx_http_upstream_check_create_srv_conf, /* create server configuration */
    NULL,                                    /* merge server configuration */

    ngx_http_upstream_check_create_loc_conf, /* create location configuration */
    ngx_http_upstream_check_merge_loc_conf   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_check_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_check_module_ctx,   /* module context */
    ngx_http_upstream_check_commands,      /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_upstream_check_init_process,  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t fastcgi_default_request;
static ngx_str_t fastcgi_default_params[] = {
    ngx_string("REQUEST_METHOD"), ngx_string("GET"),
    ngx_string("REQUEST_URI"), ngx_string("/"),
    ngx_string("SCRIPT_FILENAME"), ngx_string("index.php"),
};


#define NGX_SSL_RANDOM "NGX_HTTP_CHECK_SSL_HELLO\n\n\n\n"

/*
 * This is the SSLv3 CLIENT HELLO packet used in conjunction with the
 * check type of ssl_hello to ensure that the remote server speaks SSL.
 *
 * Check RFC 2246 (TLSv1.0) sections A.3 and A.4 for details.
 */
static char sslv3_client_hello_pkt[] = {
    "\x16"                /* ContentType         : 0x16 = Hanshake           */
    "\x03\x01"            /* ProtocolVersion     : 0x0301 = TLSv1.0          */
    "\x00\x6f"            /* ContentLength       : 0x6f bytes after this one */
    "\x01"                /* HanshakeType        : 0x01 = CLIENT HELLO       */
    "\x00\x00\x6b"        /* HandshakeLength     : 0x6b bytes after this one */
    "\x03\x03"            /* Hello Version       : 0x0303 = TLSv1.2          */
    "\x00\x00\x00\x00"    /* Unix GMT Time (s)   : filled with <now> (@0x0B) */
    NGX_SSL_RANDOM        /* Random              : must be exactly 28 bytes  */
    "\x00"                /* Session ID length   : empty (no session ID)     */
    "\x00\x1a"            /* Cipher Suite Length : \x1a bytes after this one */
    "\xc0\x2b" "\xc0\x2f" "\xcc\xa9" "\xcc\xa8"  /* 13 modern ciphers        */
    "\xc0\x0a" "\xc0\x09" "\xc0\x13" "\xc0\x14"
    "\x00\x33" "\x00\x39" "\x00\x2f" "\x00\x35"
    "\x00\x0a"
    "\x01"                /* Compression Length  : 0x01 = 1 byte for types   */
    "\x00"                /* Compression Type    : 0x00 = NULL compression   */
    "\x00\x28"            /* Extensions length */
    "\x00\x0a"            /* EC extension */
    "\x00\x08"            /* extension length */
    "\x00\x06"            /* curves length */
    "\x00\x17" "\x00\x18" "\x00\x19" /* Three curves */
    "\x00\x0d"            /* Signature extension */
    "\x00\x18"            /* extension length */
    "\x00\x16"            /* hash list length */
    "\x04\x01" "\x05\x01" "\x06\x01" "\x02\x01"  /* 11 hash algorithms */
    "\x04\x03" "\x05\x03" "\x06\x03" "\x02\x03"
    "\x05\x02" "\x04\x02" "\x02\x02"
};


#define NGX_SSL_HANDSHAKE    0x16
#define NGX_SSL_SERVER_HELLO 0x02


#define NGX_AJP_CPING        0x0a
#define NGX_AJP_CPONG        0x09


static char ngx_ajp_cping_packet[] = {
    0x12, 0x34, 0x00, 0x01, NGX_AJP_CPING, 0x00
};

static char ngx_ajp_cpong_packet[] = {
    0x41, 0x42, 0x00, 0x01, NGX_AJP_CPONG
};


static ngx_check_conf_t  ngx_check_types[] = {

    { NGX_HTTP_CHECK_TCP,
      ngx_string("tcp"),
      ngx_null_string,
      0,
      ngx_http_upstream_check_peek_handler,
      ngx_http_upstream_check_peek_handler,
      NULL,
      NULL,
      NULL,
      0,
      1 },

    { NGX_HTTP_CHECK_HTTP,
      ngx_string("http"),
      ngx_string("GET / HTTP/1.0\r\n\r\n"),
      NGX_CONF_BITMASK_SET | NGX_CHECK_HTTP_2XX | NGX_CHECK_HTTP_3XX,
      ngx_http_upstream_check_send_handler,
      ngx_http_upstream_check_recv_handler,
      ngx_http_upstream_check_http_init,
      ngx_http_upstream_check_http_parse,
      ngx_http_upstream_check_http_reinit,
      1,
      1 },

    { NGX_HTTP_CHECK_HTTP,
      ngx_string("fastcgi"),
      ngx_null_string,
      0,
      ngx_http_upstream_check_send_handler,
      ngx_http_upstream_check_recv_handler,
      ngx_http_upstream_check_http_init,
      ngx_http_upstream_check_fastcgi_parse,
      ngx_http_upstream_check_http_reinit,
      1,
      0 },

    { NGX_HTTP_CHECK_SSL_HELLO,
      ngx_string("ssl_hello"),
      ngx_string(sslv3_client_hello_pkt),
      0,
      ngx_http_upstream_check_send_handler,
      ngx_http_upstream_check_recv_handler,
      ngx_http_upstream_check_ssl_hello_init,
      ngx_http_upstream_check_ssl_hello_parse,
      ngx_http_upstream_check_ssl_hello_reinit,
      1,
      0 },

    { NGX_HTTP_CHECK_MYSQL,
      ngx_string("mysql"),
      ngx_null_string,
      0,
      ngx_http_upstream_check_send_handler,
      ngx_http_upstream_check_recv_handler,
      ngx_http_upstream_check_mysql_init,
      ngx_http_upstream_check_mysql_parse,
      ngx_http_upstream_check_mysql_reinit,
      1,
      0 },

    { NGX_HTTP_CHECK_AJP,
      ngx_string("ajp"),
      ngx_string(ngx_ajp_cping_packet),
      0,
      ngx_http_upstream_check_send_handler,
      ngx_http_upstream_check_recv_handler,
      ngx_http_upstream_check_ajp_init,
      ngx_http_upstream_check_ajp_parse,
      ngx_http_upstream_check_ajp_reinit,
      1,
      0 },

    { 0,
      ngx_null_string,
      ngx_null_string,
      0,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      0,
      0 }
};


static ngx_check_status_conf_t  ngx_check_status_formats[] = {

    { ngx_string("html"),
      ngx_string("text/html"),
      ngx_http_upstream_check_status_html_format },

    { ngx_string("csv"),
      ngx_string("text/plain"),
      ngx_http_upstream_check_status_csv_format },

    { ngx_string("json"),
      ngx_string("application/json"), /* RFC 4627 */
      ngx_http_upstream_check_status_json_format },

    { ngx_null_string, ngx_null_string, NULL }
};


static ngx_check_status_command_t ngx_check_status_commands[] =  {

    { ngx_string("format"),
      ngx_http_upstream_check_status_command_format },

    { ngx_string("status"),
      ngx_http_upstream_check_status_command_status },

    { ngx_null_string, NULL }
};

static ngx_uint_t ngx_http_upstream_check_shm_generation = 0;
static ngx_http_upstream_check_peers_t *check_peers_ctx = NULL;
static ngx_str_t one=ngx_string("1");
static ngx_str_t zero=ngx_string("0");
//static ngx_conf_t *check_conf = NULL ;
static ngx_str_t http_head=ngx_string("http_");
static ngx_str_t http_arg=ngx_string("arg_");
static ngx_str_t http_uri=ngx_string("uri");
static ngx_str_t http_body=ngx_string("body_");
static ngx_str_t http_split=ngx_string("split_");

static ngx_http_variable_t  ngx_http_custom_var_default = {
    ngx_null_string, custom_variable_set_value, custom_variable_get_value, 0, NGX_HTTP_VAR_CHANGEABLE, 0
};

ngx_variable *get_variable_by_hash(ngx_uint_t var_name_hash){
	ngx_int_t i =0;
	ngx_variable *vars =check_peers_ctx->peers_shm->vars ;
	while(i<var_max_count && vars[i].var_name_hash >0 ){
		if(vars[i].var_name_hash == var_name_hash){
			break;
		}
		i++;
	}
	vars[i].var_name_hash = var_name_hash ;
	return &vars[i];
}

ngx_variable *get_variable_by_name(ngx_str_t *var_name){
	ngx_uint_t var_name_hash = ngx_str_2_hash(var_name);
	return get_variable_by_hash(var_name_hash);
}

ngx_variables_item_list *get_variable_items_by_hash(ngx_uint_t var_name_hash){
	ngx_variable *vars =get_variable_by_hash(var_name_hash);
	return &vars->variable;
}

ngx_variables_item_list *get_variable_items(ngx_str_t *var_name){
	ngx_uint_t var_name_hash = ngx_str_2_hash(var_name);
	return get_variable_items_by_hash(var_name_hash);
}

void ngx_preload_var_conf(ngx_str_t *var_name , ngx_str_t *conf)
{
	vars_hash_conf.v_fs[vars_hash_conf.count].var_name.data = var_name->data;
	vars_hash_conf.v_fs[vars_hash_conf.count].var_name.len = var_name->len;
	vars_hash_conf.v_fs[vars_hash_conf.count].f_conf.data = conf->data;
	vars_hash_conf.v_fs[vars_hash_conf.count].f_conf.len = conf->len;
	vars_hash_conf.count++;
}

void ngx_reload_var_conf(ngx_str_t *f , ngx_str_t *var_name /*ngx_int_t flag*/)
{
	ngx_fd_t          fd;
	size_t            size;
	u_char              *buf ,*hdbuf ;
	ssize_t           n;
	ngx_file_info_t   fi;
	//
	ngx_int_t i = -1 , j=0 ,gp_i=0 , tmp_i=0;
	u_char gp_flag = 0;
	ngx_uint_t sz = 0;
	ngx_variable *var = get_variable_by_name(var_name);

	if(var == NULL) return;

	ngx_variables_item_list *items;
	ngx_variables_item_list *var_item = &var->variable;
	ngx_variables_item_list *var_item_group = var->variable_group;

	fd = ngx_open_file(f->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd != NGX_INVALID_FILE) {
    	ngx_fd_info(fd, &fi);
    	if ( ngx_fd_info(fd, &fi) != NGX_FILE_ERROR) {
//            size = lseek(fd, 0, SEEK_END);
    		ngx_memzero(&var_item->var_items, sizeof(var_item->var_items));
    		ngx_memzero(var_item_group, sizeof(var->variable_group));
    		size = fi.st_size;
            if (size > 0){
            	hdbuf = buf = malloc(size+1);
                if (buf != NULL){
                	n = ngx_read_fd(fd, buf, size);
                    if (n > 0){
                        buf[size]='\0';
//                        items->items[0].var_name[0] = '\0';
                        items = var_item;
                    	while ( *buf != '\0' ){
                    	    sz = read_line(buf);
                    	    if(sz > 0){
                    	    	if (*buf == '{' && gp_i<var_group_max_count) { //begin group
                    	    		if (gp_flag == 0){
                        	    		gp_flag = 1;
                        	    		items = &var_item_group[gp_i++];
                        	    		tmp_i = i;
                        	    		i=-1;
                    	    		}
                	    			goto tail; //if already in group model than ignore current line
                    	    	}
                    	    	if (*buf == '}') {
                    	    		if (gp_flag == 1){
                        	    		gp_flag=0;
                        	    		items = var_item;
                        	    		i=tmp_i;
                    	    		}
                    	    		goto tail;
                    	    	}

                                if ( *buf == '[' && *(buf+sz-1) ==']' ){ //a variable
                                	i++;
                                	j = 0;
                                	cpy_chars(items->var_items[i].var_name , buf+1 ,sz-2 ); //except '[' and ']'
                                	items->var_items[i+1].var_name[0] = '\0';
                                } else {
                                	if (i >= 0 && i<var_list_max_count && *buf != '#'){
                                		if(j < var_hash_max_count){
                                	        items->var_items[i].values_hash[j++] = ngx_chars_2_hash(buf,sz);
                                	        items->var_items[i].values_hash[j] = 0;
                                		} else {//if the count of values more than [var_list_max_count] ,then create new variable(same name) for more values
                                			i++;
                                			j = 0;
                                			cpy_chars(items->var_items[i].var_name , items->var_items[i-1].var_name ,var_name_max_len );
                                			items->var_items[i+1].var_name[0] = '\0';
                                			items->var_items[i].values_hash[j++] = ngx_chars_2_hash(items->var_items[i].var_name,strlen((char*)items->var_items[i].var_name));
                                			items->var_items[i].values_hash[j] = 0;
                                		}
                                	}
                                }
                              tail:
                    	    	buf += sz;
                    	    	if(*buf == '\0'){
                    	    		break;
                    	    	}

                    	    }
                    	    buf++;
                    	}

                    }
                    free(hdbuf);
                }

            }
    	}

    	if (ngx_close_file(fd) == NGX_FILE_ERROR) {
//            ngx_log_error(NGX_LOG_ALERT, cf->log, ngx_errno,ngx_close_file_n " %s failed",f->data);
        }

    }

}


ngx_buf_t *ngx_list_var(ngx_pool_t *pool, ngx_str_t *var_name /*ngx_int_t flag*/)
{
    ngx_buf_t                  *buf;
    ngx_int_t i,j,k;

    ngx_variable *var = get_variable_by_name(var_name);

   	ngx_variables_item_list *var_item = &var->variable;
   	ngx_variables_item_list *var_item_group = var->variable_group;

    buf = ngx_create_temp_buf(pool, sizeof(ngx_variable));
	if (buf != NULL) {
	    buf->last = ngx_sprintf(buf->last, "pid is :%P\n", ngx_pid );

	    i=0; j=0; k=0;
	    while(i<var_list_max_count && var_item->var_items[i].var_name[0]){
	        ngx_str_t n;
	        n.data = var_item->var_items[i].var_name;
	        n.len = strlen((char*)var_item->var_items[i].var_name);
	        buf->last = ngx_sprintf(buf->last, "name is :%V\n", &n );
	        while (j<var_hash_max_count && var_item->var_items[i].values_hash[j] > 0){
		        buf->last = ngx_sprintf(buf->last, "%l\n", var_item->var_items[i].values_hash[j] );
	    	    j++;
	        }
	        j=0;
	        i++ ;
	    }
	    //variable group
	    i=0; j=0; k=0;
	    while(k<var_group_max_count && var_item_group[k].var_items[i].var_name[0]){
	    	buf->last = ngx_sprintf(buf->last, "{\n" );
	    	while(i<var_list_max_count && var_item_group[k].var_items[i].var_name[0]){
	    		ngx_str_t n;
				n.data = var_item_group[k].var_items[i].var_name;
				n.len = strlen((char*)var_item_group[k].var_items[i].var_name);
				buf->last = ngx_sprintf(buf->last, "name is :%V\n", &n );
				while (j<var_hash_max_count && var_item_group[k].var_items[i].values_hash[j] > 0){
					buf->last = ngx_sprintf(buf->last, "%l\n", var_item_group[k].var_items[i].values_hash[j] );
					j++;
				}
				j=0;
				i++ ;
	    	}
	    	k++;
	    	i=0; j=0;
	    	buf->last = ngx_sprintf(buf->last, "}\n" );
	    }
    }
	return buf;
}

ngx_int_t
int_in_ints(ngx_uint_t *array , ngx_uint_t value ,size_t len)
{
	while(len > 0) {
		if(array[--len] == value){
			return NGX_TRUE;
		}
	}
	return NGX_FALSE;
}

static ngx_int_t custom_variable_and_value( ngx_http_request_t *r,ngx_variables_item_list *items , ngx_int_t all)
{
	ngx_str_t s,s_tmp ,s_token;
	ngx_str_t *sh;
	ngx_uint_t *idx = NULL ;
	ngx_http_variable_value_t *vl;
	ngx_int_t i=0,j=0, fg,ret,sz=0;
	u_char split_c ,*s_t;

	fg= NGX_TRUE;
	ret = NGX_FALSE;

	while(fg && i<var_list_max_count && items->var_items[i].var_name[0]){
		s.data = items->var_items[i].var_name;
		s.len = strlen((char*)items->var_items[i].var_name);

		if (s.len > http_split.len+2 && ngx_str_startwith( s.data, http_split.data, http_split.len)
		      && s.data[http_split.len+1]=='_' ){//split_,_
			split_c = s.data[http_split.len];//delimiter
			s.data += http_split.len+2;
			s.len = s.len - http_split.len - 2 ;
		} else {
			split_c = 0;
		}

		s_tmp.len=0;
		if (s.len >= http_head.len && ngx_str_startwith( s.data, http_head.data, http_head.len) ) {//$http_
			sh = ngx_http_get_variable_head(r,s.data+http_head.len , s.len - http_head.len);
			if(sh){
				s_tmp.data = sh->data;
				s_tmp.len = sh->len;
			}
		} else if (s.len >= http_arg.len && ngx_str_startwith( s.data, http_arg.data, http_arg.len) ) {//$arg_
			s.data = s.data+http_arg.len;
			s.len = s.len - http_arg.len;
			ngx_http_get_param_value(r,s.data,s.len, &s_tmp);
		} else if ( !ngx_strncmp(s.data, http_uri.data, http_uri.len) ){//uri
			s_tmp.data = r->uri.data;
			s_tmp.len = r->uri.len;
		} else if (s.len >= http_body.len && ngx_str_startwith( s.data, http_body.data, http_body.len) ) {//post body
			s.data = s.data + http_body.len;
			s.len = s.len - http_body.len;
			s_tmp.len=0;
			ngx_http_get_post_param(r,s.data,s.len, &s_tmp);
		} else {
			vl = ngx_http_get_variable_req(r , &s);
			if(vl){
				s_tmp.data = vl->data;
				s_tmp.len = vl->len;
			}
		}
		if(s_tmp.len > 0){
			if (split_c){
				sz = ngx_str_find_chr_count(s_tmp.data , s_tmp.len ,split_c);
				sz++;
				idx = ngx_palloc(r->pool, sz*sizeof(ngx_uint_t));
				sh=&s_tmp;
				while( j < sz){
					s_t = ngx_str_sch_next_trimtoken(sh->data ,sh->len ,split_c,&s_token);
					if(s_token.len > 0){
						idx[j]=ngx_str_2_hash(&s_token);
						sh->len = sh->len - (s_t - sh->data) +1;
						sh->data = s_t;
						j++;
					}else {
						break;
					}
				}
			} else {
				sz=1;
				idx = ngx_palloc(r->pool, sz*sizeof(ngx_uint_t));
				idx[0]=ngx_str_2_hash(&s_tmp);
			}
		}
		//
		j = 0;
		ret = NGX_FALSE;
		while(j<var_hash_max_count && idx && items->var_items[i].values_hash[j] > 0) {
			if (int_in_ints(idx,items->var_items[i].values_hash[j++],sz)){
				if(all){
				    fg = NGX_TRUE;
				    ret = NGX_TRUE;
				}else{
				    fg = NGX_FALSE;
				    ret = NGX_TRUE;
				}
				break;
			} else {
				if(all){
			        fg = NGX_FALSE;
				}
			}
		}

		j=0;
		i++;
	}

	return ret;
}


static void custom_variable_set_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	//
}

static ngx_int_t custom_variable_get_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	//
	if(data <= 0 ){
		return NGX_ERROR;
	}

/*  ngx_str_t s;
	ngx_str_t *sh;
	ngx_uint_t idx = 0;
	ngx_http_variable_value_t *vl;
	*/
    ngx_int_t i=0,j=NGX_FALSE;

    ngx_variable *var = get_variable_by_hash(data);
   	if(var == NULL) return NGX_ERROR;

  	ngx_variables_item_list *items;
   	ngx_variables_item_list *var_item = &var->variable;
   	ngx_variables_item_list *var_item_group = var->variable_group;



    v->data = zero.data;
	v->len = zero.len;
	v->valid = 0;

	items = var_item_group;
	while(i<var_group_max_count && items[i].var_items[0].var_name[0]){
		j = custom_variable_and_value(r, &items[i],NGX_TRUE);
		if(j == NGX_TRUE){
			v->data = one.data;
			v->len = one.len;
			v->valid = 1;
			break;
		}
		i++;
		continue;
	}

	if(j == NGX_FALSE) {
		items = var_item;
		if( custom_variable_and_value(r,items,NGX_FALSE) ){
		    v->data = one.data;
			v->len = one.len;
			v->valid = 1;
		}
	}

	return NGX_OK;
}


ngx_uint_t
ngx_http_upstream_check_add_peer(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us, ngx_http_upstream_rr_peer_t *peer_mem_addr)
{
    ngx_http_upstream_check_peer_t       *peer;
    ngx_http_upstream_check_peers_t      *peers;
    ngx_http_upstream_check_srv_conf_t   *ucscf;
    ngx_http_upstream_check_main_conf_t  *ucmcf;
    ngx_http_upstream_rr_peer_t          *pr;

    if (us->srv_conf == NULL) {
        return NGX_ERROR;
    }
    
    pr = peer_mem_addr;

    ucscf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_check_module);

    /*if ( !ucscf->check_cmd_on ){
        ngx_str_t ccf;
        ccf.len=4;
        ccf.data=(u_char*)"http";
        ucscf->check_type_conf=ngx_http_get_check_type_conf(&ccf);
        ucscf->check_interval=30000;
    }*/

//    if(ucscf->check_cmd_on && ucscf->check_interval == 0) {
//        return NGX_ERROR;
//    }

    ucmcf = ngx_http_conf_get_module_main_conf(cf,
                                               ngx_http_upstream_check_module);
    peers = ucmcf->peers;

    peer = ngx_array_push(&peers->peers);
    if (peer == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(peer, sizeof(ngx_http_upstream_check_peer_t));
    
    peer->peer_addr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));

    peer->index = peers->peers.nelts - 1;
    peer->conf = ucscf;
    peer->upstream_name = &us->host;
    peer->peer_addr->sockaddr = pr->sockaddr;
    peer->peer_addr->socklen = pr->socklen;
    peer->weight = pr->weight;
//    ngx_memcpy(&peer->peer_addr->name.data,pr->name.data, pr->name.len);
//    peer->peer_addr->name.len=pr->name.len;
    peer->peer_addr->name.len=pr->name.len;
    peer->peer_addr->name.data=pr->name.data;
    peer->peer_mem_addr = peer_mem_addr;

    if (ucscf->port) {
        peer->check_peer_addr = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
        if (peer->check_peer_addr == NULL) {
            return NGX_ERROR;
        }

        if (ngx_http_upstream_check_addr_change_port(cf->pool,
                peer->check_peer_addr, peer->peer_addr, ucscf->port)
            != NGX_OK) {

            return NGX_ERROR;
        }

    } else {
        peer->check_peer_addr = peer->peer_addr;
    }

    peers->checksum +=
        ngx_murmur_hash2(peer->peer_addr->name.data, peer->peer_addr->name.len);

    return peer->index;
}

static ngx_http_upstream_check_peer_t* 
ngx_http_upstream_check_get_peer_by_peer(void *peer)
{
    	ngx_http_upstream_check_peer_t *p;
    	ngx_uint_t i = 0;
    	//
    	if (check_peers_ctx == NULL) {
    		return NULL;
    	}
    	
    	p = check_peers_ctx->peers.elts;
    	
    	for (; i < check_peers_ctx->peers.nelts ; i++){
    		if(p[i].peer_mem_addr == peer){
    			p = &p[i];
    			break;
    		}
    	}

    	return p;
}



static ngx_int_t
ngx_http_upstream_check_addr_change_port(ngx_pool_t *pool, ngx_addr_t *dst,
    ngx_addr_t *src, ngx_uint_t port)
{
    size_t                len;
    u_char               *p;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    dst->socklen = src->socklen;
    dst->sockaddr = ngx_palloc(pool, dst->socklen);
    if (dst->sockaddr == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(dst->sockaddr, src->sockaddr, dst->socklen);

    switch (dst->sockaddr->sa_family) {

    case AF_INET:

        len = NGX_INET_ADDRSTRLEN + sizeof(":65535") - 1;
        sin = (struct sockaddr_in *) dst->sockaddr;
        sin->sin_port = htons(port);

        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:

        len = NGX_INET6_ADDRSTRLEN + sizeof(":65535") - 1;
        sin6 = (struct sockaddr_in6 *) dst->sockaddr;
        sin6->sin6_port = htons(port);

        break;
#endif

    default:
        return NGX_ERROR;
    }

    p = ngx_pnalloc(pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

#if (nginx_version >= 1005012)
    len = ngx_sock_ntop(dst->sockaddr, dst->socklen, p, len, 1);
#else
    len = ngx_sock_ntop(dst->sockaddr, p, len, 1);
#endif

    dst->name.len = len;
    dst->name.data = p;

    return NGX_OK;
}

void ngx_http_upstream_check_set_peer_weight(void *fstp ,void *p, ngx_uint_t w)
{
    ngx_http_upstream_check_peer_t  *peer;
    ngx_http_upstream_check_peer_t  *fstpeer;
    ngx_http_upstream_rr_peer_t     *memp;

    memp = (ngx_http_upstream_rr_peer_t*)p;

    peer = ngx_http_upstream_check_get_peer_by_peer(p);
    fstpeer = ngx_http_upstream_check_get_peer_by_peer(fstp);

    if ( peer == NULL ) {
        return;
    }

    fstpeer->shm->v_total_weight = fstpeer->shm->v_total_weight - peer->shm->v_weight + w - memp->weight;
    peer->shm->v_weight = w - memp->weight;

	peer->shm->weight=w;
}

ngx_uint_t
ngx_http_upstream_get_peer_weight(void *p)
{
    ngx_http_upstream_check_peer_t  *peer;

    peer = ngx_http_upstream_check_get_peer_by_peer(p);

    if ( peer == NULL ) {
        return 0 ;
    }

    if(!peer->shm->weight)
    {
    	peer->shm->weight = peer->weight;
    }

    return (peer->shm->weight);
}

ngx_int_t
ngx_http_upstream_get_v_total_weight(void *fstp)
{
    ngx_http_upstream_check_peer_t  *peer;

    peer = ngx_http_upstream_check_get_peer_by_peer(fstp);

    if ( peer == NULL ) {
        return 0 ;
    }

    return (peer->shm->v_total_weight);
}

void ngx_http_upstream_check_force_down_peer(void *p, ngx_uint_t dw)
{
    ngx_http_upstream_check_peer_t  *peer;

    peer = ngx_http_upstream_check_get_peer_by_peer(p);

    if ( peer == NULL ) {
        return;
    }

    peer->shm->force_down=dw;
}


ngx_uint_t
ngx_http_upstream_check_peer_force_down(void *p)
{
    ngx_http_upstream_check_peer_t  *peer;

    peer = ngx_http_upstream_check_get_peer_by_peer(p);

    if ( peer == NULL ) {
        return 0 ;
    }

    return (peer->shm->force_down);
}


ngx_uint_t
ngx_http_upstream_check_peer_down(void *p)
{
    ngx_http_upstream_check_peer_t  *peer;

		peer = ngx_http_upstream_check_get_peer_by_peer(p);

    if ( peer == NULL ) {
        return 0 ;
    }

    return (peer->shm->down);
}


/* TODO: this interface can count each peer's busyness */
void
ngx_http_upstream_check_get_peer(void *p)
{
    ngx_http_upstream_check_peer_t  *peer;
    
    peer = ngx_http_upstream_check_get_peer_by_peer(p);

    if ( peer == NULL ) {
        return ;
    }

    ngx_shmtx_lock(&peer->shm->mutex);

    peer->shm->busyness++;
    peer->shm->access_count++;

    ngx_shmtx_unlock(&peer->shm->mutex);
}


void
ngx_http_upstream_check_free_peer(void *p)
{
    ngx_http_upstream_check_peer_t  *peer;

    peer = ngx_http_upstream_check_get_peer_by_peer(p);

    if ( peer == NULL ) {
        return ;
    }

    ngx_shmtx_lock(&peer->shm->mutex);

    if (peer->shm->busyness > 0) {
        peer->shm->busyness--;
    }

    ngx_shmtx_unlock(&peer->shm->mutex);
}


static ngx_int_t
ngx_http_upstream_check_add_timers(ngx_cycle_t *cycle)
{
    ngx_uint_t                           i;
    ngx_msec_t                           t, delay;
    ngx_check_conf_t                    *cf;
    ngx_http_upstream_check_peer_t      *peer;
    ngx_http_upstream_check_peers_t     *peers;
    ngx_http_upstream_check_srv_conf_t  *ucscf;
    ngx_http_upstream_check_peer_shm_t  *peer_shm;
    ngx_http_upstream_check_peers_shm_t *peers_shm;

    peers = check_peers_ctx;
    if (peers == NULL) {
        return NGX_OK;
    }

    peers_shm = peers->peers_shm;
    if (peers_shm == NULL) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                   "http check upstream init_process, shm_name: %V, "
                   "peer number: %ud",
                   &peers->check_shm_name,
                   peers->peers.nelts);

    srandom(ngx_pid);

    peer = peers->peers.elts;
    peer_shm = peers_shm->peers;

    for (i = 0; i < peers->peers.nelts; i++) {

        peer[i].shm = &peer_shm[i];

        ucscf = peer[i].conf;
        // if check directive is not configed or interval is 0 , donot start timer
        if(!ucscf->check_cmd_on || ucscf->check_interval == 0){
            continue;
        }

        peer[i].check_ev.handler = ngx_http_upstream_check_begin_handler;
        peer[i].check_ev.log = cycle->log;
        peer[i].check_ev.data = &peer[i];
        peer[i].check_ev.timer_set = 0;

        peer[i].check_timeout_ev.handler =
            ngx_http_upstream_check_timeout_handler;
        peer[i].check_timeout_ev.log = cycle->log;
        peer[i].check_timeout_ev.data = &peer[i];
        peer[i].check_timeout_ev.timer_set = 0;

        cf = ucscf->check_type_conf;

        if (cf->need_pool) {
            peer[i].pool = ngx_create_pool(ngx_pagesize, cycle->log);
            if (peer[i].pool == NULL) {
                return NGX_ERROR;
            }
        }

        peer[i].send_handler = cf->send_handler;
        peer[i].recv_handler = cf->recv_handler;

        peer[i].init = cf->init;
        peer[i].parse = cf->parse;
        peer[i].reinit = cf->reinit;

        /*
         * We add a random start time here, since we don't want to trigger
         * the check events too close to each other at the beginning.
         */
        delay = ucscf->check_interval > 1000 ? ucscf->check_interval : 1000;
        t = ngx_random() % delay;

        ngx_add_timer(&peer[i].check_ev, t);
    }

    return NGX_OK;
}


static void
ngx_http_upstream_check_begin_handler(ngx_event_t *event)
{
    ngx_msec_t                           interval;
    ngx_http_upstream_check_peer_t      *peer;
    ngx_http_upstream_check_peers_t     *peers;
    ngx_http_upstream_check_srv_conf_t  *ucscf;
    ngx_http_upstream_check_peers_shm_t *peers_shm;

    if (ngx_http_upstream_check_need_exit()) {
        return;
    }

    peers = check_peers_ctx;
    if (peers == NULL) {
        return;
    }

    peers_shm = peers->peers_shm;
    if (peers_shm == NULL) {
        return;
    }

    peer = event->data;
    ucscf = peer->conf;

    ngx_add_timer(event, ucscf->check_interval / 2);

    /* This process is processing this peer now. */
    if ((peer->shm->owner == ngx_pid  ||
        (peer->pc.connection != NULL) ||
        peer->check_timeout_ev.timer_set)) {
        return;
    }

    //when force down the peer , don't check
    if( peer->shm->force_down ){
    	return;
    }

    interval = ngx_current_msec - peer->shm->access_time;
    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, event->log, 0,
                   "http check begin handler index: %ui, owner: %P, "
                   "ngx_pid: %P, interval: %M, check_interval: %M",
                   peer->index, peer->shm->owner,
                   ngx_pid, interval,
                   ucscf->check_interval);

    ngx_shmtx_lock(&peer->shm->mutex);

    if (peers_shm->generation != ngx_http_upstream_check_shm_generation) {
        ngx_shmtx_unlock(&peer->shm->mutex);
        return;
    }

    if ((interval >= ucscf->check_interval)
         && (peer->shm->owner == NGX_INVALID_PID))
    {
        peer->shm->owner = ngx_pid;

    } else if (interval >= (ucscf->check_interval << 4)) {

        /*
         * If the check peer has been untouched for 2^4 times of
         * the check interval, activate the current timer.
         * Sometimes, the checking process may disappear
         * in some circumstances, and the clean event will never
         * be triggered.
         */
        peer->shm->owner = ngx_pid;
        peer->shm->access_time = ngx_current_msec;
    }

    ngx_shmtx_unlock(&peer->shm->mutex);

    if (peer->shm->owner == ngx_pid) {
        ngx_http_upstream_check_connect_handler(event);
    }
}


static void
ngx_http_upstream_check_connect_handler(ngx_event_t *event)
{
    ngx_int_t                            rc;
    ngx_connection_t                    *c;
    ngx_http_upstream_check_peer_t      *peer;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    if (ngx_http_upstream_check_need_exit()) {
        return;
    }

    peer = event->data;
    ucscf = peer->conf;

    if (peer->pc.connection != NULL) {
        c = peer->pc.connection;
        if ((rc = ngx_http_upstream_check_peek_one_byte(c)) == NGX_OK) {
            goto upstream_check_connect_done;
        } else {
            ngx_close_connection(c);
            peer->pc.connection = NULL;
        }
    }
    ngx_memzero(&peer->pc, sizeof(ngx_peer_connection_t));

    peer->pc.sockaddr = peer->check_peer_addr->sockaddr;
    peer->pc.socklen = peer->check_peer_addr->socklen;
    peer->pc.name = &peer->check_peer_addr->name;

    peer->pc.get = ngx_event_get_peer;
    peer->pc.log = event->log;
    peer->pc.log_error = NGX_ERROR_ERR;

    peer->pc.cached = 0;
    peer->pc.connection = NULL;

    rc = ngx_event_connect_peer(&peer->pc);

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_http_upstream_check_status_update(peer, 0);
        ngx_http_upstream_check_clean_event(peer);
        return;
    }

    /* NGX_OK or NGX_AGAIN */
    c = peer->pc.connection;
    c->data = peer;
    c->log = peer->pc.log;
    c->sendfile = 0;
    c->read->log = c->log;
    c->write->log = c->log;
    c->pool = peer->pool;

upstream_check_connect_done:
    peer->state = NGX_HTTP_CHECK_CONNECT_DONE;

    c->write->handler = peer->send_handler;
    c->read->handler = peer->recv_handler;

    ngx_add_timer(&peer->check_timeout_ev, ucscf->check_timeout);

    /* The kqueue's loop interface needs it. */
    if (rc == NGX_OK) {
        c->write->handler(c->write);
    }
}

static ngx_int_t
ngx_http_upstream_check_peek_one_byte(ngx_connection_t *c)
{
    char                            buf[1];
    ngx_int_t                       n;
    ngx_err_t                       err;

    n = recv(c->fd, buf, 1, MSG_PEEK);
    err = ngx_socket_errno;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                   "http check upstream recv(): %i, fd: %d",
                   n, c->fd);

    if (n == 1 || (n == -1 && err == NGX_EAGAIN)) {
        return NGX_OK;
    } else {
        return NGX_ERROR;
    }
}

static void
ngx_http_upstream_check_peek_handler(ngx_event_t *event)
{
    ngx_connection_t               *c;
    ngx_http_upstream_check_peer_t *peer;

    if (ngx_http_upstream_check_need_exit()) {
        return;
    }

    c = event->data;
    peer = c->data;

    if (ngx_http_upstream_check_peek_one_byte(c) == NGX_OK) {
        ngx_http_upstream_check_status_update(peer, 1);

    } else {
        c->error = 1;
        ngx_http_upstream_check_status_update(peer, 0);
    }

    ngx_http_upstream_check_clean_event(peer);

    ngx_http_upstream_check_finish_handler(event);
}


static void
ngx_http_upstream_check_discard_handler(ngx_event_t *event)
{
    u_char                          buf[4096];
    ssize_t                         size;
    ngx_connection_t               *c;
    ngx_http_upstream_check_peer_t *peer;

    c = event->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "upstream check discard handler");

    if (ngx_http_upstream_check_need_exit()) {
        return;
    }

    peer = c->data;

    while (1) {
        size = c->recv(c, buf, 4096);

        if (size > 0) {
            continue;

        } else if (size == NGX_AGAIN) {
            break;

        } else {
            if (size == 0) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                               "peer closed its half side of the connection");
            }

            goto check_discard_fail;
        }
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto check_discard_fail;
    }

    return;

 check_discard_fail:
    c->error = 1;
    ngx_http_upstream_check_clean_event(peer);
}


static void
ngx_http_upstream_check_dummy_handler(ngx_event_t *event)
{
    return;
}


static void
ngx_http_upstream_check_send_handler(ngx_event_t *event)
{
    ssize_t                         size;
    ngx_connection_t               *c;
    ngx_http_upstream_check_ctx_t  *ctx;
    ngx_http_upstream_check_peer_t *peer;

    if (ngx_http_upstream_check_need_exit()) {
        return;
    }

    c = event->data;
    peer = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http check send.");

    if (c->pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, event->log, 0,
                      "check pool NULL with peer: %V ",
                      &peer->check_peer_addr->name);

        goto check_send_fail;
    }

    if (peer->state != NGX_HTTP_CHECK_CONNECT_DONE) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {

            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "check handle write event error with peer: %V ",
                          &peer->check_peer_addr->name);

            goto check_send_fail;
        }

        return;
    }

    if (peer->check_data == NULL) {

        peer->check_data = ngx_pcalloc(peer->pool,
                                       sizeof(ngx_http_upstream_check_ctx_t));
        if (peer->check_data == NULL) {
            goto check_send_fail;
        }

        if (peer->init == NULL || peer->init(peer) != NGX_OK) {

            ngx_log_error(NGX_LOG_ERR, event->log, 0,
                          "check init error with peer: %V ",
                          &peer->check_peer_addr->name);

            goto check_send_fail;
        }
    }

    ctx = peer->check_data;

    while (ctx->send.pos < ctx->send.last) {

        size = c->send(c, ctx->send.pos, ctx->send.last - ctx->send.pos);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (size >=0) ? 0 : ngx_socket_errno;
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, err,
                       "http check send size: %z, total: %z",
                       size, ctx->send.last - ctx->send.pos);
        }
#endif

        if (size > 0) {
            ctx->send.pos += size;
        } else if (size == 0 || size == NGX_AGAIN) {
            return;
        } else {
            c->error = 1;
            goto check_send_fail;
        }
    }

    if (ctx->send.pos == ctx->send.last) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http check send done.");
        peer->state = NGX_HTTP_CHECK_SEND_DONE;
        c->requests++;
    }

    return;

check_send_fail:
    ngx_http_upstream_check_status_update(peer, 0);
    ngx_http_upstream_check_clean_event(peer);
}


static void
ngx_http_upstream_check_recv_handler(ngx_event_t *event)
{
    u_char                         *new_buf;
    ssize_t                         size, n;
    ngx_int_t                       rc;
    ngx_connection_t               *c;
    ngx_http_upstream_check_ctx_t  *ctx;
    ngx_http_upstream_check_peer_t *peer;

    if (ngx_http_upstream_check_need_exit()) {
        return;
    }

    c = event->data;
    peer = c->data;

    if (peer->state != NGX_HTTP_CHECK_SEND_DONE) {

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto check_recv_fail;
        }

        return;
    }

    ctx = peer->check_data;

    if (ctx->recv.start == NULL) {
        /* 1/2 of the page_size, is it enough? */
        ctx->recv.start = ngx_palloc(c->pool, ngx_pagesize / 2);
        if (ctx->recv.start == NULL) {
            goto check_recv_fail;
        }

        ctx->recv.last = ctx->recv.pos = ctx->recv.start;
        ctx->recv.end = ctx->recv.start + ngx_pagesize / 2;
    }

    while (1) {
        n = ctx->recv.end - ctx->recv.last;

        /* buffer not big enough? enlarge it by twice */
        if (n == 0) {
            size = ctx->recv.end - ctx->recv.start;
            new_buf = ngx_palloc(c->pool, size * 2);
            if (new_buf == NULL) {
                goto check_recv_fail;
            }

            ngx_memcpy(new_buf, ctx->recv.start, size);

            ctx->recv.pos = ctx->recv.start = new_buf;
            ctx->recv.last = new_buf + size;
            ctx->recv.end = new_buf + size * 2;

            n = ctx->recv.end - ctx->recv.last;
        }

        size = c->recv(c, ctx->recv.last, n);

#if (NGX_DEBUG)
        {
        ngx_err_t  err;

        err = (size >= 0) ? 0 : ngx_socket_errno;
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                       "http check recv size: %z, peer: %V ",
                       size, &peer->check_peer_addr->name);
        }
#endif

        if (size > 0) {
            ctx->recv.last += size;
            continue;
        } else if (size == 0 || size == NGX_AGAIN) {
            break;
        } else {
            c->error = 1;
            goto check_recv_fail;
        }
    }

    rc = peer->parse(peer);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http check parse rc: %i, peer: %V ",
                   rc, &peer->check_peer_addr->name);

    switch (rc) {

    case NGX_AGAIN:
        /* The peer has closed its half side of the connection. */
        if (size == 0) {
            ngx_http_upstream_check_status_update(peer, 0);
            c->error = 1;
            break;
        }

        return;

    case NGX_ERROR:
        ngx_log_error(NGX_LOG_ERR, event->log, 0,
                      "check protocol %V error with peer: %V ",
                      &peer->conf->check_type_conf->name,
                      &peer->check_peer_addr->name);

        ngx_http_upstream_check_status_update(peer, 0);
        break;

    case NGX_OK:
        /* fall through */

    default:
        ngx_http_upstream_check_status_update(peer, 1);
        break;
    }

    peer->state = NGX_HTTP_CHECK_RECV_DONE;
    ngx_http_upstream_check_clean_event(peer);
    return;

check_recv_fail:
    ngx_http_upstream_check_status_update(peer, 0);
    ngx_http_upstream_check_clean_event(peer);
}


static ngx_int_t
ngx_http_upstream_check_http_init(ngx_http_upstream_check_peer_t *peer)
{
    ngx_http_upstream_check_ctx_t       *ctx;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    ctx = peer->check_data;
    ucscf = peer->conf;

    ctx->send.start = ctx->send.pos = (u_char *)ucscf->send.data;
    ctx->send.end = ctx->send.last = ctx->send.start + ucscf->send.len;

    ctx->recv.start = ctx->recv.pos = NULL;
    ctx->recv.end = ctx->recv.last = NULL;

    ctx->state = 0;

    ngx_memzero(&ctx->status, sizeof(ngx_http_status_t));

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_http_parse(ngx_http_upstream_check_peer_t *peer)
{
    ngx_int_t                            rc;
    ngx_uint_t                           code, code_n;
    ngx_http_upstream_check_ctx_t       *ctx;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    ucscf = peer->conf;
    ctx = peer->check_data;

    if ((ctx->recv.last - ctx->recv.pos) > 0) {

        rc = ngx_http_upstream_check_parse_status_line(ctx,
                                                       &ctx->recv,
                                                       &ctx->status);
        if (rc == NGX_AGAIN) {
            return rc;
        }

        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "http parse status line error with peer: %V ",
                          &peer->check_peer_addr->name);
            return rc;
        }

        code = ctx->status.code;

        if (code >= 200 && code < 300) {
            code_n = NGX_CHECK_HTTP_2XX;
        } else if (code >= 300 && code < 400) {
            code_n = NGX_CHECK_HTTP_3XX;
        } else if (code >= 400 && code < 500) {
            peer->pc.connection->error = 1;
            code_n = NGX_CHECK_HTTP_4XX;
        } else if (code >= 500 && code < 600) {
            peer->pc.connection->error = 1;
            code_n = NGX_CHECK_HTTP_5XX;
        } else {
            peer->pc.connection->error = 1;
            code_n = NGX_CHECK_HTTP_ERR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "http_parse: code_n: %ui, conf: %ui",
                       code_n, ucscf->code.status_alive);

        if (code_n & ucscf->code.status_alive) {
            return NGX_OK;
        } else {
            return NGX_ERROR;
        }
    } else {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_fastcgi_process_record(
    ngx_http_upstream_check_ctx_t *ctx, ngx_buf_t *b, ngx_http_status_t *status)
{
    u_char                     ch, *p;
    ngx_http_fastcgi_state_e   state;

    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {

        ch = *p;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "http fastcgi record byte: %02Xd", ch);

        switch (state) {

        case ngx_http_fastcgi_st_version:
            if (ch != 1) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "upstream sent unsupported FastCGI "
                              "protocol version: %d", ch);
                return NGX_ERROR;
            }
            state = ngx_http_fastcgi_st_type;
            break;

        case ngx_http_fastcgi_st_type:
            switch (ch) {
            case NGX_HTTP_FASTCGI_STDOUT:
            case NGX_HTTP_FASTCGI_STDERR:
            case NGX_HTTP_FASTCGI_END_REQUEST:
                status->code = (ngx_uint_t) ch;
                break;
            default:
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "upstream sent invalid FastCGI "
                              "record type: %d", ch);
                return NGX_ERROR;

            }
            state = ngx_http_fastcgi_st_request_id_hi;
            break;

        /* we support the single request per connection */

        case ngx_http_fastcgi_st_request_id_hi:
            if (ch != 0) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "upstream sent unexpected FastCGI "
                              "request id high byte: %d", ch);
                return NGX_ERROR;
            }
            state = ngx_http_fastcgi_st_request_id_lo;
            break;

        case ngx_http_fastcgi_st_request_id_lo:
            if (ch != 1) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                              "upstream sent unexpected FastCGI "
                              "request id low byte: %d", ch);
                return NGX_ERROR;
            }
            state = ngx_http_fastcgi_st_content_length_hi;
            break;

        case ngx_http_fastcgi_st_content_length_hi:
            ctx->length = ch << 8;
            state = ngx_http_fastcgi_st_content_length_lo;
            break;

        case ngx_http_fastcgi_st_content_length_lo:
            ctx->length |= (size_t) ch;
            state = ngx_http_fastcgi_st_padding_length;
            break;

        case ngx_http_fastcgi_st_padding_length:
            ctx->padding = (size_t) ch;
            state = ngx_http_fastcgi_st_reserved;
            break;

        case ngx_http_fastcgi_st_reserved:
            state = ngx_http_fastcgi_st_data;

            b->pos = p + 1;
            ctx->state = state;

            return NGX_OK;

        /* suppress warning */
        case ngx_http_fastcgi_st_data:
        case ngx_http_fastcgi_st_padding:
            break;
        }
    }

    ctx->state = state;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_upstream_check_fastcgi_parse(ngx_http_upstream_check_peer_t *peer)
{
    ngx_int_t                            rc;
    ngx_flag_t                           done;
    ngx_uint_t                           type, code, code_n;
    ngx_http_upstream_check_ctx_t       *ctx;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    ucscf = peer->conf;
    ctx = peer->check_data;

    if ((ctx->recv.last - ctx->recv.pos) <= 0) {
        return NGX_AGAIN;
    }

    done = 0;

    for ( ;; ) {

        if (ctx->state < ngx_http_fastcgi_st_data) {
            rc = ngx_http_upstream_check_fastcgi_process_record(ctx,
                    &ctx->recv, &ctx->status);

            type = ctx->status.code;

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                           "fastcgi_parse rc: [%i], type: [%ui]", rc, type);

            if (rc == NGX_AGAIN) {
                return rc;
            }

            if (rc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                   "check fastcgi parse status line error with peer: %V",
                   &peer->check_peer_addr->name);

                return rc;
            }

            if (type != NGX_HTTP_FASTCGI_STDOUT
                && type != NGX_HTTP_FASTCGI_STDERR)
            {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                   "check fastcgi sent unexpected FastCGI record: %d", type);

                return NGX_ERROR;
            }

            if (type == NGX_HTTP_FASTCGI_STDOUT && ctx->length == 0) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                   "check fastcgi prematurely closed FastCGI stdout");

                return NGX_ERROR;
            }
        }

        if (ctx->state == ngx_http_fastcgi_st_padding) {

            if (ctx->recv.pos + ctx->padding < ctx->recv.last) {
                ctx->status.code = ngx_http_fastcgi_st_version;
                ctx->recv.pos += ctx->padding;

                continue;
            }

            if (ctx->recv.pos + ctx->padding == ctx->recv.last) {
                ctx->status.code = ngx_http_fastcgi_st_version;
                ctx->recv.pos = ctx->recv.last;

                return NGX_AGAIN;
            }

            ctx->padding -= ctx->recv.last - ctx->recv.pos;
            ctx->recv.pos = ctx->recv.last;

            return NGX_AGAIN;
        }

        if (ctx->status.code == NGX_HTTP_FASTCGI_STDERR) {

            ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                          "fastcgi check error");

            return NGX_ERROR;
        }

        /* ctx->status.code == NGX_HTTP_FASTCGI_STDOUT */

        if (ctx->recv.pos + ctx->length < ctx->recv.last) {
            ctx->recv.last = ctx->recv.pos + ctx->length;
        } else {
            return NGX_ERROR;
        }

        ctx->status.code = 0;

        for ( ;; ) {
            rc = ngx_http_upstream_check_parse_fastcgi_status(ctx,
                                                              &ctx->recv,
                                                              &ctx->status);
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                          "fastcgi http parse status line rc: %i ", rc);

            if (rc == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                   "fastcgi http parse status line error with peer: %V ",
                    &peer->check_peer_addr->name);
                return NGX_ERROR;
            }

            if (rc == NGX_AGAIN) {
                break;
            }

            if (rc == NGX_DONE) {
                done = 1;
                ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0,
                              "fastcgi http parse status: %i",
                              ctx->status.code);
                break;
            }

            /* rc = NGX_OK */
        }

        if (ucscf->code.status_alive == 0 || done == 0) {
            return NGX_OK;
        }

        code = ctx->status.code;

        if (code >= 200 && code < 300) {
            code_n = NGX_CHECK_HTTP_2XX;
        } else if (code >= 300 && code < 400) {
            code_n = NGX_CHECK_HTTP_3XX;
        } else if (code >= 400 && code < 500) {
            code_n = NGX_CHECK_HTTP_4XX;
        } else if (code >= 500 && code < 600) {
            code_n = NGX_CHECK_HTTP_5XX;
        } else {
            code_n = NGX_CHECK_HTTP_ERR;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "fastcgi http_parse: code_n: %ui, conf: %ui",
                       code_n, ucscf->code.status_alive);

        if (code_n & ucscf->code.status_alive) {
            return NGX_OK;
        } else {
            return NGX_ERROR;
        }

    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_parse_fastcgi_status(ngx_http_upstream_check_ctx_t *ctx,
    ngx_buf_t *b, ngx_http_status_t *status)
{
    u_char      c, ch, *p, *name_s, *name_e;
    ngx_flag_t  find;

    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_ignore_line,
        sw_almost_done,
        sw_header_almost_done
    } state;

    /* the last '\0' is not needed because string is zero terminated */

    static u_char  lowcase[] =
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    status->count = 0;
    status->code = 0;
    find = 0;
    name_s = name_e = NULL;
    state = sw_start;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:

            switch (ch) {
            case CR:
                state = sw_header_almost_done;
                break;
            case LF:
                goto header_done;
            default:
                state = sw_name;

                c = lowcase[ch];

                if (c) {
                    name_s = p;
                    break;
                }

                if (ch == '\0') {
                    return NGX_ERROR;
                }


                break;
            }

            break;

        /* header name */
        case sw_name:
            c = lowcase[ch];

            if (c) {
                break;
            }

            if (ch == ':') {
                name_e = p;
#if (NGX_DEBUG)
                ngx_str_t name;
                name.data = name_s;
                name.len = name_e - name_s;
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                               "fastcgi header: %V", &name);
#endif
                state = sw_space_before_value;

                if (ngx_strncasecmp(name_s, (u_char *) "status",
                                    name_e - name_s)
                    == 0)
                {

                    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                                   "find status header");

                    find = 1;
                }

                break;
            }

            if (ch == CR) {
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                goto done;
            }

            /* IIS may send the duplicate "HTTP/1.1 ..." lines */
            if (ch == '\0') {
                return NGX_ERROR;
            }

            break;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case '\0':
                return NGX_ERROR;
            default:
                state = sw_value;
                if (find) {
                    if (ch < '1' || ch > '9') {
                        return NGX_ERROR;
                    }

                    status->code = status->code * 10 + ch - '0';
                    if (status->count++ != 0) {
                        return NGX_ERROR;
                    }
                }

                break;
            }

            break;

        /* header value */
        case sw_value:

            if (find) {
                if (ch < '0' || ch > '9') {
                    return NGX_ERROR;
                }

                status->code = status->code * 10 + ch - '0';

                if (++status->count == 3) {
                    return NGX_DONE;
                }
            }

            switch (ch) {
            case ' ':
                state = sw_space_after_value;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case '\0':
                return NGX_ERROR;
            }

            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                state = sw_start;
                break;
            case '\0':
                return NGX_ERROR;
            default:
                state = sw_value;
                break;
            }
            break;

        /* ignore header line */
        case sw_ignore_line:
            switch (ch) {
            case LF:
                state = sw_start;
                break;
            default:
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            case CR:
                break;
            default:
                return NGX_ERROR;
            }
            break;

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_ERROR;
            }
        }
    }

    b->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;
    ctx->state = sw_start;

    return NGX_OK;

header_done:

    b->pos = p + 1;
    ctx->state = sw_start;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_parse_status_line(ngx_http_upstream_check_ctx_t *ctx,
    ngx_buf_t *b, ngx_http_status_t *status)
{
    u_char ch, *p;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    state = ctx->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            if (ch != 'H') {
                return NGX_ERROR;
            }

            state = sw_H;
            break;

        case sw_H:
            if (ch != 'T') {
                return NGX_ERROR;
            }

            state = sw_HT;
            break;

        case sw_HT:
            if (ch != 'T') {
                return NGX_ERROR;
            }

            state = sw_HTT;
            break;

        case sw_HTT:
            if (ch != 'P') {
                return NGX_ERROR;
            }

            state = sw_HTTP;
            break;

        case sw_HTTP:
            if (ch != '/') {
                return NGX_ERROR;
            }

            state = sw_first_major_digit;
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            status->code = status->code * 10 + ch - '0';

            if (++status->count == 3) {
                state = sw_space_after_status;
                status->start = p - 2;
            }

            break;

        /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            status->end = p - 1;
            if (ch == LF) {
                goto done;
            } else {
                return NGX_ERROR;
            }
        }
    }

    b->pos = p;
    ctx->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;

    if (status->end == NULL) {
        status->end = p;
    }

    ctx->state = sw_start;

    return NGX_OK;
}


static void
ngx_http_upstream_check_http_reinit(ngx_http_upstream_check_peer_t *peer)
{
    ngx_http_upstream_check_ctx_t  *ctx;

    ctx = peer->check_data;

    ctx->send.pos = ctx->send.start;
    ctx->send.last = ctx->send.end;

    ctx->recv.pos = ctx->recv.last = ctx->recv.start;

    ctx->state = 0;

    ngx_memzero(&ctx->status, sizeof(ngx_http_status_t));
}


static ngx_int_t
ngx_http_upstream_check_ssl_hello_init(ngx_http_upstream_check_peer_t *peer)
{
    ngx_http_upstream_check_ctx_t       *ctx;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    ctx = peer->check_data;
    ucscf = peer->conf;

    ctx->send.start = ctx->send.pos = (u_char *)ucscf->send.data;
    ctx->send.end = ctx->send.last = ctx->send.start + ucscf->send.len;

    ctx->recv.start = ctx->recv.pos = NULL;
    ctx->recv.end = ctx->recv.last = NULL;

    return NGX_OK;
}


/* a rough check of server ssl_hello responses */
static ngx_int_t
ngx_http_upstream_check_ssl_hello_parse(ngx_http_upstream_check_peer_t *peer)
{
    size_t                         size;
    ngx_ssl_server_hello_t        *resp;
    ngx_http_upstream_check_ctx_t *ctx;

    ctx = peer->check_data;

    size = ctx->recv.last - ctx->recv.pos;
    if (size < sizeof(ngx_ssl_server_hello_t)) {
        return NGX_AGAIN;
    }

    resp = (ngx_ssl_server_hello_t *) ctx->recv.pos;

    ngx_log_debug7(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "http check ssl_parse, type: %ud, version: %ud.%ud, "
                   "length: %ud, handshanke_type: %ud, hello_version: %ud.%ud",
                   resp->msg_type, resp->version.major, resp->version.minor,
                   ntohs(resp->length), resp->handshake_type,
                   resp->hello_version.major, resp->hello_version.minor);

    if (resp->msg_type != NGX_SSL_HANDSHAKE) {
        return NGX_ERROR;
    }

    if (resp->handshake_type != NGX_SSL_SERVER_HELLO) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_upstream_check_ssl_hello_reinit(ngx_http_upstream_check_peer_t *peer)
{
    ngx_http_upstream_check_ctx_t *ctx;

    ctx = peer->check_data;

    ctx->send.pos = ctx->send.start;
    ctx->send.last = ctx->send.end;

    ctx->recv.pos = ctx->recv.last = ctx->recv.start;
}


static ngx_int_t
ngx_http_upstream_check_mysql_init(ngx_http_upstream_check_peer_t *peer)
{
    ngx_http_upstream_check_ctx_t       *ctx;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    ctx = peer->check_data;
    ucscf = peer->conf;

    ctx->send.start = ctx->send.pos = (u_char *)ucscf->send.data;
    ctx->send.end = ctx->send.last = ctx->send.start + ucscf->send.len;

    ctx->recv.start = ctx->recv.pos = NULL;
    ctx->recv.end = ctx->recv.last = NULL;

    return NGX_OK;
}


/* a rough check of mysql greeting responses */
static ngx_int_t
ngx_http_upstream_check_mysql_parse(ngx_http_upstream_check_peer_t *peer)
{
    size_t                         size;
    ngx_mysql_handshake_init_t    *handshake;
    ngx_http_upstream_check_ctx_t *ctx;

    ctx = peer->check_data;

    size = ctx->recv.last - ctx->recv.pos;
    if (size < sizeof(ngx_mysql_handshake_init_t)) {
        return NGX_AGAIN;
    }

    handshake = (ngx_mysql_handshake_init_t *) ctx->recv.pos;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "mysql_parse: packet_number=%ud, protocol=%ud, server=%s",
                   handshake->packet_number, handshake->protocol_version,
                   handshake->others);

    /* The mysql greeting packet's serial number always begins with 0. */
    if (handshake->packet_number != 0x00) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_upstream_check_mysql_reinit(ngx_http_upstream_check_peer_t *peer)
{
    ngx_http_upstream_check_ctx_t *ctx;

    ctx = peer->check_data;

    ctx->send.pos = ctx->send.start;
    ctx->send.last = ctx->send.end;

    ctx->recv.pos = ctx->recv.last = ctx->recv.start;
}


static ngx_int_t
ngx_http_upstream_check_ajp_init(ngx_http_upstream_check_peer_t *peer)
{
    ngx_http_upstream_check_ctx_t       *ctx;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    ctx = peer->check_data;
    ucscf = peer->conf;

    ctx->send.start = ctx->send.pos = (u_char *)ucscf->send.data;
    ctx->send.end = ctx->send.last = ctx->send.start + ucscf->send.len;

    ctx->recv.start = ctx->recv.pos = NULL;
    ctx->recv.end = ctx->recv.last = NULL;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_ajp_parse(ngx_http_upstream_check_peer_t *peer)
{
    size_t                         size;
    u_char                        *p;
    ngx_http_upstream_check_ctx_t *ctx;

    ctx = peer->check_data;

    size = ctx->recv.last - ctx->recv.pos;
    if (size < sizeof(ngx_ajp_cpong_packet)) {
        return NGX_AGAIN;
    }

    p = ctx->recv.pos;

#if (NGX_DEBUG)
    {
    ngx_ajp_raw_packet_t  *ajp;

    ajp = (ngx_ajp_raw_packet_t *) p;
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                   "ajp_parse: preamble=0x%uxd, length=0x%uxd, type=0x%uxd",
                   ntohs(ajp->preamble), ntohs(ajp->length), ajp->type);
    }
#endif

    if (ngx_memcmp(ngx_ajp_cpong_packet, p, sizeof(ngx_ajp_cpong_packet)) == 0)
    {
        return NGX_OK;
    } else {
        return NGX_ERROR;
    }
}


static void
ngx_http_upstream_check_ajp_reinit(ngx_http_upstream_check_peer_t *peer)
{
    ngx_http_upstream_check_ctx_t  *ctx;

    ctx = peer->check_data;

    ctx->send.pos = ctx->send.start;
    ctx->send.last = ctx->send.end;

    ctx->recv.pos = ctx->recv.last = ctx->recv.start;
}


static void
ngx_http_upstream_check_status_update(ngx_http_upstream_check_peer_t *peer,
    ngx_int_t result)
{
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    ucscf = peer->conf;

    if (result) {
        peer->shm->rise_count++;
        peer->shm->fall_count = 0;
        if (peer->shm->down && peer->shm->rise_count >= ucscf->rise_count) {
            peer->shm->down = 0;
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "enable check peer: %V ",
                          &peer->check_peer_addr->name);
        }
    } else {
        peer->shm->rise_count = 0;
        peer->shm->fall_count++;
        if (!peer->shm->down && peer->shm->fall_count >= ucscf->fall_count) {
            peer->shm->down = 1;
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
                          "disable check peer: %V ",
                          &peer->check_peer_addr->name);
        }
    }

    peer->shm->access_time = ngx_current_msec;
}


static void
ngx_http_upstream_check_clean_event(ngx_http_upstream_check_peer_t *peer)
{
    ngx_connection_t                    *c;
    ngx_http_upstream_check_srv_conf_t  *ucscf;
    ngx_check_conf_t                    *cf;

    c = peer->pc.connection;
    ucscf = peer->conf;
    cf = ucscf->check_type_conf;

    if (c) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http check clean event: index:%i, fd: %d",
                       peer->index, c->fd);
        if (c->error == 0 &&
            cf->need_keepalive &&
            (c->requests < ucscf->check_keepalive_requests))
        {
            c->write->handler = ngx_http_upstream_check_dummy_handler;
            c->read->handler = ngx_http_upstream_check_discard_handler;
        } else {
            ngx_close_connection(c);
            peer->pc.connection = NULL;
        }
    }

    if (peer->check_timeout_ev.timer_set) {
        ngx_del_timer(&peer->check_timeout_ev);
    }

    peer->state = NGX_HTTP_CHECK_ALL_DONE;

    if (peer->check_data != NULL && peer->reinit) {
        peer->reinit(peer);
    }

    peer->shm->owner = NGX_INVALID_PID;
}


static void
ngx_http_upstream_check_timeout_handler(ngx_event_t *event)
{
    ngx_http_upstream_check_peer_t  *peer;

    if (ngx_http_upstream_check_need_exit()) {
        return;
    }

    peer = event->data;
    peer->pc.connection->error = 1;

    ngx_log_error(NGX_LOG_ERR, event->log, 0,
                  "check time out with peer: %V ",
                  &peer->check_peer_addr->name);

    ngx_http_upstream_check_status_update(peer, 0);
    ngx_http_upstream_check_clean_event(peer);
}


static void
ngx_http_upstream_check_finish_handler(ngx_event_t *event)
{
    if (ngx_http_upstream_check_need_exit()) {
        return;
    }
}


static ngx_int_t
ngx_http_upstream_check_need_exit()
{
    if (ngx_terminate || ngx_exiting || ngx_quit) {
        ngx_http_upstream_check_clear_all_events();
        return 1;
    }

    return 0;
}


static void
ngx_http_upstream_check_clear_all_events()
{
    ngx_uint_t                       i;
    ngx_connection_t                *c;
    ngx_http_upstream_check_peer_t  *peer;
    ngx_http_upstream_check_peers_t *peers;

    static ngx_flag_t                has_cleared = 0;

    if (has_cleared || check_peers_ctx == NULL) {
        return;
    }

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                  "clear all the events on %P ", ngx_pid);

    has_cleared = 1;

    peers = check_peers_ctx;

    peer = peers->peers.elts;
    for (i = 0; i < peers->peers.nelts; i++) {

        if (peer[i].check_ev.timer_set) {
            ngx_del_timer(&peer[i].check_ev);
        }

        if (peer[i].check_timeout_ev.timer_set) {
            ngx_del_timer(&peer[i].check_timeout_ev);
        }

        c = peer[i].pc.connection;
        if (c) {
            ngx_close_connection(c);
            peer[i].pc.connection = NULL;
        }

        if (peer[i].pool != NULL) {
            ngx_destroy_pool(peer[i].pool);
            peer[i].pool = NULL;
        }
    }
}


static ngx_int_t
ngx_http_upstream_check_status_handler(ngx_http_request_t *r)
{
    size_t                                 buffer_size;
    ngx_int_t                              rc;
    ngx_buf_t                             *b;
    ngx_chain_t                            out;
    ngx_http_upstream_check_peers_t       *peers;
    ngx_http_upstream_check_loc_conf_t    *uclcf;
    ngx_http_upstream_check_status_ctx_t  *ctx;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    uclcf = ngx_http_get_module_loc_conf(r, ngx_http_upstream_check_module);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_check_status_ctx_t));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_upstream_check_status_parse_args(r, ctx);

    if (ctx->format == NULL) {
        ctx->format = uclcf->format;
    }

    r->headers_out.content_type = ctx->format->content_type;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    peers = check_peers_ctx;
    if (peers == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "http upstream check module can not find any check "
                      "server, make sure you've added the check servers");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* 1/4 pagesize for each record */
    buffer_size = peers->peers.nelts * ngx_pagesize / 4;
    buffer_size = ngx_align(buffer_size, ngx_pagesize) + ngx_pagesize;

    b = ngx_create_temp_buf(r->pool, buffer_size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    ctx->format->output(b, peers, ctx->flag);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    if (r->headers_out.content_length_n == 0) {
        r->header_only = 1;
    }

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static void
ngx_http_upstream_check_status_parse_args(ngx_http_request_t *r,
    ngx_http_upstream_check_status_ctx_t *ctx)
{
    ngx_str_t                    value;
    ngx_uint_t                   i;
    ngx_check_status_command_t  *command;

    if (r->args.len == 0) {
        return;
    }

    for (i = 0; /* void */ ; i++) {

        command = &ngx_check_status_commands[i];

        if (command->name.len == 0) {
            break;
        }

        if (ngx_http_arg(r, command->name.data, command->name.len, &value)
            == NGX_OK) {

           if (command->handler(ctx, &value) != NGX_OK) {
               ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                             "http upstream check, bad argument: \"%V\"",
                             &value);
           }
        }
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "http upstream check, flag: \"%ui\"", ctx->flag);
}


static ngx_int_t
ngx_http_upstream_check_status_command_format(
    ngx_http_upstream_check_status_ctx_t *ctx, ngx_str_t *value)
{
    ctx->format = ngx_http_get_check_status_format_conf(value);
    if (ctx->format == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_status_command_status(
    ngx_http_upstream_check_status_ctx_t *ctx, ngx_str_t *value)
{
    if (value->len == (sizeof("down") - 1)
        && ngx_strncasecmp(value->data, (u_char *) "down", value->len) == 0) {

        ctx->flag |= NGX_CHECK_STATUS_DOWN;

    } else if (value->len == (sizeof("up") - 1)
               && ngx_strncasecmp(value->data, (u_char *) "up", value->len)
               == 0) {

        ctx->flag |= NGX_CHECK_STATUS_UP;

    } else {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_upstream_check_status_html_format(ngx_buf_t *b,
    ngx_http_upstream_check_peers_t *peers, ngx_uint_t flag)
{
    ngx_uint_t                      i, count;
    ngx_http_upstream_check_peer_t *peer;

    peer = peers->peers.elts;

    count = 0;

    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        count++;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\n"
            "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
            "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
            "<head>\n"
            "  <title>Nginx http upstream check status</title>\n"
            "</head>\n"
            "<body>\n"
            "<h1>Nginx http upstream check status</h1>\n"
            "<h2>Check upstream server number: %ui, generation: %ui</h2>\n"
            "<table style=\"background-color:white\" cellspacing=\"0\" "
            "       cellpadding=\"3\" border=\"1\">\n"
            "  <tr bgcolor=\"#C0C0C0\">\n"
            "    <th>Index</th>\n"
            "    <th>Upstream</th>\n"
            "    <th>Name</th>\n"
            "    <th>Status</th>\n"
            "    <th>Rise counts</th>\n"
            "    <th>Fall counts</th>\n"
            "    <th>Check type</th>\n"
            "    <th>Check port</th>\n"
            "  </tr>\n",
            count, ngx_http_upstream_check_shm_generation);

    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        b->last = ngx_snprintf(b->last, b->end - b->last,
                "  <tr%s>\n"
                "    <td>%ui</td>\n"
                "    <td>%V</td>\n"
                "    <td>%V</td>\n"
                "    <td>%s</td>\n"
                "    <td>%ui</td>\n"
                "    <td>%ui</td>\n"
                "    <td>%V</td>\n"
                "    <td>%ui</td>\n"
                "  </tr>\n",
                peer[i].shm->down ? " bgcolor=\"#FF0000\"" : "",
                i,
                peer[i].upstream_name,
                &peer[i].peer_addr->name,
                peer[i].shm->down ? "down" : "up",
                peer[i].shm->rise_count,
                peer[i].shm->fall_count,
                &peer[i].conf->check_type_conf->name,
                peer[i].conf->port);
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "</table>\n"
            "</body>\n"
            "</html>\n");
}


static void
ngx_http_upstream_check_status_csv_format(ngx_buf_t *b,
    ngx_http_upstream_check_peers_t *peers, ngx_uint_t flag)
{
    ngx_uint_t                       i;
    ngx_http_upstream_check_peer_t  *peer;

    peer = peers->peers.elts;
    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        b->last = ngx_snprintf(b->last, b->end - b->last,
                "%ui,%V,%V,%s,%ui,%ui,%V,%ui\n",
                i,
                peer[i].upstream_name,
                &peer[i].peer_addr->name,
                peer[i].shm->down ? "down" : "up",
                peer[i].shm->rise_count,
                peer[i].shm->fall_count,
                &peer[i].conf->check_type_conf->name,
                peer[i].conf->port);
    }
}


static void
ngx_http_upstream_check_status_json_format(ngx_buf_t *b,
    ngx_http_upstream_check_peers_t *peers, ngx_uint_t flag)
{
    ngx_uint_t                       count, i, last;
    ngx_http_upstream_check_peer_t  *peer;

    peer = peers->peers.elts;

    count = 0;

    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        count++;
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "{\"servers\": {\n"
            "  \"total\": %ui,\n"
            "  \"generation\": %ui,\n"
            "  \"server\": [\n",
            count,
            ngx_http_upstream_check_shm_generation);

    last = peers->peers.nelts - 1;
    for (i = 0; i < peers->peers.nelts; i++) {

        if (flag & NGX_CHECK_STATUS_DOWN) {

            if (!peer[i].shm->down) {
                continue;
            }

        } else if (flag & NGX_CHECK_STATUS_UP) {

            if (peer[i].shm->down) {
                continue;
            }
        }

        b->last = ngx_snprintf(b->last, b->end - b->last,
                "    {\"index\": %ui, "
                "\"upstream\": \"%V\", "
                "\"name\": \"%V\", "
                "\"status\": \"%s\", "
                "\"rise\": %ui, "
                "\"fall\": %ui, "
                "\"type\": \"%V\", "
                "\"port\": %ui}"
                "%s\n",
                i,
                peer[i].upstream_name,
                &peer[i].peer_addr->name,
                peer[i].shm->down ? "down" : "up",
                peer[i].shm->rise_count,
                peer[i].shm->fall_count,
                &peer[i].conf->check_type_conf->name,
                peer[i].conf->port,
                (i == last) ? "" : ",");
    }

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "  ]\n");

    b->last = ngx_snprintf(b->last, b->end - b->last,
            "}}\n");
}


static ngx_check_conf_t *
ngx_http_get_check_type_conf(ngx_str_t *str)
{
    ngx_uint_t  i;

    for (i = 0; /* void */ ; i++) {

        if (ngx_check_types[i].type == 0) {
            break;
        }

        if (str->len != ngx_check_types[i].name.len) {
            continue;
        }

        if (ngx_strncmp(str->data, ngx_check_types[i].name.data,
                        str->len) == 0)
        {
            return &ngx_check_types[i];
        }
    }

    return NULL;
}


static char *
ngx_http_upstream_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                           *value, s;
    ngx_uint_t                           i, port, rise, fall, default_down;
    ngx_msec_t                           interval, timeout;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    /* default values */
    port = 0;
    rise = 2;
    fall = 5;
    interval = 30000;
    timeout = 1000;
    default_down = 1;

    value = cf->args->elts;

    ucscf = ngx_http_conf_get_module_srv_conf(cf,
                                              ngx_http_upstream_check_module);
    if (ucscf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            ucscf->check_type_conf = ngx_http_get_check_type_conf(&s);

            if (ucscf->check_type_conf == NULL) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "port=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            port = ngx_atoi(s.data, s.len);
            if (port == (ngx_uint_t) NGX_ERROR || port == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            interval = ngx_atoi(s.data, s.len);
            if (interval == (ngx_msec_t) NGX_ERROR || interval == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            timeout = ngx_atoi(s.data, s.len);
            if (timeout == (ngx_msec_t) NGX_ERROR || timeout == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "rise=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            rise = ngx_atoi(s.data, s.len);
            if (rise == (ngx_uint_t) NGX_ERROR || rise == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fall=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            fall = ngx_atoi(s.data, s.len);
            if (fall == (ngx_uint_t) NGX_ERROR || fall == 0) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "default_down=", 13) == 0) {
            s.len = value[i].len - 13;
            s.data = value[i].data + 13;

            if (ngx_strcasecmp(s.data, (u_char *) "true") == 0) {
                default_down = 1;
            } else if (ngx_strcasecmp(s.data, (u_char *) "false") == 0) {
                default_down = 0;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid value \"%s\", "
                                   "it must be \"true\" or \"false\"",
                                   value[i].data);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        goto invalid_check_parameter;
    }

    ucscf->port = port;
    ucscf->check_interval = interval;
    ucscf->check_timeout = timeout;
    ucscf->fall_count = fall;
    ucscf->rise_count = rise;
    ucscf->default_down = default_down;

    ucscf->check_cmd_on = 1;

    if (ucscf->check_type_conf == NGX_CONF_UNSET_PTR) {
        ngx_str_set(&s, "tcp");
        ucscf->check_type_conf = ngx_http_get_check_type_conf(&s);
    }

    return NGX_CONF_OK;

invalid_check_parameter:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_upstream_check_keepalive_requests(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                           *value;
    ngx_http_upstream_check_srv_conf_t  *ucscf;
    ngx_uint_t                           requests;

    value = cf->args->elts;

    ucscf = ngx_http_conf_get_module_srv_conf(cf,
                                              ngx_http_upstream_check_module);

    requests = ngx_atoi(value[1].data, value[1].len);
    if (requests == (ngx_uint_t) NGX_ERROR || requests == 0) {
        return "invalid value";
    }

    ucscf->check_keepalive_requests = requests;

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_http_send(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                           *value;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    value = cf->args->elts;

    ucscf = ngx_http_conf_get_module_srv_conf(cf,
                                              ngx_http_upstream_check_module);

    ucscf->send = value[1];

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_fastcgi_params(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                           *value, *k, *v;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    value = cf->args->elts;

    ucscf = ngx_http_conf_get_module_srv_conf(cf,
                                              ngx_http_upstream_check_module);

    k = ngx_array_push(ucscf->fastcgi_params);
    if (k == NULL) {
        return NGX_CONF_ERROR;
    }

    v = ngx_array_push(ucscf->fastcgi_params);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    *k = value[1];
    *v = value[2];

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_http_expect_alive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_str_t                           *value;
    ngx_uint_t                           bit, i, m;
    ngx_conf_bitmask_t                  *mask;
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    value = cf->args->elts;
    mask = ngx_check_http_expect_alive_masks;

    ucscf = ngx_http_conf_get_module_srv_conf(cf,
                                              ngx_http_upstream_check_module);
    bit = ucscf->code.status_alive;

    for (i = 1; i < cf->args->nelts; i++) {
        for (m = 0; mask[m].name.len != 0; m++) {

            if (mask[m].name.len != value[i].len
                || ngx_strcasecmp(mask[m].name.data, value[i].data) != 0)
            {
                continue;
            }

            if (bit & mask[m].mask) {
                ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                                   "duplicate value \"%s\"", value[i].data);

            } else {
                bit |= mask[m].mask;
            }

            break;
        }

        if (mask[m].name.len == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "invalid value \"%s\"", value[i].data);

            return NGX_CONF_ERROR;
        }
    }

    ucscf->code.status_alive = bit;

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_shm_size(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                            *value;
    ngx_http_upstream_check_main_conf_t  *ucmcf;

    ucmcf = ngx_http_conf_get_module_main_conf(cf,
                                               ngx_http_upstream_check_module);
    if (ucmcf->shm_size) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ucmcf->shm_size = ngx_parse_size(&value[1]);
    if (ucmcf->shm_size == (size_t) NGX_ERROR) {
        return "invalid value";
    }

    return NGX_CONF_OK;
}


static ngx_check_status_conf_t *
ngx_http_get_check_status_format_conf(ngx_str_t *str)
{
    ngx_uint_t  i;

    for (i = 0; /* void */ ; i++) {

        if (ngx_check_status_formats[i].format.len == 0) {
            break;
        }

        if (str->len != ngx_check_status_formats[i].format.len) {
            continue;
        }

        if (ngx_strncmp(str->data, ngx_check_status_formats[i].format.data,
                        str->len) == 0)
        {
            return &ngx_check_status_formats[i];
        }
    }

    return NULL;
}


static char *
ngx_http_upstream_check_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                           *value;
    ngx_http_core_loc_conf_t            *clcf;
    ngx_http_upstream_check_loc_conf_t  *uclcf;

    value = cf->args->elts;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_upstream_check_status_handler;

    if (cf->args->nelts == 2) {
        uclcf = ngx_http_conf_get_module_loc_conf(cf,
                                              ngx_http_upstream_check_module);

        uclcf->format = ngx_http_get_check_status_format_conf(&value[1]);
        if (uclcf->format == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid check format \"%V\"", &value[1]);

            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_upstream_check_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_check_main_conf_t  *ucmcf;
    
//    check_conf = cf;

    ucmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_check_main_conf_t));
    if (ucmcf == NULL) {
        return NULL;
    }

    ucmcf->peers = ngx_pcalloc(cf->pool,
                               sizeof(ngx_http_upstream_check_peers_t));
    if (ucmcf->peers == NULL) {
        return NULL;
    }

    ucmcf->peers->checksum = 0;

    if (ngx_array_init(&ucmcf->peers->peers, cf->pool, 16,
                       sizeof(ngx_http_upstream_check_peer_t)) != NGX_OK)
    {
        return NULL;
    }

    vars_hash.count=0;
    vars_hash_conf.count = 0;

    return ucmcf;
}


static ngx_buf_t *
ngx_http_upstream_check_create_fastcgi_request(ngx_pool_t *pool,
    ngx_str_t *params, ngx_uint_t num)
{
    size_t                      size, len, padding;
    ngx_buf_t                  *b;
    ngx_str_t                  *k, *v;
    ngx_uint_t                  i, j;
    ngx_http_fastcgi_header_t  *h;

    len = 0;
    for (i = 0, j = 0; i < num; i++, j = i * 2) {
        k = &params[j];
        v = &params[j + 1];

        len += 1 + k->len + ((v->len > 127) ? 4 : 1) + v->len;
    }

    padding = 8 - len % 8;
    padding = (padding == 8) ? 0 : padding;

    size = sizeof(ngx_http_fastcgi_header_t)
        + sizeof(ngx_http_fastcgi_begin_request_t)

        + sizeof(ngx_http_fastcgi_header_t)  /* NGX_HTTP_FASTCGI_PARAMS */
        + len + padding
        + sizeof(ngx_http_fastcgi_header_t)  /* NGX_HTTP_FASTCGI_PARAMS */

        + sizeof(ngx_http_fastcgi_header_t); /* NGX_HTTP_FASTCGI_STDIN */


    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        return NULL;
    }

    ngx_http_fastcgi_request_start.br.flags = 0;

    ngx_memcpy(b->pos, &ngx_http_fastcgi_request_start,
               sizeof(ngx_http_fastcgi_request_start_t));

    h = (ngx_http_fastcgi_header_t *)
        (b->pos + sizeof(ngx_http_fastcgi_header_t)
         + sizeof(ngx_http_fastcgi_begin_request_t));

    h->content_length_hi = (u_char) ((len >> 8) & 0xff);
    h->content_length_lo = (u_char) (len & 0xff);
    h->padding_length = (u_char) padding;
    h->reserved = 0;

    b->last = b->pos + sizeof(ngx_http_fastcgi_header_t)
        + sizeof(ngx_http_fastcgi_begin_request_t)
        + sizeof(ngx_http_fastcgi_header_t);

    for (i = 0, j = 0; i < num; i++, j = i * 2) {
        k = &params[j];
        v = &params[j + 1];

        if (k->len > 127) {
            *b->last++ = (u_char) (((k->len >> 24) & 0x7f) | 0x80);
            *b->last++ = (u_char) ((k->len >> 16) & 0xff);
            *b->last++ = (u_char) ((k->len >> 8) & 0xff);
            *b->last++ = (u_char) (k->len & 0xff);

        } else {
            *b->last++ = (u_char) k->len;
        }

        if (v->len > 127) {
            *b->last++ = (u_char) (((v->len >> 24) & 0x7f) | 0x80);
            *b->last++ = (u_char) ((v->len >> 16) & 0xff);
            *b->last++ = (u_char) ((v->len >> 8) & 0xff);
            *b->last++ = (u_char) (v->len & 0xff);

        } else {
            *b->last++ = (u_char) v->len;
        }

        b->last = ngx_copy(b->last, k->data, k->len);
        b->last = ngx_copy(b->last, v->data, v->len);
    }

    if (padding) {
        ngx_memzero(b->last, padding);
        b->last += padding;
    }

    h = (ngx_http_fastcgi_header_t *) b->last;
    b->last += sizeof(ngx_http_fastcgi_header_t);

    h->version = 1;
    h->type = NGX_HTTP_FASTCGI_PARAMS;
    h->request_id_hi = 0;
    h->request_id_lo = 1;
    h->content_length_hi = 0;
    h->content_length_lo = 0;
    h->padding_length = 0;
    h->reserved = 0;

    h = (ngx_http_fastcgi_header_t *) b->last;
    b->last += sizeof(ngx_http_fastcgi_header_t);

    return b;
}



static char *
ngx_http_upstream_check_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_buf_t                      *b;
    ngx_uint_t                      i;
    ngx_http_upstream_srv_conf_t  **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    b = ngx_http_upstream_check_create_fastcgi_request(cf->pool,
            fastcgi_default_params,
            sizeof(fastcgi_default_params) / sizeof(ngx_str_t) / 2);

    if (b == NULL) {
        return NGX_CONF_ERROR;
    }

    fastcgi_default_request.data = b->pos;
    fastcgi_default_request.len = b->last - b->pos;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (ngx_http_upstream_check_init_srv_conf(cf, uscfp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return ngx_http_upstream_check_init_shm(cf, conf);
}


static void *
ngx_http_upstream_check_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_check_srv_conf_t  *ucscf;

    ucscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_check_srv_conf_t));
    if (ucscf == NULL) {
        return NULL;
    }

    ucscf->fastcgi_params = ngx_array_create(cf->pool, 2 * 4, sizeof(ngx_str_t));
    if (ucscf->fastcgi_params == NULL) {
        return NULL;
    }

    ucscf->port = NGX_CONF_UNSET_UINT;
    ucscf->fall_count = NGX_CONF_UNSET_UINT;
    ucscf->rise_count = NGX_CONF_UNSET_UINT;
    ucscf->check_timeout = NGX_CONF_UNSET_MSEC;
    ucscf->check_keepalive_requests = NGX_CONF_UNSET_UINT;
    ucscf->check_type_conf = NGX_CONF_UNSET_PTR;

    ucscf->check_cmd_on=0;

    return ucscf;
}


ngx_int_t
ngx_http_upstream_check_add_variable(ngx_conf_t *cf ,ngx_str_t * var_name)
{
    ngx_http_variable_t *var = ngx_http_add_variable(cf, var_name, ngx_http_custom_var_default.flags);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->set_handler = ngx_http_custom_var_default.set_handler;
    var->get_handler = ngx_http_custom_var_default.get_handler;
    var->data = ngx_str_2_hash(var_name);
    vars_hash.name_hash[vars_hash.count++] = ngx_str_2_hash(var_name);

    return NGX_OK;
}


static void *
ngx_http_upstream_check_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_check_loc_conf_t  *uclcf;

    uclcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_check_loc_conf_t));
    if (uclcf == NULL) {
        return NULL;
    }

    uclcf->format = NGX_CONF_UNSET_PTR;

    return uclcf;
}


static char *
ngx_http_upstream_check_init_srv_conf(ngx_conf_t *cf, void *conf)
{
    ngx_str_t                           s;
    ngx_buf_t                          *b;
    ngx_check_conf_t                   *check;
    ngx_http_upstream_srv_conf_t       *us = conf;
    ngx_http_upstream_check_srv_conf_t *ucscf;

    if (us->srv_conf == NULL) {
        return NGX_CONF_OK;
    }

    ucscf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_check_module);

    if (ucscf->port == NGX_CONF_UNSET_UINT) {
        ucscf->port = 0;
    }

    if (ucscf->fall_count == NGX_CONF_UNSET_UINT) {
        ucscf->fall_count = 2;
    }

    if (ucscf->rise_count == NGX_CONF_UNSET_UINT) {
        ucscf->rise_count = 5;
    }

    if (ucscf->check_interval == NGX_CONF_UNSET_MSEC) {
        ucscf->check_interval = 0;
    }

    if (ucscf->check_timeout == NGX_CONF_UNSET_MSEC) {
        ucscf->check_timeout = 1000;
    }

    if (ucscf->check_keepalive_requests == NGX_CONF_UNSET_UINT) {
        ucscf->check_keepalive_requests = 1;
    }

    if (ucscf->check_type_conf == NGX_CONF_UNSET_PTR) {
        ucscf->check_type_conf = NULL;
    }

    check = ucscf->check_type_conf;

    if (check) {
        if (ucscf->send.len == 0) {
            ngx_str_set(&s, "fastcgi");

            if (check == ngx_http_get_check_type_conf(&s)) {

                if (ucscf->fastcgi_params->nelts == 0) {
                    ucscf->send.data = fastcgi_default_request.data;
                    ucscf->send.len = fastcgi_default_request.len;

                } else {
                    b = ngx_http_upstream_check_create_fastcgi_request(
                            cf->pool, ucscf->fastcgi_params->elts,
                            ucscf->fastcgi_params->nelts / 2);
                    if (b == NULL) {
                        return NGX_CONF_ERROR;
                    }

                    ucscf->send.data = b->pos;
                    ucscf->send.len = b->last - b->pos;
                }
            } else {
                ucscf->send.data = check->default_send.data;
                ucscf->send.len = check->default_send.len;
            }
        }


        if (ucscf->code.status_alive == 0) {
            ucscf->code.status_alive = check->default_status_alive;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_str_t                            format = ngx_string("html");
    ngx_http_upstream_check_loc_conf_t  *prev = parent;
    ngx_http_upstream_check_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->format, prev->format,
                             ngx_http_get_check_status_format_conf(&format));

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_check_init_shm(ngx_conf_t *cf, void *conf)
{
    ngx_str_t                            *shm_name;
    ngx_uint_t                            shm_size;
    ngx_shm_zone_t                       *shm_zone;
    ngx_http_upstream_check_main_conf_t  *ucmcf = conf;

    if (ucmcf->peers->peers.nelts > 0) {

        ngx_http_upstream_check_shm_generation++;

        shm_name = &ucmcf->peers->check_shm_name;

        ngx_http_upstream_check_get_shm_name(shm_name, cf->pool,
                                    ngx_http_upstream_check_shm_generation);

        /* The default check shared memory size is 5M */
        shm_size = 5 * 1024 * 1024;

        shm_size = shm_size < ucmcf->shm_size ?
                              ucmcf->shm_size : shm_size;

        shm_zone = ngx_shared_memory_add(cf, shm_name, shm_size,
                                         &ngx_http_upstream_check_module);

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                       "http upstream check, upsteam:%V, shm_zone size:%ui",
                       shm_name, shm_size);

        shm_zone->data = cf->pool;
        check_peers_ctx = ucmcf->peers;

        shm_zone->init = ngx_http_upstream_check_init_shm_zone;
    }
    else {
         check_peers_ctx = NULL;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_upstream_check_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool,
    ngx_uint_t generation)
{
    u_char  *last;

    shm_name->data = ngx_palloc(pool, SHM_NAME_LEN);
    if (shm_name->data == NULL) {
        return NGX_ERROR;
    }

    last = ngx_snprintf(shm_name->data, SHM_NAME_LEN, "%s#%ui",
                        "ngx_http_upstream_check", generation);

    shm_name->len = last - shm_name->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                               size;
    ngx_str_t                            oshm_name;
    ngx_int_t                            rc;
    ngx_uint_t                           i, same, number;
    ngx_pool_t                          *pool;
    ngx_shm_zone_t                      *oshm_zone;
    ngx_slab_pool_t                     *shpool;
    ngx_http_upstream_check_peer_t      *peer;
    ngx_http_upstream_check_peers_t     *peers;
    ngx_http_upstream_check_srv_conf_t  *ucscf;
    ngx_http_upstream_check_peer_shm_t  *peer_shm, *opeer_shm;
    ngx_http_upstream_check_peers_shm_t *peers_shm, *opeers_shm;

    opeers_shm = NULL;
    peers_shm = NULL;
    ngx_str_null(&oshm_name);

    same = 0;
    peers = check_peers_ctx;
    if (peers == NULL) {
        return NGX_OK;
    }

    number = peers->peers.nelts;
    if (number == 0) {
        return NGX_OK;
    }

    pool = shm_zone->data;
    if (pool == NULL) {
        pool = ngx_cycle->pool;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (data) {
        opeers_shm = data;

        if ((opeers_shm->number == number)
            && (opeers_shm->checksum == peers->checksum)) {

            peers_shm = data;
            same = 1;
        }
    }

    if (!same) {

        if (ngx_http_upstream_check_shm_generation > 1) {

            ngx_http_upstream_check_get_shm_name(&oshm_name,
                    pool, ngx_http_upstream_check_shm_generation - 1);

            /* The global variable ngx_cycle still points to the old one */
            oshm_zone = ngx_shared_memory_find((ngx_cycle_t *) ngx_cycle,
                                               &oshm_name,
                                               &ngx_http_upstream_check_module);

            if (oshm_zone) {
                opeers_shm = oshm_zone->data;

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
                               "http upstream check, find oshm_zone:%p, "
                               "opeers_shm: %p",
                               oshm_zone, opeers_shm);
            }
        }

        size = sizeof(*peers_shm) +
               (number - 1) * sizeof(ngx_http_upstream_check_peer_shm_t);

        peers_shm = ngx_slab_alloc(shpool, size);

        if (peers_shm == NULL) {
            goto failure;
        }

        ngx_memzero(peers_shm, size);
    }

    peers_shm->generation = ngx_http_upstream_check_shm_generation;
    peers_shm->checksum = peers->checksum;
    peers_shm->number = number;

    peer = peers->peers.elts;

    for (i = 0; i < number; i++) {

        peer_shm = &peers_shm->peers[i];

        /*
         * This function may be triggered before the old stale
         * work process exits. The owner may stick to the old
         * pid.
         */
        peer_shm->owner = NGX_INVALID_PID;

        if (same) {
            continue;
        }

        peer_shm->socklen = peer[i].peer_addr->socklen;
        peer_shm->sockaddr = ngx_slab_alloc(shpool, peer_shm->socklen);
        if (peer_shm->sockaddr == NULL) {
            goto failure;
        }

        ngx_memcpy(peer_shm->sockaddr, peer[i].peer_addr->sockaddr,
                   peer_shm->socklen);

        peer_shm->upstream_name = ngx_str_2_hash( peer[i].upstream_name ) ;

        /*if (vars_hash_conf.count > 0){
        	ngx_uint_t i;
        	for(i=0;i<vars_hash_conf.count;i++){
        		ngx_reload_var_conf( &vars_hash_conf.v_fs[i].f_conf, &vars_hash_conf.v_fs[i].var_name);
        	}
        }*/


        if (opeers_shm) {

            opeer_shm = ngx_http_upstream_check_find_shm_peer(opeers_shm,
                                                              peer[i].peer_addr , peer[i].upstream_name);
            if (opeer_shm) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, shm_zone->shm.log, 0,
                               "http upstream check, inherit opeer: %V ",
                               &peer[i].peer_addr->name);

                rc = ngx_http_upstream_check_init_shm_peer(peer_shm, opeer_shm,
                         0, pool, &peer[i].peer_addr->name);
                if (rc != NGX_OK) {
                    return NGX_ERROR;
                }

                continue;
            }
        }

        ucscf = peer[i].conf;
        rc = ngx_http_upstream_check_init_shm_peer(peer_shm, NULL,
                                                   ucscf->default_down, pool,
                                                   &peer[i].peer_addr->name);
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    }

    peers->peers_shm = peers_shm;
    shm_zone->data = peers_shm;

    if (vars_hash_conf.count > 0){
		ngx_uint_t i;
		for(i=0;i<vars_hash_conf.count;i++){
			ngx_reload_var_conf( &vars_hash_conf.v_fs[i].f_conf, &vars_hash_conf.v_fs[i].var_name);
		}
	}

	if (opeers_shm) {
		if(&opeers_shm->vars[0] && opeers_shm->vars[0].var_name_hash > 0){
			ngx_uint_t i=0,k=0;
			for( ; i<var_max_count && opeers_shm->vars[i].var_name_hash > 0 ;i++){
				ngx_uint_t j=0;
				for(; j < vars_hash.count ;j++){
					if (opeers_shm->vars[i].var_name_hash == vars_hash.name_hash[j] ){
						memcpy( &peers_shm->vars[k++] , &opeers_shm->vars[i], sizeof(ngx_variable));
						break;
					}
				}
			}
		}
		//
		if ( opeers_shm->ips[0].addr){
			memcpy( &peers_shm->ips , &opeers_shm->ips, sizeof(opeers_shm->ips));
		}
	}


    return NGX_OK;

failure:
    ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                  "http upstream shm_size is too small, "
                  "you should specify a larger size.");
    return NGX_ERROR;
}


static ngx_shm_zone_t *
ngx_shared_memory_find(ngx_cycle_t *cycle, ngx_str_t *name, void *tag)
{
    ngx_uint_t        i;
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;

    part = (ngx_list_part_t *) &(cycle->shared_memory.part);
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (name->len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (ngx_strncmp(name->data, shm_zone[i].shm.name.data, name->len) != 0)
        {
            continue;
        }

        if (tag != shm_zone[i].tag) {
            continue;
        }

        return &shm_zone[i];
    }

    return NULL;
}


static ngx_http_upstream_check_peer_shm_t *
ngx_http_upstream_check_find_shm_peer(ngx_http_upstream_check_peers_shm_t *p, ngx_addr_t *addr ,ngx_str_t *upname)
{
    ngx_uint_t                          i;
    ngx_http_upstream_check_peer_shm_t *peer_shm;

    for (i = 0; i < p->number; i++) {

        peer_shm = &p->peers[i];

        if (addr->socklen != peer_shm->socklen) {
            continue;
        }
        if (ngx_str_2_hash(upname) == peer_shm->upstream_name
        		&& ngx_memcmp(addr->sockaddr, peer_shm->sockaddr, addr->socklen) == 0) {

            return peer_shm;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_upstream_check_init_shm_peer(ngx_http_upstream_check_peer_shm_t *psh,
    ngx_http_upstream_check_peer_shm_t *opsh, ngx_uint_t init_down,
    ngx_pool_t *pool, ngx_str_t *name)
{
    u_char  *file;

    if (opsh) {
        psh->access_time  = opsh->access_time;
        psh->access_count = opsh->access_count;

        psh->fall_count   = opsh->fall_count;
        psh->rise_count   = opsh->rise_count;
        psh->busyness     = opsh->busyness;

        psh->down         = opsh->down;

        psh->force_down   = opsh->force_down;
        psh->weight   = opsh->weight;
        psh->v_weight = opsh->v_weight;
        psh->v_total_weight = opsh->v_total_weight;
        psh->upstream_name = opsh->upstream_name;

    } else {
        psh->access_time  = 0;
        psh->access_count = 0;

        psh->fall_count   = 0;
        psh->rise_count   = 0;
        psh->busyness     = 0;

        psh->down         = init_down;

        psh->force_down   = 0;
        psh->weight   = 0;
        psh->v_weight = 0;
        psh->v_total_weight = 0;
    }

#if (NGX_HAVE_ATOMIC_OPS)

    file = NULL;

#else

    file = ngx_pnalloc(pool, ngx_cycle->lock_file.len + name->len);
    if (file == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_sprintf(file, "%V%V%Z", &ngx_cycle->lock_file, name);

#endif

#if (nginx_version >= 1002000)
    if (ngx_shmtx_create(&psh->mutex, &psh->lock, file) != NGX_OK) {
#else
    if (ngx_shmtx_create(&psh->mutex, (void *) &psh->lock, file) != NGX_OK) {
#endif
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_check_init_process(ngx_cycle_t *cycle)
{
    ngx_http_upstream_check_main_conf_t *ucmcf;

    if (ngx_process != NGX_PROCESS_WORKER) {
        return NGX_OK;
    }

    ucmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_upstream_check_module);
    if (ucmcf == NULL) {
        return NGX_OK;
    }

    return ngx_http_upstream_check_add_timers(cycle);
}


void
ngx_http_add_address_rule(ngx_http_request_t *r ,ngx_str_t *address , ngx_uint_t deny)
{
    ngx_cidr_t                  cidr;
    ngx_int_t                   rc, flag=NGX_FALSE;
    ngx_http_access_rule_t      *deny_ips;
    size_t    i;
	struct sockaddr_in *sin;

    if(check_peers_ctx) {
		rc = ngx_ptocidr(address, &cidr);
	    if (rc == NGX_OK) {
	        if ( cidr.family == AF_INET ) {
				sin = (struct sockaddr_in *) r->connection->sockaddr;
				//the deny ip must not current client ip
				if ( (sin->sin_addr.s_addr & cidr.u.in.mask) == cidr.u.in.addr ) {
					return ;
				}
	        	//
	        	deny_ips = check_peers_ctx->peers_shm->ips;
	        	for(i = 0;i< var_max_access_ip ;i++){
	        		if(deny_ips[i].addr == 0 && deny && !flag) {
	        			deny_ips[i].mask = cidr.u.in.mask;
	        			deny_ips[i].addr = cidr.u.in.addr;
	        			deny_ips[i].deny = deny;
	        			flag = NGX_TRUE;
	        		}else if ( deny_ips[i].addr == cidr.u.in.addr &&  deny_ips[i].mask == cidr.u.in.mask){
	        			if(!deny){
	        				deny_ips[i].addr = 0;
	        			}
	        			break;
	        		}
	        	}
			}
		}
    }
}


static ngx_int_t
ngx_http_access_handler(ngx_http_request_t *r)
{
	struct sockaddr_in          *sin;
	size_t   i;
    ngx_http_access_rule_t      *deny_ips;

	if(r->connection->sockaddr->sa_family == AF_INET) {
		if(check_peers_ctx) {
			sin = (struct sockaddr_in *) r->connection->sockaddr;
			deny_ips = check_peers_ctx->peers_shm->ips;
			for(i = 0;i< var_max_access_ip ;i++){
				if(deny_ips[i].addr){
					if ((sin->sin_addr.s_addr & deny_ips[i].mask) == deny_ips[i].addr) {
						return NGX_HTTP_FORBIDDEN;
					}
				}
			}
		}
	}
    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_upstream_modify_conf(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_access_handler;

    return NGX_OK;
}

ngx_str_t*
ngx_http_deny_list(ngx_pool_t *pool)
{
    ngx_str_t *str ,ip;
    size_t i,buf_size = 0 ;
    ngx_http_access_rule_t      *deny_ips;
    u_char *b;
    size_t ip_len = 18;//xxx.xxx.xxx.xxx/xx
    uint32_t m ;

    str = ngx_palloc(pool, sizeof(ngx_str_t));
    str->len = 0;
    str->data = NULL;

    if(check_peers_ctx) {
    	deny_ips = check_peers_ctx->peers_shm->ips;
    	for(i = 0;i< var_max_access_ip ;i++){
			if(deny_ips[i].addr){
				buf_size+= ip_len+1; //\n
			}
    	}
    	if(buf_size == 0) {
    		return NULL;
    	}
    	b = str->data = ngx_palloc(pool, buf_size);
    	ip.data = ngx_palloc(pool, ip_len+1);
    	for(i = 0;i< var_max_access_ip ;i++){
			if(deny_ips[i].addr){
			    ngx_inet_ntoa(deny_ips[i].addr , &ip);
			    b = ngx_strcat(b,ip.data,ip.len);
			    str->len += ip.len;
			    /*
			     * Formula:
			     * htonl((uint32_t) (0xffffffffu << (32 - shift)));
			     * if "shift" equals 24 ,the resualt is 24 "1"s  is 111111111111111111111111
			     * this formula as same as 2^24-1
			     * */
			    if(deny_ips[i].mask < 0xffffffff){ //
				    *b = '/';
				    b+=1;
				    m = deny_ips[i].mask;
				    m = ngx_math_log2(m);

/*				    u_char *ms;
				    ms = (u_char*)(&deny_ips[i].addr);
				    printf(" -1--------- %d %d %d %d- \n",ms[0],ms[1],ms[2],ms[3]);
*/
				    /*m = ntohl(deny_ips[i].mask);
				    m = ~(m/deny_ips[i].mask);
				    m = 32 - m/0xffffffff/2;
				    m = (m >> 23) & 0xff;
				    m -= 127;*/
			    	ngx_sprintf(b,"%ui",m);
			    	b+=2;
			    	str->len+=3;
			    }
			    *b = '\n';
			    b+=1;
			    str->len += 1;
			}
		}
    }

    return str;
}
