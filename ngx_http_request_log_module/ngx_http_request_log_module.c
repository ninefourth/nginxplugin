/**
 * */
#include "ngx_http_request_log_module.h"
#include "../ngx_common/ngx_common_util.h"
#include "../ngx_common/uthash.h"

static char *ngx_http_request_log_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_request_log_filter_init(ngx_conf_t *cf);
//static char *ngx_http_request_log_init_main_conf(ngx_conf_t *cf, void *conf);

ngx_int_t volatile request_log = NGX_FALSE;
const ngx_int_t IPLEN = 22;

static ngx_command_t ngx_http_request_log_commands[] = {
   {
        ngx_string("request_log"),
		NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1 ,
        ngx_http_request_log_conf,
        0,
        0,
        NULL
   },
   ngx_null_command
};

//模块环境参数
static ngx_http_module_t  ngx_http_request_log_module_ctx = {
    NULL,                                  /* preconfiguration */
	ngx_http_request_log_filter_init,               /* postconfiguration */
    NULL,                                  /* create main configuration */
	NULL,//ngx_http_request_log_init_main_conf,          /* init main configuration */
    NULL,  /* create server configuration */
    NULL,                                  /* merge server configuration */
    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

//模块入口
ngx_module_t  ngx_http_request_log_module = {
    NGX_MODULE_V1,
	&ngx_http_request_log_module_ctx, 			    /* module context */
	ngx_http_request_log_commands,			    /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
	NULL,						           /* init master */
    NULL,                                  /* init module */
	NULL,					               /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
//

struct request_log_s{ //内存，存放日志
    ngx_uint_t req_id;                    /* key */
    u_char *line;					/* value */
    ngx_pool_t	*pool;
    UT_hash_handle hh;         /* makes this structure hashable */
};
struct request_log_s *req_log = NULL;
//

//////////from ngx_http_log_module
extern ngx_module_t  ngx_http_log_module;
typedef struct ngx_http_log_op_s  ngx_http_log_op_t;
typedef u_char *(*ngx_http_log_op_run_pt) (ngx_http_request_t *r, u_char *buf,ngx_http_log_op_t *op);
typedef size_t (*ngx_http_log_op_getlen_pt) (ngx_http_request_t *r,uintptr_t data);

typedef struct ngx_slab_page_s_s  ngx_slab_page_t_t;
struct ngx_slab_page_s_s {
    uintptr_t         slab;
    ngx_slab_page_t_t  *next;
    uintptr_t         prev;
};

struct ngx_http_log_op_s {
    size_t                      len;
    ngx_http_log_op_getlen_pt   getlen;
    ngx_http_log_op_run_pt      run;
    uintptr_t                   data;
};

typedef struct {
    ngx_str_t                   name;
    ngx_array_t                *flushes;
    ngx_array_t                *ops;        /* array of ngx_http_log_op_t */
} ngx_http_log_fmt_t;

typedef struct {
    u_char                     *start;
    u_char                     *pos;
    u_char                     *last;
    ngx_event_t                *event;
    ngx_msec_t                  flush;
    ngx_int_t                   gzip;
} ngx_http_log_buf_t;

typedef struct {
    ngx_array_t                *lengths;
    ngx_array_t                *values;
} ngx_http_log_script_t;

typedef struct {
    ngx_open_file_t            *file;
    ngx_http_log_script_t      *script;
    time_t                      disk_full_time;
    time_t                      error_log_time;
    ngx_syslog_peer_t          *syslog_peer;
    ngx_http_log_fmt_t         *format;
    ngx_http_complex_value_t   *filter;
} ngx_http_log_t;

typedef struct {
    ngx_array_t                *logs;       /* array of ngx_http_log_t */

    ngx_open_file_cache_t      *open_file_cache;
    time_t                      open_file_cache_valid;
    ngx_uint_t                  open_file_cache_min_uses;

    ngx_uint_t                  off;        /* unsigned  off:1 */
} ngx_http_log_loc_conf_t;

//////////
void request_log_delete_all() {
	struct request_log_s *hd_rg, *rg, *tmp;
	hd_rg = req_log;
	HASH_ITER(hh, hd_rg, rg, tmp) {
		HASH_DEL(hd_rg, rg);
		ngx_pfree(rg->pool,rg->line);
		ngx_pfree(rg->pool,rg);
	}
}

void ngx_http_request_log_disable()
{
	request_log = NGX_FALSE;
	request_log_delete_all();
//	HASH_CLEAR(hh,req_log);
	req_log = NULL;
}

void ngx_http_request_log_enable()
{
	request_log = NGX_TRUE;
}

static ngx_uint_t
ngx_http_request_log_get_reqid(ngx_http_request_t *r)
{
	return (ngx_uint_t)r + r->start_sec*1000 + r->start_msec;
}

//将上游服务器信息记入日志
void
ngx_http_request_log_write_server(ngx_int_t rid, u_char *nm, size_t len)
{
	if(request_log == NGX_TRUE) {
		struct request_log_s *rg;
		HASH_FIND_INT(req_log, &rid, rg);
		if(rg != NULL) {
			ngx_str_t token;
			ngx_str_sch_next_trimtoken(rg->line, strlen((char*)rg->line), ' ', &token);
			if(token.len > 0) {
				ngx_memcpy(rg->line+token.len+1,nm,len);
				if( IPLEN - len > 0 ) {
					ngx_memset(rg->line+token.len+1+len,' ',IPLEN-len);
				}
			}
		}
	}
}

static void
ngx_http_request_log_append(ngx_http_request_t *r , u_char *line , size_t len)
{
	struct request_log_s *rg;
	ngx_uint_t rid;
//	rg = ngx_alloc(sizeof(*rg),r->connection->log);
//	rg->line = ngx_alloc(len+1,r->connection->log);
	rg = ngx_palloc(r->pool,sizeof(*rg));
	rg->line = ngx_palloc(r->pool,len+1);
	rg->pool = r->pool;
	cpy_chars(rg->line,line,len);
	rid = ngx_http_request_log_get_reqid(r);
	rg->req_id = rid;
	HASH_ADD_INT(req_log,req_id,rg);
}

static void
ngx_http_request_log_remove(ngx_http_request_t *r)
{
	ngx_uint_t rid;
	if(request_log == NGX_TRUE && r->start_sec > 0) {
		rid = ngx_http_request_log_get_reqid(r);
		struct request_log_s *rg;
		HASH_FIND_INT(req_log, &rid, rg);
		if(rg != NULL) {
			HASH_DEL(req_log,rg);
			ngx_pfree(rg->pool,rg->line);
			ngx_pfree(rg->pool,rg);
		}
	}
}

//此处照抄ngx_http_log_module.c的ngx_http_log_handler方法,把写到文件替换为写入内存
static ngx_int_t
ngx_http_request_log_access_handler(ngx_http_request_t *r)
{
	if(request_log == NGX_TRUE){
		u_char                   *line, *p ,*sp;
		size_t                    len, size;
		ssize_t                   n;
		ngx_str_t                 val;
		ngx_uint_t                i, l;
		ngx_http_log_t           *log;
		ngx_http_log_op_t        *op;
		ngx_http_log_buf_t       *buffer;
		ngx_http_log_loc_conf_t  *lcf;
		ngx_int_t ms;

		lcf = ngx_http_get_module_loc_conf(r, ngx_http_log_module);
		if (lcf->off) {
			return NGX_OK;
		}
		log = lcf->logs->elts;
		for (l = 0; l < lcf->logs->nelts; l++) {
			if (log[l].filter) {
				if (ngx_http_complex_value(r, log[l].filter, &val) != NGX_OK) {
					return NGX_ERROR;
				}
				if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
					continue;
				}
			}
			if (ngx_time() == log[l].disk_full_time) {
				/*
				 * on FreeBSD writing to a full filesystem with enabled softupdates
				 * may block process for much longer time than writing to non-full
				 * filesystem, so we skip writing to a log for one second
				 */
				continue;
			}

			ngx_http_script_flush_no_cacheable_variables(r, log[l].format->flushes);
			len = 0;
			op = log[l].format->ops->elts;
			for (i = 0; i < log[l].format->ops->nelts; i++) {
				if (op[i].len == 0) {
					len += op[i].getlen(r, op[i].data);

				} else {
					len += op[i].len;
				}
			}
			if (log[l].syslog_peer) {
				/* length of syslog's PRI and HEADER message parts */
				len += sizeof("<255>Jan 01 00:00:00 ") - 1 + ngx_cycle->hostname.len + 1 + log[l].syslog_peer->tag.len + 2;
				goto alloc_line;
			}
			len += NGX_LINEFEED_SIZE;
			buffer = log[l].file ? log[l].file->data : NULL;
			if (buffer) {
				if (len > (size_t) (buffer->last - buffer->pos)) {
					//TODO 写入内存
//					ngx_http_log_write(r, &log[l], buffer->start,buffer->pos - buffer->start);
					ngx_http_request_log_append(r, buffer->start, buffer->pos - buffer->start);
					buffer->pos = buffer->start;
				}
				if (len <= (size_t) (buffer->last - buffer->pos)) {
					p = buffer->pos;
					if (buffer->event && p == buffer->start) {
						ngx_add_timer(buffer->event, buffer->flush);
					}
					for (i = 0; i < log[l].format->ops->nelts; i++) {
						p = op[i].run(r, p, &op[i]);
					}
					ngx_linefeed(p);
					buffer->pos = p;
					continue;
				}
				if (buffer->event && buffer->event->timer_set) {
					ngx_del_timer(buffer->event);
				}
			}

		alloc_line:
			ms = r->start_sec * 1000 + r->start_msec;
			size = ngx_num_bit_count(ms);
			line = ngx_pnalloc(r->pool, len + size + IPLEN + 1); //ms+server+log+'\0'
			if (line == NULL) {
				return NGX_ERROR;
			}
			sp = line;
			line = ngx_strcat(line,ngx_int_to_str(r->pool,ms),size);
			line = ngx_strcat(line,(u_char*)" ",1);
			ngx_memset(line,' ',IPLEN); //placeholder server
			line += IPLEN;
			p = line;
			//
			if (log[l].syslog_peer) {
				p = ngx_syslog_add_header(log[l].syslog_peer, line);
			}
			for (i = 0; i < log[l].format->ops->nelts; i++) {
				p = op[i].run(r, p, &op[i]);
			}
			if (log[l].syslog_peer) {
				size = p - line;
				n = ngx_syslog_send(log[l].syslog_peer, line, size);
				if (n < 0) {
					ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,"send() to syslog failed");

				} else if ((size_t) n != size) {
					ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,"send() to syslog has written only %z of %uz",n, size);
				}
				continue;
			}
			ngx_linefeed(p);
			//TODO 写入内存
//			ngx_http_log_write(r, &log[l], line, p - line);
			ngx_http_request_log_append(r, sp, p - sp);
		}
	}
    return NGX_DECLINED;
}

void ngx_http_request_log_print(ngx_str_t *f,ngx_http_request_t *r)
{
	ngx_fd_t          fd;
//	ngx_file_info_t   fi;
	ngx_http_request_log_remove(r); //排除 log/print?file=
	ngx_delete_file(f->data);
	fd = ngx_open_file(f->data, NGX_FILE_APPEND, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
	if (fd != NGX_INVALID_FILE) {
		struct request_log_s *rg;
		char* ssm;
		ngx_time_t      *tp;
		ngx_msec_int_t   ms, cms;
		ngx_int_t			hd;
		ngx_str_t		token;
	    tp = ngx_timeofday();
	    cms = tp->sec * 1000 + tp->msec;
		for (rg = req_log; rg != NULL; rg = rg->hh.next) {
			//TODO
		    ngx_str_sch_next_trimtoken(rg->line, strlen((char*)rg->line), ' ', &token);
		    if(token.len > 0) {
		    	hd = ngx_str_to_int(token.data,token.len);
		    	ms = cms - hd; //请求耗时
		    	ssm = (char*)ngx_int_to_str(r->pool,ms);
		    	rg->line += (token.len - strlen(ssm));
		    	ngx_memcpy(rg->line,ssm,strlen(ssm));
				ngx_write_fd(fd, rg->line, strlen((char*)rg->line));
				rg->line = token.data; //原始位置
		    }
		}
		//
		if (ngx_close_file(fd) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"close request log file [%V] failed", f);
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"write request log to file [%V] failed", f);
	}
}

static ngx_int_t
ngx_http_request_log_handler(ngx_http_request_t *r)
{
	//TODO 清掉r对应的内存日志
	ngx_http_request_log_remove(r);
	return NGX_DECLINED;
}

static ngx_int_t
ngx_http_request_log_filter_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt        *rh,*lh;
    ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

//    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
	/*if( cmcf->phases[NGX_HTTP_POST_ACCESS_PHASE].handlers.size == 0 ) {
		if (ngx_array_init(&cmcf->phases[NGX_HTTP_POST_ACCESS_PHASE].handlers, cf->pool, 1, sizeof(ngx_http_handler_pt)) != NGX_OK) {
			return NGX_ERROR;
		}
	}*/

    rh = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (rh == NULL) {
        return NGX_ERROR;
    }
    *rh = ngx_http_request_log_access_handler;
    //
    lh = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
	if (lh == NULL) {
		return NGX_ERROR;
	}
	*lh = ngx_http_request_log_handler;

    return NGX_OK;
}

static char *ngx_http_request_log_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t *value = cf->args->elts ;
	if( ngx_str_cmp2(&value[1],"on") == 0) {
		request_log = NGX_TRUE;
	}
	//
	return NGX_CONF_OK;
}
