/**
 * */
#include "ngx_http_request_log_module.h"
#include "../ngx_common/ngx_common_util.h"
#include "../ngx_common/uthash.h"
#include <ngx_thread.h>
typedef __int32_t int32_t;

static char *ngx_http_request_log_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_request_log_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_request_log_init_process(ngx_cycle_t *cycle);

//static char *ngx_http_request_log_init_main_conf(ngx_conf_t *cf, void *conf);
#define ngx_req_timestamp 1672531200 //1970-2023时间秒
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
	ngx_http_request_log_init_process,               /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
//

typedef struct request_log_s{ //内存，存放日志
	int32_t req_id;                    /* key */
    u_char *line;					/* value */
//    ngx_pool_t	*pool;
    UT_hash_handle hh;         /* makes this structure hashable */
} request_log_t;

request_log_t *req_log = NULL;
request_log_t default_fst_req_log;
const int32_t REQ_FIST_LOG_ID = -1;
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

#define debug_log(log,txt,l)																				\
	do {																								\
		if ( (req_log) != NULL) {																		\
			ngx_log_error(NGX_LOG_ERR, log, 0, "-- %s ----------------- ngx_pid:%d === tbl:%l pid:%d tid:%d rid:%d", 	\
						txt, ngx_pid, (req_log)->hh.tbl, ngx_log_pid, ngx_log_tid, l);								\
		} else {																						\
			ngx_log_error(NGX_LOG_ERR, log, 0, "== %s ========== ngx_pid:%d pid:%d tid:%d rid:%d", 			\
						txt, ngx_pid, ngx_log_pid, ngx_log_tid, l);											\
		}																							\
	}while (0)

//
ngx_atomic_t		log_lock; //volatile
void hash_request_log_add_first()
{
	if( default_fst_req_log.req_id != REQ_FIST_LOG_ID ) {
		default_fst_req_log.req_id = REQ_FIST_LOG_ID;
		default_fst_req_log.line = NULL;
	//	default_fst_req_log.pool = NULL;
		HASH_ADD_INT(req_log,req_id,&default_fst_req_log);//添加到hash一个元素，不让哈希为空,当并发的时候如果hash被清空了会有内存泄露的风险
	}
}

void hash_request_log_add_log(ngx_pool_t *pool, int32_t rid, u_char *line, size_t size)
{
	request_log_t *rg;

	ngx_rwlock_rlock(&log_lock);
	HASH_FIND_INT(req_log, &rid, rg);
	ngx_rwlock_unlock(&log_lock);
	if(rg != NULL){
		ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0, "request_log: duplicated log id %d ",rid);
		return;
	}

	rg = ngx_pcalloc(pool,sizeof(request_log_t));

	if( size == 0) {
		rg->line = line;
	} else {
		rg->line = ngx_palloc(pool,size+1);
//	rg->pool = pool;
		cpy_chars(rg->line,line,size);
	}
	rg->req_id = rid;
//debug_log(ngx_cycle->log,(char*)"hash add begin2",rid);
	ngx_rwlock_wlock(&log_lock);
	HASH_ADD_INT(req_log,req_id,rg);
	ngx_rwlock_unlock(&log_lock);
}

void hash_request_log_find(int32_t rid, request_log_t **rg)
{
	ngx_rwlock_rlock(&log_lock);
	HASH_FIND_INT(req_log, &rid, *rg);
	ngx_rwlock_unlock(&log_lock);
}

void hash_request_log_remove(int32_t rid)
{
	request_log_t *rg;
	ngx_rwlock_wlock(&log_lock);
	HASH_DEL_INT(req_log, &rid, rg);
	ngx_rwlock_unlock(&log_lock);
}

void hash_request_log_delete_all() {
	request_log_t *hd_rg, *rg, *tmp;
	hd_rg = req_log;
	ngx_rwlock_wlock(&log_lock);
	HASH_ITER(hh, hd_rg, rg, tmp) {
		if( rg->req_id != REQ_FIST_LOG_ID ) { //保留默认的一个，为了不使hash置空，因为并发情况下置空会有内存泄露问题
			HASH_DEL(hd_rg, rg);
		//因为所有日志的生命期在request阶段，所以request结束后自动释放
//		ngx_pfree(rg->pool,rg->line);
//		ngx_pfree(rg->pool,rg);
		}
	}
	ngx_rwlock_unlock(&log_lock);
}

void ngx_http_request_log_disable()
{
	request_log = NGX_FALSE;
	hash_request_log_delete_all();
//	HASH_CLEAR(hh,req_log);
}

void ngx_http_request_log_enable()
{
	request_log = NGX_TRUE;
}

static int32_t
ngx_http_request_log_get_reqid(ngx_http_request_t *r)
{
	return (int32_t)((ngx_uint_t)r + r->start_sec*1000 + r->start_msec);
}

//将上游服务器信息记入日志
void
ngx_http_request_log_write_server(ngx_int_t rid, u_char *nm, size_t len)
{
	if(request_log == NGX_TRUE) {
		request_log_t *rg;
		hash_request_log_find(rid,&rg);
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
ngx_http_request_log_append(ngx_http_request_t *r , u_char *line)
{
	int32_t rid;
	rid = ngx_http_request_log_get_reqid(r);
	hash_request_log_add_log(r->pool,rid,line,0);
}

static void
ngx_http_request_log_remove(ngx_http_request_t *r)
{
	int32_t rid;
	if(request_log == NGX_TRUE && r->start_sec > 0) {
		rid = ngx_http_request_log_get_reqid(r);
		hash_request_log_remove(rid);
	}
}

//此处照抄ngx_http_log_module.c的ngx_http_log_handler方法,把写到文件替换为写入内存
static ngx_int_t
ngx_http_request_log_access_handler(ngx_http_request_t *r)
{
	if(request_log == NGX_TRUE){
		u_char                   *line, *p ,*sp;
		size_t                    len, size;
		ngx_str_t                 val;
		ngx_uint_t                i, l;
		ngx_http_log_t           *log;
		ngx_http_log_op_t        *op;
		ngx_http_log_loc_conf_t  *lcf;
		ngx_int_t ms;

		lcf = ngx_http_get_module_loc_conf(r, ngx_http_log_module);
		if (lcf->off) {
			return NGX_OK;
		}
		log = lcf->logs->elts;
		for (l = 0; l < lcf->logs->nelts; l++) {
			if (log[l].syslog_peer) {
				continue;
			}
			if (log[l].filter) {
				if (ngx_http_complex_value(r, log[l].filter, &val) != NGX_OK) {
					return NGX_ERROR;
				}
				if (val.len == 0 || (val.len == 1 && val.data[0] == '0')) {
					continue;
				}
			}

			len = 0;
			op = log[l].format->ops->elts;
			for (i = 0; i < log[l].format->ops->nelts; i++) {
				if (op[i].len == 0) {
					len += op[i].getlen(r, op[i].data);

				} else {
					len += op[i].len;
				}
			}

			len += NGX_LINEFEED_SIZE;

			ms = r->start_sec * 1000 + r->start_msec;
			size = ngx_num_bit_count(ms);
			sp = line = ngx_pnalloc(r->pool, len + size + IPLEN + 1); //ms+server+log+'\0'
			if (line == NULL) {
				return NGX_ERROR;
			}
			line = ngx_strcat(line,ngx_int_to_str(r->pool,ms),size);
			line = ngx_strcat(line,(u_char*)" ",1);
			ngx_memset(line,' ',IPLEN); //placeholder server
			line += IPLEN;
			p = line;
			//
			for (i = 0; i < log[l].format->ops->nelts; i++) {
				p = op[i].run(r, p, &op[i]);
			}
			ngx_linefeed(p);
			sp[p - sp] = '\0';
			//TODO 写入内存
//			ngx_http_log_write(r, &log[l], line, p - line);
//			ngx_http_request_log_append(r, sp, p - sp);
			ngx_http_request_log_append(r, sp);
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
		char* ssm;
		ngx_time_t      *tp;
		ngx_msec_int_t   ms, cms;
		ngx_int_t			hd;
		ngx_str_t		token;
	    tp = ngx_timeofday();
	    cms = tp->sec * 1000 + tp->msec;
	    //
	    request_log_t *hd_rg, *rg, *tmp;
		hd_rg = req_log;
		ngx_rwlock_rlock(&log_lock);
		HASH_ITER(hh, hd_rg, rg, tmp) {
			if( rg != NULL && rg->req_id != REQ_FIST_LOG_ID) {
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
		}
		ngx_rwlock_unlock(&log_lock);
		//
		if (ngx_close_file(fd) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"close request log file [%V] failed", f);
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"open request log file [%V] failed: [%l]", f,fd);
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
    ngx_array_t *lhds = &cmcf->phases[NGX_HTTP_LOG_PHASE].handlers;
    if(lhds->nelts > 0) {
    	ngx_uint_t ns = lhds->nelts;
    	ngx_http_handler_pt *p = (ngx_http_handler_pt*)lhds->elts;
    	lhds->nalloc++;
    	lhds->elts = ngx_palloc(lhds->pool, (ns+1) * lhds->size);
        if (lhds->elts == NULL) {
            return NGX_ERROR;
        }
        lhds->nelts = 0;
        lh = ngx_array_push(lhds);
        ngx_memcpy((ngx_http_handler_pt*)lhds->elts + 1, p, lhds->size * ns);
        lhds->nelts = ns + 1;
        ngx_pfree(lhds->pool,p);
    } else {
    	lh = ngx_array_push(lhds);
    }
//    lh = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
	if (lh == NULL) {
		return NGX_ERROR;
	}
	*lh = ngx_http_request_log_handler;
	hash_request_log_add_first();

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

static ngx_int_t
ngx_http_request_log_init_process(ngx_cycle_t *cycle)
{
//	if(req_log != NULL) {
//		HASH_INIT_POOL(req_log->hh.tbl, cycle->pool);
//	}
	return NGX_OK;
}
