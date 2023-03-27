
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_request_chain_module.h"
#include "../ngx_common/ngx_common_util.h"

static ngx_int_t ngx_http_request_filter_init(ngx_conf_t *cf);
static void *ngx_http_limit_req_create_conf(ngx_conf_t *cf);
extern ngx_module_t  ngx_http_limit_req_module;

static ngx_http_module_t  ngx_http_request_chain_module_ctx = {
    NULL,									/* preconfiguration */
	ngx_http_request_filter_init,					/* postconfiguration */
    NULL,									/* create main configuration */
    NULL,									/* init main configuration */
    NULL,									/* create server configuration */
    NULL,									/* merge server configuration */
	ngx_http_limit_req_create_conf,				/* create location configuration */
    NULL									/* merge location configuration */
};

ngx_module_t  ngx_http_request_chain_module = {
    NGX_MODULE_V1,
    &ngx_http_request_chain_module_ctx,   /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

typedef struct {
    ngx_array_t                  limits;
    ngx_uint_t                   limit_log_level;
    ngx_uint_t                   delay_log_level;
    ngx_uint_t                   status_code;
    ngx_flag_t                   dry_run;
} ngx_http_limit_req_conf_t;

typedef struct {
    u_char                       color;
    u_char                       dummy;
    u_short                      len;
    ngx_queue_t                  queue;
    ngx_msec_t                   last;
    /* integer value, 1 corresponds to 0.001 r/s */
    ngx_uint_t                   excess;
    ngx_uint_t                   count;
    u_char                       data[1];
} ngx_http_limit_req_node_t;


typedef struct {
    ngx_rbtree_t                  rbtree;
    ngx_rbtree_node_t             sentinel;
    ngx_queue_t                   queue;
} ngx_http_limit_req_shctx_t;


typedef struct {
    ngx_http_limit_req_shctx_t  *sh;
    ngx_slab_pool_t             *shpool;
    /* integer value, 1 corresponds to 0.001 r/s */
    ngx_uint_t                   rate;
    ngx_http_complex_value_t     key;
    ngx_http_limit_req_node_t   *node;
} ngx_http_limit_req_ctx_t;

typedef struct {
    ngx_shm_zone_t              *shm_zone;
    /* integer value, 1 corresponds to 0.001 r/s */
    ngx_uint_t                   burst;
    ngx_uint_t                   delay;
} ngx_http_limit_req_limit_t;


typedef struct {
	ngx_uint_t 				hash_loc;
	void						*cnf_addr;
} ngx_http_request_chain_loc_cnf_t;

typedef struct {
	ngx_http_request_chain_loc_cnf_t loc_cnf[100];
	ngx_uint_t					total;
} ngx_http_request_chain_loc_cnfs_t;

static ngx_http_request_chain_loc_cnfs_t loc_cnfs;

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
//static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;
//static ngx_http_request_body_filter_pt   ngx_http_next_request_body_filter;

static ngx_int_t
ngx_http_request_filter(ngx_http_request_t *r)
{
	return ngx_http_next_header_filter(r);
}
/*
static ngx_int_t
ngx_http_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	return ngx_http_next_body_filter(r, in);
}*/
/*
static ngx_int_t
ngx_http_request_body_filter(ngx_http_request_t *r, ngx_chain_t *chain)
{
	return ngx_http_next_request_body_filter(r,chain);
}*/

static ngx_int_t
ngx_http_access_handler(ngx_http_request_t *r)
{
	ngx_http_limit_req_conf_t   *lrcf;
	ngx_cycle_t *cycle;
	cycle = (ngx_cycle_t*)ngx_cycle;
	cycle->modules[ngx_http_request_chain_module.ctx_index];
	lrcf = ngx_http_get_module_loc_conf(r, ngx_http_request_chain_module);
    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_request_filter_init(ngx_conf_t *cf)
{

	ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

//    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_access_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_request_filter;

//    ngx_memzero(&loc_cnfs, sizeof(loc_cnfs));

//    ngx_http_next_body_filter = ngx_http_top_body_filter;
//    ngx_http_top_body_filter = ngx_http_body_filter;

//    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
//    ngx_http_top_request_body_filter = ngx_http_request_body_filter;

    return NGX_OK;
}


static void *
ngx_http_limit_req_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_req_conf_t  *conf;
    ngx_str_t *loc, *uri;
    ngx_http_request_chain_loc_cnf_t *loc_cnf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_req_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->limit_log_level = NGX_CONF_UNSET_UINT;
    conf->status_code = NGX_CONF_UNSET_UINT;
    conf->dry_run = NGX_CONF_UNSET;
    //
    loc = &((ngx_str_t*)cf->args->elts)[0];
    if(ngx_strncmp(loc->data, "location", loc->len) == 0){
    	loc_cnf = &loc_cnfs.loc_cnf[loc_cnfs.total++];
    	uri = &((ngx_str_t*)cf->args->elts)[cf->args->nelts-1];
    	loc_cnf->hash_loc = ngx_str_2_hash(uri);
    	loc_cnf->cnf_addr = conf;
    }

    return conf;
}



static void
ngx_http_limit_req_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t          **p;
    ngx_http_limit_req_node_t   *lrn, *lrnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            lrn = (ngx_http_limit_req_node_t *) &node->color;
            lrnt = (ngx_http_limit_req_node_t *) &temp->color;

            p = (ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_http_request_chain_limit_req_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_limit_req_ctx_t  *octx = data;

    size_t                     len;
    ngx_http_limit_req_ctx_t  *ctx;

    ctx = shm_zone->data;

    if (octx) {
        if (ctx->key.value.len != octx->key.value.len
            || ngx_strncmp(ctx->key.value.data, octx->key.value.data,
                           ctx->key.value.len)
               != 0)
        {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                          "limit_req \"%V\" uses the \"%V\" key "
                          "while previously it used the \"%V\" key",
                          &shm_zone->shm.name, &ctx->key.value,
                          &octx->key.value);
            return NGX_ERROR;
        }

        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;

        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_limit_req_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_limit_req_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->queue);

    len = sizeof(" in limit_req zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in limit_req zone \"%V\"%Z",
                &shm_zone->shm.name);

    ctx->shpool->log_nomem = 0;

    return NGX_OK;
}


char *
ngx_http_request_chain_limit_zone(ngx_http_request_t *r,ngx_str_t *direct)
{
	ngx_int_t                    burst=1, delay=1 ;
	ngx_uint_t						hash, i;
    u_char                            *p;
    size_t                             len;
    ssize_t                            size;
    ngx_str_t                         name, s;
    ngx_int_t                          rate, scale;
    ngx_shm_zone_t                    *shm_zone;
    ngx_http_limit_req_ctx_t          *ctx;
    ngx_http_compile_complex_value_t   ccv;
    ngx_http_limit_req_conf_t			*lrcf = NULL;
    ngx_str_t   vv;
    u_char     *s_t;
    ngx_conf_t cf;
    ngx_http_limit_req_limit_t  *limit, *limits;

    ngx_memzero(&cf, sizeof(ngx_conf_t));
    cf.pool=r->pool;
    cf.log=r->connection->log;
    cf.cycle = (ngx_cycle_t*)ngx_cycle;
    cf.ctx = r->ctx;
    ((ngx_http_conf_ctx_t *)cf.ctx)->main_conf = r->main_conf ;

    s_t = ngx_str_sch_next_trimtoken(direct->data , direct->len , ',' , &vv);
    direct->len = direct->len - (s_t - direct->data) ;
    direct->data = s_t;

//    value = cf->args->elts;

    ctx = ngx_pcalloc(cf.pool, sizeof(ngx_http_limit_req_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    /*ngx_str_sch_next_trimtoken(direct->data , direct->len ,',',&vv);
    direct->len = direct->len - (s_t - direct->data) ;
    direct->data = s_t;*/

    ccv.cf = &cf;
    ccv.value = &vv;
    ccv.complex_value = &ctx->key;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    size = 0;
    rate = 1;
    scale = 1;
    name.len = 0;

    while( NGX_TRUE ) {
    	s_t = ngx_str_sch_next_trimtoken(direct->data , direct->len ,',',&vv);
    	if (vv.len == 0) {
    		break;
    	}
        direct->len = direct->len - (s_t - direct->data) ;
        direct->data = s_t;

        if (ngx_strncmp(vv.data, "zone=", 5) == 0) {

            name.data = vv.data + 5;

            p = (u_char *) ngx_strchr(name.data, ':');

            if (p == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, &cf, 0,
                                   "invalid zone size \"%V\"", &vv);
                return NGX_CONF_ERROR;
            }

            name.len = p - name.data;

            s.data = p + 1;
            s.len = vv.data + vv.len - s.data;

            size = ngx_parse_size(&s);

            if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, &cf, 0,
                                   "invalid zone size \"%V\"", &vv );
                return NGX_CONF_ERROR;
            }

            if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, &cf, 0,
                                   "zone \"%V\" is too small", &vv );
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(vv.data, "rate=", 5) == 0) {

            len = vv.len;
            p = vv.data + len - 3;

            if (ngx_strncmp(p, "r/s", 3) == 0) {
                scale = 1;
                len -= 3;

            } else if (ngx_strncmp(p, "r/m", 3) == 0) {
                scale = 60;
                len -= 3;
            }

            rate = ngx_atoi(vv.data + 5, len - 5);
            if (rate <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, &cf, 0,
                                   "invalid rate \"%V\"", &vv);
                return NGX_CONF_ERROR;
            }

            continue;
        }
        if (ngx_strncmp(vv.data, "burst=", 6) == 0) {

			burst = ngx_atoi(vv.data + 6, vv.len - 6);
			if (burst <= 0) {
				ngx_conf_log_error(NGX_LOG_EMERG, &cf, 0,
								   "invalid burst value \"%V\"", &vv);
				return NGX_CONF_ERROR;
			}

			continue;
		}

		if (ngx_strncmp(vv.data, "delay=", 6) == 0) {

			delay = ngx_atoi(vv.data + 6, vv.len - 6);
			if (delay <= 0) {
				ngx_conf_log_error(NGX_LOG_EMERG, &cf, 0,
								   "invalid delay value \"%V\"", &vv);
				return NGX_CONF_ERROR;
			}

			continue;
		}

		if (ngx_strncmp(vv.data, "location=", 9) == 0) {
			vv.data = vv.data + 9;
			vv.len -= 9;
			hash = ngx_str_2_hash(&vv);
			for(i=0 ; i < loc_cnfs.total ;i++) {
				if( loc_cnfs.loc_cnf[i].hash_loc == hash) {
					lrcf = (ngx_http_limit_req_conf_t*)loc_cnfs.loc_cnf[i].cnf_addr;
					break;
				}
			}

			continue;
		}

		if (ngx_strcmp(vv.data, "nodelay") == 0) {
			delay = NGX_MAX_INT_T_VALUE / 1000;
			continue;
		}


        ngx_conf_log_error(NGX_LOG_EMERG, &cf, 0,
                           "invalid parameter \"%V\"", &vv);
        return NGX_CONF_ERROR;
    }

    if(lrcf == NULL) {
        return NGX_CONF_ERROR;
    }

    if (name.len == 0) {
        return NGX_CONF_ERROR;
    }

    ctx->rate = rate * 1000 / scale;

    shm_zone = ngx_shared_memory_add(&cf, &name, size,
                                     &ngx_http_limit_req_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }
/*
    if (shm_zone->data) {
        ctx = shm_zone->data;
        return NGX_CONF_ERROR;
    }*/


    limits = lrcf->limits.elts;

    if (limits == NULL) {
        if (ngx_array_init(&lrcf->limits, cf.pool, 1,
                           sizeof(ngx_http_limit_req_limit_t))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 0; i < lrcf->limits.nelts; i++) {
        if (shm_zone == limits[i].shm_zone) {
            return "is duplicate";
        }
    }

    limit = ngx_array_push(&lrcf->limits);
    if (limit == NULL) {
        return NGX_CONF_ERROR;
    }

    limit->shm_zone = shm_zone;
    limit->burst = burst * 1000;
    limit->delay = delay * 1000;

    shm_zone->init = ngx_http_request_chain_limit_req_init_zone;
    shm_zone->data = ctx;


	if (shm_zone->init(shm_zone, NULL) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

    return NGX_CONF_OK;
}
