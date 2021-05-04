
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_HTTP_UPSTREAM_XFDF_IP_HASH)
#include "ngx_http_upstream_xfdf_ip_hash_module.h"
#endif

#if (NGX_HTTP_UPSTREAM_CHECK)
#include "ngx_http_upstream_check_module.h"
#endif


static char *ngx_http_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
//static void *ngx_http_endpoint_create_srv_conf(ngx_conf_t *cf);


//模块指令
static ngx_command_t  ngx_http_endpoint_commands[] = {

    { ngx_string("endpoint"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_endpoint,
      0,
      0,
      NULL },

      ngx_null_command
};

//模块环境参数
static ngx_http_module_t  ngx_http_endpoint_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

//模块入口
ngx_module_t  ngx_http_endpoint_module = {
    NGX_MODULE_V1,
    &ngx_http_endpoint_module_ctx, /* module context */
    ngx_http_endpoint_commands,    /* module directives */
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


static ngx_str_t sucs = ngx_string("success");

ngx_array_t *
ngx_http_endpoint_parse_path(ngx_pool_t *pool, ngx_str_t *path)
{
    u_char       *p, *last, *end;
    ngx_str_t    *str;
    ngx_array_t  *array;

    array = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    if (array == NULL) {
        return NULL;
    }

    p = path->data + 1;
    last = path->data + path->len;

    while(p < last) {
        end = ngx_strlchr(p, last, '/');
        str = ngx_array_push(array);

        if (str == NULL) {
            return NULL;
        }

        if (end) {
            str->data = p;
            str->len = end - p;

        } else {
            str->data = p;
            str->len = last - p;

        }

        p += str->len + 1;
    }

#if (NGX_DEBUG)
    ngx_str_t  *arg;
    ngx_uint_t  i;

    arg = array->elts;
    for (i = 0; i < array->nelts; i++) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0,
                       "[dyups] res[%i]:%V", i, &arg[i]);
    }
#endif

    return array;
}


static void
ngx_http_get_param_value(ngx_http_request_t *r , u_char *param , ngx_uint_t len , ngx_str_t *value)
{
	ngx_uint_t i,j , k=0;
	ngx_str_t *args = &r->args;

	value->len=0;

	if(args && args->len > len ){
		for(i=0,j=0; i<args->len; i++){
			if( k==2 ){
				if( args->data[i] == '&'){
					break;
				}
                value->len++;
			}else if( k==1 || i==0 || args->data[i]=='&' ){
				if(args->data[i]=='&') i++;
				if(i >= args->len) break;
				if(j == len && args->data[i] == '='){
                    k=2;
                    if(i < args->len-2){
                        value->data = &args->data[++i];
                        value->len = 1;
                    }
                    continue;
				}
				if(args->data[i] == param[j++]){
					k=1;
					continue;
				}else{
					k=0;
					j=0;
				}
			}
		}
	}
}


static ngx_int_t
ngx_http_endpoint_do_get(ngx_http_request_t *r, ngx_array_t *resource)
{
    ngx_int_t                  rc,status;
    ngx_buf_t                  *buf;
    ngx_chain_t                out;
    ngx_str_t                  *con;
    ngx_str_t                  *value;
    ngx_int_t                  g=0,t=0;
    ngx_str_t                  arg_cf=ngx_string("conf");

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    con = NULL;
    buf = NULL;

    if (resource->nelts == 0) {
        return NGX_HTTP_NOT_FOUND;
    }

    value = resource->elts;

    if (value[0].len == 4 && ngx_strncasecmp(value[0].data, (u_char *)"list", 4) == 0) {
        con = ngx_xfdf_list_upstreams();
        if (con != NULL) {
            buf = ngx_create_temp_buf(r->pool, con->len);
            if (buf != NULL) {
                buf->last = ngx_sprintf(buf->last, "%V\n", con);
            }
        }
    } else if(value[0].len == 4 && ngx_strncasecmp(value[0].data, (u_char *)"down", 4) == 0) {
        if( resource->nelts == 3  ){
            ngx_str_t *up = &value[1]; //upstream
            ngx_str_t *sr = &value[2]; //server
            ngx_xfdf_deal_server(up,sr,1);
            buf = ngx_create_temp_buf(r->pool, sucs.len);
            if (buf != NULL) {
                buf->last = ngx_sprintf(buf->last, "%V\n", &sucs );
            }
        }
        if( resource->nelts == 4  ) {
            ngx_str_t *up = &value[1]; //upstream
            ngx_str_t *sr = &value[2]; //server
            if(ngx_strncasecmp(value[3].data, (u_char *)"log", 3) == 0) {
                ngx_xfdf_deal_server(up,sr,2);
                buf = ngx_create_temp_buf(r->pool, sucs.len);
                if (buf != NULL) {
                    buf->last = ngx_sprintf(buf->last, "%V\n", &sucs );
                }
            }
        }
    } else if(value[0].len == 2 && ngx_strncasecmp(value[0].data, (u_char *)"up", 2) == 0) {
        if( resource->nelts == 3  ){
            ngx_str_t *up = &value[1]; //upstream
            ngx_str_t *sr = &value[2]; //server
            ngx_xfdf_deal_server(up,sr,0);
            buf = ngx_create_temp_buf(r->pool, sucs.len);
            if (buf != NULL) {
                buf->last = ngx_sprintf(buf->last, "%V\n", &sucs);
            }
        }
    } else if(value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"weight", 6) == 0) {
        if( resource->nelts == 4  ){
            ngx_str_t *up = &value[1]; //upstream
            ngx_str_t *sr = &value[2]; //server
            ngx_str_t *wt = &value[3]; //weight
            ngx_uint_t w = ngx_atoi(wt->data, wt->len);
            ngx_xfdf_deal_peer_weight(up,sr,w);
            buf = ngx_create_temp_buf(r->pool, sucs.len);
            if (buf != NULL) {
                buf->last = ngx_sprintf(buf->last, "%V\n", &sucs);
            }
        }
    } else if (value[0].len == 7 && (t=(ngx_strncasecmp(value[0].data, (u_char *)"fortest", 7) == 0) ||
    		(g=ngx_strncasecmp(value[0].data, (u_char *)"forgray", 7) == 0) )) {
    	ngx_str_t f;
        ngx_http_get_param_value(r,arg_cf.data , arg_cf.len , &f);
    	if(f.len >0 ){
//			ngx_str_t *f = &value[1]; //test configure file
//			ngx_str_t f = ngx_string("conf/test.conf");
//    		f.data = (u_char*)"conf/test.conf";
//    		f.len = 14;
			//
			if(t) status = FORTEST;
			if(g) status = FORGRAY;
			f.data = (u_char*)ngx_strcpy(r->pool,&f);
			ngx_reload_var_conf(&f,status);
			buf = ngx_create_temp_buf(r->pool, sucs.len);
			if (buf != NULL) {
				buf->last = ngx_sprintf(buf->last, "%V\n", &sucs );
			}
		}
    } else if (value[0].len == 8 && (t=(ngx_strncasecmp(value[0].data, (u_char *)"listtest", 8) == 0) ||
    		(g=ngx_strncasecmp(value[0].data, (u_char *)"listgray", 8) == 0) )) {
    	if(t) status = FORTEST;
    	if(g) status = FORGRAY;
    	buf = ngx_list_var(r->pool,status);
    }


    if( buf !=NULL && ngx_buf_size(buf) == 0) {
        status = NGX_HTTP_NO_CONTENT;
    } else {
        status = buf ? NGX_HTTP_OK : NGX_HTTP_NOT_FOUND;
    }

    r->headers_out.status = status;

    if (status != NGX_HTTP_OK) {
        r->headers_out.content_length_n = 0;
    } else {
        r->headers_out.content_length_n = ngx_buf_size(buf);
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    if (status != NGX_HTTP_OK) {
        return ngx_http_send_special(r, NGX_HTTP_FLUSH);
    }

    buf->last_buf = 1;
    out.buf = buf;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}




static ngx_int_t
ngx_http_endpoint_handler(ngx_http_request_t *r)
{
    ngx_array_t  *res;

    res = ngx_http_endpoint_parse_path(r->pool, &r->uri);

    return ngx_http_endpoint_do_get(r, res);
}

static char *
ngx_http_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_endpoint_handler;

    return NGX_CONF_OK;
}

/*
static void *
ngx_http_endpoint_create_srv_conf(ngx_conf_t *cf)
{
    return NULL;
}*/
