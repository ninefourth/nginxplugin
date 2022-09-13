
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "../ngx_common/ngx_common_util.h"

#if (NGX_HTTP_UPSTREAM_XFDF_IP_HASH)
#include "ngx_http_upstream_xfdf_ip_hash_module.h"
#endif

#if (NGX_HTTP_UPSTREAM_CHECK)
#include "ngx_http_upstream_check_module.h"
#endif

#if(NGX_HTTP_REQUEST_CHAIN)
#include "ngx_http_request_chain_module.h"
#endif


static char *ngx_http_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_var_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
//static void *ngx_http_endpoint_create_srv_conf(ngx_conf_t *cf);


//模块指令
static ngx_command_t  ngx_http_endpoint_commands[] = {

    { ngx_string("endpoint"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_endpoint,
      0,
      0,
      NULL },
	{ ngx_string("var_conf"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
	  ngx_http_var_conf,
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

static size_t
ngx_http_out_content( ngx_pool_t *pool, ngx_str_t *val, ngx_chain_t *out, ngx_uint_t tail )
{
	ngx_buf_t					*buf;
	ngx_chain_t				*out_native;
	ngx_str_t					val_native;
	size_t					len=0;
	if(val->len > pool->max) {
		out_native = ngx_palloc(pool, sizeof(ngx_chain_t));
		val_native.data = val->data;
		val_native.len = pool->max;
		buf = append_printf(pool, &val_native,0);
		len = ngx_buf_size(buf);
		out->buf = buf;
		out->next = out_native;
		val_native.data = val->data+pool->max;
		val_native.len = val->len - pool->max;
		len+=ngx_http_out_content(pool, &val_native ,out_native,tail);
	}else{
		buf = append_printf(pool, val, (tail == 1) );
		len = ngx_buf_size(buf);
		out->buf = buf;
		if(tail == 1) {
			buf->last_buf = 1;
			out->next = NULL;
		}
	}
	return len;
}

static void
ngx_append(ngx_chain_t *p , ngx_chain_t *c)
{
	if(p->next == NULL) {
		p->next = c;
	}else{
		ngx_append(p->next,c);
	}
}

static ngx_int_t
ngx_http_endpoint_do_get(ngx_http_request_t *r, ngx_array_t *resource)
{
    ngx_int_t                  rc,status;
    ngx_chain_t                out;
    ngx_str_t                  *con;
    ngx_str_t                  *value,val_tmp;
    ngx_str_t                  arg_cf=ngx_string("conf") , ip = ngx_string("ip"), tab = ngx_string("\t");
	u_char 					*s_t;
	size_t					buf_sz = 0;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    con = NULL;
    out.next = NULL;
    if (resource->nelts == 0) {
        return NGX_HTTP_NOT_FOUND;
    }

    value = resource->elts;

    if (value[0].len == 4 && ngx_strncasecmp(value[0].data, (u_char *)"list", 4) == 0) {
        con = ngx_xfdf_list_upstreams();
//        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "-- %l ---%V----",con->len, con);
        if (con != NULL && con->len >0 ) {
        	buf_sz = ngx_http_out_content(r->pool,con,&out,1);
        }
    } else if(value[0].len == 4 && ngx_strncasecmp(value[0].data, (u_char *)"down", 4) == 0) {
    	rc = -1;
    	ngx_str_t *up,*sr;
        if( resource->nelts == 3  ){
            up = &value[1]; //upstream
            sr = &value[2]; //server
            rc = 1;
        }
        if( resource->nelts == 4  ) {
            up = &value[1]; //upstream
            sr = &value[2]; //server
            if(ngx_strncasecmp(value[3].data, (u_char *)"log", 3) == 0) {
                rc = 2;
            }
        }
        if(rc > 0) {
        	s_t = sr->data;
            while(s_t){
            	s_t = ngx_str_sch_next_trimtoken(sr->data ,sr->len ,',',&val_tmp);
				ngx_xfdf_deal_server(up,&val_tmp,rc);
				if(s_t != NULL){
					sr->len = sr->len - (s_t - sr->data);
					sr->data = s_t;
				}
            }
//            ngx_xfdf_deal_server(up,sr,1);
            buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        }
    } else if(value[0].len == 2 && ngx_strncasecmp(value[0].data, (u_char *)"up", 2) == 0) {
        if( resource->nelts == 3  ){
            ngx_str_t *up = &value[1]; //upstream
            ngx_str_t *sr = &value[2]; //server
            s_t = sr->data;
			while(s_t){
				s_t = ngx_str_sch_next_trimtoken(sr->data ,sr->len ,',',&val_tmp);
				ngx_xfdf_deal_server(up,&val_tmp,0);
				if(s_t != NULL){
					sr->len = sr->len - (s_t - sr->data);
					sr->data = s_t;
				}
			}
            //
            buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        }
    } else if(value[0].len == 7 && ngx_strncasecmp(value[0].data, (u_char *)"nocheck", 7) == 0) {
        if( resource->nelts == 3  ){
            ngx_str_t *up = &value[1]; //upstream
            ngx_str_t *sr = &value[2]; //server
            s_t = sr->data;
			while(s_t){
				s_t = ngx_str_sch_next_trimtoken(sr->data ,sr->len ,',',&val_tmp);
				ngx_xfdf_deal_server(up,&val_tmp,3);
				if(s_t != NULL){
					sr->len = sr->len - (s_t - sr->data);
					sr->data = s_t;
				}
			}
            //
			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        }
    } else if(value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"weight", 6) == 0) {
        if( resource->nelts == 4  ){
            ngx_str_t *up = &value[1]; //upstream
            ngx_str_t *sr = &value[2]; //server
            ngx_str_t *wt = &value[3]; //weight
            ngx_uint_t w = ngx_atoi(wt->data, wt->len);
            ngx_xfdf_deal_peer_weight(up,sr,w);
            buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        }
    } else if (value[0].len == 9 && ngx_strncasecmp(value[0].data, (u_char *)"variables", 9) == 0 ) {
    	if( resource->nelts == 2 ){
    		ngx_str_t *varname = &value[1]; //variable name
        	ngx_str_t f;
            ngx_http_get_param_value(r,arg_cf.data , arg_cf.len , &f);
        	if(f.len >0 ){
    			f.data = (u_char*)ngx_strcpy(r->pool,&f);
    			ngx_reload_var_conf(&f,varname);
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
			}
    	}else if( resource->nelts == 3 &&  value[2].len == 4 && ngx_strncasecmp(value[2].data, (u_char *)"list", 4) == 0){
			ngx_str_t *varname = &value[1]; //variable name
			out.buf = ngx_list_var(r->pool,varname);
			out.buf->last_buf = 1;
			out.next = NULL;
			buf_sz = ngx_buf_size(out.buf);
    	}
	} else if (value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"region", 6) == 0 ) {
    	if( resource->nelts == 2 ){
    		ngx_str_t *upstream = &value[1]; //upstream name
        	ngx_str_t f;
            ngx_http_get_param_value(r,arg_cf.data , arg_cf.len , &f);
        	if(f.len >0 ){
    			f.data = (u_char*)ngx_strcpy(r->pool,&f);
    			ngx_reload_region_conf(&f,ngx_str_2_hash(upstream));
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        	}
    	}
    } else if (value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"router", 6) == 0 ) {
    	if( resource->nelts == 2 ){
    		ngx_str_t *router_name = &value[1]; //router name
        	ngx_str_t f;
            ngx_http_get_param_value(r,arg_cf.data , arg_cf.len , &f);
        	if(f.len >0 ){
    			f.data = (u_char*)ngx_strcpy(r->pool,&f);
    			ngx_reload_router(r->pool,router_name ,&f);
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        	}
    	} else if( resource->nelts == 4 ){// /router/[name]/[add|exist|get]/[variable]
    		ngx_str_t *router_name = &value[1]; //router name
    		if( value[2].len == 9 && ngx_strncasecmp(value[2].data, (u_char *)"variables", 9) == 0
    			&& value[3].len == 4 && ngx_strncasecmp(value[3].data, (u_char *)"list", 4) == 0 ){// /router/[name]/variables/list
    			buf_sz = ngx_http_out_content(r->pool,router_name,&out,1);
    		} else if( value[2].len == 3 && ngx_strncasecmp(value[2].data, (u_char *)"add", 3) == 0){
    			ngx_str_t *v = &value[3];
    			ngx_set_router_variable(r->pool ,router_name,v);
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
    		} else if( value[2].len == 5 && ngx_strncasecmp(value[2].data, (u_char *)"exist", 5) == 0){
    			ngx_str_t *v = &value[3];
    			char rn[4];
    			rc = ngx_get_router_variable_region(router_name,v);
    			sprintf(rn,"%ld",rc);
    			val_tmp.data = (u_char*)rn;
    			val_tmp.len = strlen(rn);
    			buf_sz = ngx_http_out_content(r->pool,&val_tmp,&out,1);
    		} else if( value[2].len == 3 && ngx_strncasecmp(value[2].data, (u_char *)"get", 3) == 0){
    			ngx_chain_t out_1,out_2;
    			ngx_str_t *v = &value[3];
    			ngx_str_t v_tmp;
    			out_1.next = NULL;
    			out_2.next = NULL;
    			v_tmp.len = 0;
				char rn[4];
				rc = ngx_router_key_get_region(router_name,v,&v_tmp);
				sprintf(rn,"%ld",rc);
				val_tmp.data = (u_char*)rn;
				val_tmp.len = strlen(rn);
				buf_sz = ngx_http_out_content(r->pool,&val_tmp,&out,0);
				ngx_append(&out,&out_1);
				buf_sz += ngx_http_out_content(r->pool,&tab,&out_1,0);
				ngx_append(&out_1,&out_2);
				buf_sz += ngx_http_out_content(r->pool,&v_tmp,&out_2,1);
    		}
    	}/*else if( resource->nelts == 5 ){// /router/[name]/index/remove/[key]
    		ngx_str_t *router_name = &value[1]; //router name
    		if( value[3].len == 6 && ngx_strncasecmp(value[3].data, (u_char *)"remove", 6) == 0){
    			ngx_str_t *idxt = &value[2]; //variable index
    			ngx_uint_t idx = ngx_atoi(idxt->data, idxt->len);
    			ngx_str_t *k = &value[4];
    			ngx_add_router_item(r->pool ,router_name,idx,k);
    			buf = append_printf(r->pool, &sucs);
    		}
    	}*/else if( resource->nelts == 6 ){// /router/[name]/index/add/[key]/[value]
    		ngx_str_t *router_name = &value[1]; //router name
    		if( value[3].len == 3 && ngx_strncasecmp(value[3].data, (u_char *)"add", 3) == 0){
    			ngx_str_t *idxt = &value[2]; //variable index
    			ngx_uint_t idx = ngx_atoi(idxt->data, idxt->len);
    			ngx_str_t *k = &value[4];
    			ngx_str_t *v = &value[5];
    			ngx_add_router_item(r->pool ,router_name,idx,k,ngx_atoi(v->data, v->len));
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
    		}
    	}
    } else if (value[0].len == 7 && ngx_strncasecmp(value[0].data, (u_char *)"address", 7) == 0 ) {
    	if( resource->nelts == 2  ){
    	    ngx_str_t address;
			ngx_http_get_param_value(r,ip.data , ip.len , &address);
			if(address.len > 0){
				ngx_str_t *opt = &value[1];//deny or allow
				if (ngx_strncasecmp(opt->data, (u_char *)"deny", 4) == 0){
					ngx_http_add_address_rule(r,&address,1);
				} else if (ngx_strncasecmp(opt->data, (u_char *)"allow", 5) == 0){
					ngx_http_add_address_rule(r,&address,0);
				}
				buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
			}
    	} else if( resource->nelts == 3  ){
    		if (ngx_strncasecmp(value[1].data, (u_char *)"deny", 4) == 0){
				if (ngx_strncasecmp(value[2].data, (u_char *)"list", 4) == 0){
					con = ngx_http_deny_list(r->pool);
					if (con != NULL) {
						buf_sz = ngx_http_out_content(r->pool,con,&out,1);
					}
				}
    		}
    	}
    } else if(value[0].len == 5 && ngx_strncasecmp(value[0].data, (u_char *)"limit", 5) == 0) {
		#ifdef NGX_HTTP_REQUEST_CHAIN
    	    ngx_str_t s=ngx_string("$proxy_add_x_forwarded_for , zone=bus_r:1m , rate=2r/s ,burst=1,location=/store/");
    		ngx_http_request_chain_limit_zone(r,&s);
		#endif
//		buf = append_printf(r->pool, &sucs);
    	buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
    }


//    if( buf !=NULL && ngx_buf_size(buf) == 0) {
    if( buf_sz == 0 ) {
        status = NGX_HTTP_NO_CONTENT;
    } else {
    	status = NGX_HTTP_OK;
//        status = buf ? NGX_HTTP_OK : NGX_HTTP_NOT_FOUND;
    }

    r->headers_out.status = status;

    if (status != NGX_HTTP_OK) {
        r->headers_out.content_length_n = 0;
    } else {
//        r->headers_out.content_length_n = ngx_buf_size(buf);
        r->headers_out.content_length_n = buf_sz;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    if (status != NGX_HTTP_OK) {
        return ngx_http_send_special(r, NGX_HTTP_FLUSH);
    }

//    buf->last_buf = (out.next == NULL);
//    out.buf = buf;
//    out.next = NULL;

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

static char *
ngx_http_var_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    #if (NGX_HTTP_UPSTREAM_CHECK)
    if(cf->args->nelts > 1){
    	ngx_uint_t i ,j;
        ngx_str_t *value = cf->args->elts ,*val ,v_n,v_cf;
    	for(i=1; i<cf->args->nelts; ){
    		val = &value[i];
    		for(j=1;j < val->len-1 ;j++){
    			//has a configure file
    			if(val->data[j] == '='){
    				v_n.data=val->data;
    				v_n.len=j;
    				v_cf.data=&val->data[j+1];
    				v_cf.len=val->len-j-1;
    				v_cf.data = (u_char*)ngx_strcpy(cf->pool,&v_cf);
    				ngx_http_upstream_check_add_variable(cf,&v_n);
    				ngx_preload_var_conf(&v_n,&v_cf);
    				goto next;
    			}
    		}
    		//if has no configure file
    		ngx_http_upstream_check_add_variable(cf,val);
    		next:
				++i;
    	}
    }
    #endif

    return NGX_CONF_OK;
}

/*
static void *
ngx_http_endpoint_create_srv_conf(ngx_conf_t *cf)
{
    return NULL;
}*/
