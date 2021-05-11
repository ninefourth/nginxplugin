#ifndef _NGX_HTTP_UPSTREAM_CHECK_MODELE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_CHECK_MODELE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef volatile ngx_atomic_int_t  ngx_atomic_i_t;

ngx_uint_t ngx_http_upstream_check_add_peer(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us, ngx_http_upstream_rr_peer_t *peer_mem_addr);

ngx_uint_t ngx_http_upstream_check_peer_down(void *p);

void ngx_http_upstream_check_get_peer(void *p);
void ngx_http_upstream_check_free_peer(void *p);
ngx_uint_t ngx_http_upstream_check_peer_force_down(void *p);
void ngx_http_upstream_check_force_down_peer(void *p, ngx_uint_t dw);

ngx_uint_t ngx_http_upstream_get_peer_weight(void *p);
void ngx_http_upstream_check_set_peer_weight(void *fstp,void *p, ngx_uint_t w);
ngx_int_t ngx_http_upstream_get_v_total_weight(void *fstp);

void ngx_reload_var_conf(ngx_str_t *f,ngx_str_t *var_name);
ngx_buf_t *ngx_list_var(ngx_pool_t *pool,ngx_str_t *var_name);

ngx_str_t *ngx_http_get_variable_head(ngx_http_request_t *r, u_char *name , size_t len);
ngx_http_variable_value_t *ngx_http_get_variable_req(ngx_http_request_t *r, ngx_str_t *name);
ngx_int_t ngx_str_startwith(u_char *des , u_char *head , ngx_int_t len);

ngx_int_t ngx_http_upstream_check_add_variable(ngx_conf_t *cf ,ngx_str_t * var_name);
void ngx_preload_var_conf(ngx_str_t *var_name , ngx_str_t *conf);

ngx_str_t *ngx_http_get_param_value(ngx_http_request_t *r , u_char *param , ngx_uint_t len , ngx_str_t *value);

//ngx_uint_t ngx_is_test(ngx_str_t)
#define NGX_TRUE                  1
#define NGX_FALSE                 0


#endif //_NGX_HTTP_UPSTREAM_CHECK_MODELE_H_INCLUDED_

