#ifndef _NGX_HTTP_UPSTREAM_CHECK_MODELE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_CHECK_MODELE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define default_region 1;

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

ngx_int_t ngx_http_upstream_check_add_variable(ngx_conf_t *cf ,ngx_str_t * var_name);
void ngx_preload_var_conf(ngx_str_t *var_name , ngx_str_t *conf);

void ngx_http_add_address_rule(ngx_http_request_t *r ,ngx_str_t *address , ngx_uint_t deny);
ngx_str_t *ngx_http_deny_list(ngx_pool_t *pool);

void ngx_reload_region_conf(ngx_str_t *f , ngx_uint_t up_name_hash);
ngx_uint_t ngx_http_upstream_get_peer_region(void *p);

ngx_uint_t ngx_http_upstream_request_region(ngx_http_request_t *r);
ngx_int_t ngx_http_upstream_get_region_total_weight(void *fstp , ngx_uint_t region);
void ngx_reload_router(ngx_pool_t *pool,ngx_str_t *name , ngx_str_t *cnf);
void ngx_add_router_item(ngx_pool_t *pool ,ngx_str_t *router_name , ngx_uint_t idx, ngx_str_t *key ,ngx_uint_t region);
//void ngx_remove_router_item(ngx_pool_t *pool ,ngx_str_t *router_name , ngx_uint_t idx ,ngx_str_t *key);
void ngx_set_router_variable(ngx_pool_t *pool ,ngx_str_t *router_name , ngx_str_t *var);
ngx_int_t ngx_get_router_variable_region(ngx_str_t *router_name , ngx_str_t *var);
ngx_uint_t ngx_router_key_get_region(ngx_str_t *router_name , ngx_str_t *desc);
ngx_buf_t *ngx_list_router_var(ngx_pool_t *pool, ngx_str_t *router_name );

#endif //_NGX_HTTP_UPSTREAM_CHECK_MODELE_H_INCLUDED_

