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

#endif //_NGX_HTTP_UPSTREAM_CHECK_MODELE_H_INCLUDED_

