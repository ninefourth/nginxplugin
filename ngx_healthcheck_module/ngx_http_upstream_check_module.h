#ifndef _NGX_HTTP_UPSTREAM_CHECK_MODELE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_CHECK_MODELE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_uint_t ngx_http_upstream_check_add_peer(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us, ngx_http_upstream_rr_peer_t *peer_mem_addr);

ngx_uint_t ngx_http_upstream_check_peer_down(void *p);

void ngx_http_upstream_check_get_peer(void *p);
void ngx_http_upstream_check_free_peer(void *p);
ngx_uint_t ngx_http_upstream_check_peer_force_down(void *p);
void ngx_http_upstream_check_force_down_peer(void *p, ngx_uint_t dw);


#endif //_NGX_HTTP_UPSTREAM_CHECK_MODELE_H_INCLUDED_

