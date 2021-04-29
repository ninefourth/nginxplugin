#ifndef _NGX_HTTP_UPSTREAM_XFDF_IP_HASH_MODELE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_XFDF_IP_HASH_MODELE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_upstream_rr_peer_t*      peer;
    ngx_str_t                         name;
} ngx_http_upstream_xfdf_peer_t;

typedef struct  {
    ngx_http_upstream_xfdf_peer_t     *peers;
    ngx_str_t                         *name;
    size_t                            num;
} ngx_http_upstream_xfdf_up_t ;

typedef struct {
    ngx_array_t      *upstreams ; //ngx_http_upstream_xfdf_up_t
    ngx_pool_t       *pool;
} ngx_http_upstream_xfdf_ups_t ;

ngx_str_t* ngx_xfdf_list_upstreams();
void ngx_xfdf_deal_server(ngx_str_t *up , ngx_str_t *sr ,ngx_int_t dw);
void ngx_xfdf_deal_peer_weight(ngx_str_t *up , ngx_str_t *sr ,ngx_int_t w);
//ngx_http_variable_t* ngx_http_get_variable_by_name(ngx_conf_t *cf, ngx_str_t *name);
//char* ngx_strcpy( ngx_pool_t *pool , ngx_str_t *str);

#endif //_NGX_HTTP_UPSTREAM_XFDF_IP_HASH_MODELE_H_INCLUDED_
