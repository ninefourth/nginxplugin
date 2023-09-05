#ifndef _NGX_HTTP_UPSTREAM_XFDF_IP_HASH_MODELE_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_XFDF_IP_HASH_MODELE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_http_upstream_xfdf_peer_s   ngx_http_upstream_xfdf_peer_t;

struct ngx_http_upstream_xfdf_peer_s{
    ngx_http_upstream_rr_peer_t*      peer;
    ngx_str_t                      name;
    ngx_http_upstream_xfdf_peer_t	 *prev;
    ngx_http_upstream_xfdf_peer_t	 *next;
    ngx_uint_t						 index;
    ngx_int_t						 es; //是否是弹性创建的
};

typedef struct  {
	ngx_atomic_t					lock;
    ngx_http_upstream_xfdf_peer_t     *peers;
    ngx_str_t                         *name;
    size_t                            num;
    ngx_http_upstream_rr_peers_t		*rr_peers;
    ngx_http_upstream_srv_conf_t		*us;
} ngx_http_upstream_xfdf_up_t ;

typedef struct {
    ngx_array_t      				*upstreams ; //ngx_http_upstream_xfdf_up_t
    ngx_http_upstream_xfdf_peer_t	*peers; //peer池
    size_t						maxsize; //池的最大数
    ngx_uint_t						freepos; //池中可能的最小空闲位置
    ngx_pool_t       				*pool;
} ngx_http_upstream_xfdf_ups_t ;

ngx_str_t* ngx_xfdf_list_upstreams();
void ngx_xfdf_deal_server(ngx_str_t *up , ngx_str_t *sr ,ngx_int_t dw);
void ngx_xfdf_deal_peer_weight(ngx_str_t *up , ngx_str_t *sr ,ngx_int_t w);
ngx_http_variable_t* ngx_http_get_variable_by_name(ngx_conf_t *cf, ngx_str_t *name);
void ngx_xfdf_down_peer(ngx_str_t *up , ngx_str_t *sr);

ngx_http_upstream_rr_peer_t *ngx_xfdf_add_upstream_peer(ngx_str_t *up, ngx_str_t* sr, ngx_int_t w);
ngx_http_upstream_srv_conf_t* ngx_xfdf_get_upstream_srv_conf(ngx_str_t *up);
ngx_http_upstream_rr_peer_t* ngx_xfdf_remove_upstream_peer(ngx_str_t *up, ngx_str_t* sr);
void ngx_http_upstream_append_peer(ngx_str_t *up, ngx_http_upstream_rr_peer_t *peer);
void ngx_http_upstream_remove_peer(ngx_str_t *up, ngx_http_upstream_rr_peer_t *peer);
void ngx_http_upstream_release_rr_peer(ngx_http_upstream_rr_peer_t *peer);
ngx_int_t ngx_xfdf_upstream_peer_is_es(ngx_str_t *up, ngx_str_t* sr);

void* ngx_xfdf_deal_server_get_peer(ngx_http_upstream_rr_peer_t **fstp ,ngx_str_t *up , ngx_str_t *sr);
#endif //_NGX_HTTP_UPSTREAM_XFDF_IP_HASH_MODELE_H_INCLUDED_
