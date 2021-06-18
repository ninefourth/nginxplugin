#ifndef _NGX_HTTP_REQUEST_CHAIN_MODELE_H_INCLUDED_
#define _NGX_HTTP_REQUEST_CHAIN_MODELE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

char * ngx_http_request_chain_limit_zone(ngx_http_request_t *r ,ngx_str_t *direct);

#endif
