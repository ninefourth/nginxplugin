#ifndef _NGX_HTTP_REQUEST_LOG_MODULE_H_INCLUDED_
#define _NGX_HTTP_REQUEST_LOG_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

void ngx_http_request_log_print(ngx_str_t *f,ngx_http_request_t *r);
void ngx_http_request_log_disable();
void ngx_http_request_log_enable();

void ngx_http_request_log_write_server(ngx_int_t rid, u_char *nm, size_t len);


#endif