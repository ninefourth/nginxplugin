#ifndef _NGX_HTTP_ENDPOINT_MODELE_H_INCLUDED_
#define _NGX_HTTP_ENDPOINT_MODELE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

//static void update_dyn_up_srv_dw(ngx_str_t *up, ngx_str_t *sr, ngx_int_t a);
//static void update_dyn_up_srv_fdw(ngx_str_t *up, ngx_str_t *sr, ngx_int_t a);

ngx_int_t is_debug_log();

#define ngx_log_debug_process(level, log, ...)                                        \
    if (is_debug_log() == 1) ngx_log_error(level, log, __VA_ARGS__)

#endif
