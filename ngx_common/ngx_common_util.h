#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_TRUE                  1
#define NGX_FALSE                 0

/*string function*/
ngx_uint_t ngx_chars_2_hash(u_char *s , size_t size);
ngx_uint_t ngx_str_2_hash(ngx_str_t *s);
void cpy_chars(u_char *des , u_char *sor , size_t size);
char *ngx_strcpy( ngx_pool_t *pool , ngx_str_t *str);
u_char *ngx_strcat(u_char* des , u_char* src , size_t len);
ngx_uint_t read_line(u_char *buf);
ngx_int_t ngx_str_startwith(u_char *des , u_char *head , ngx_int_t len);
ngx_uint_t ngx_str_find_chr_count(u_char *s ,size_t len , u_char c);
u_char *ngx_str_sch_next_trimtoken(u_char *s , size_t len, u_char c , ngx_str_t *token);

/*http request function*/
//get http url parameter
ngx_str_t *ngx_http_get_param_value(ngx_http_request_t *r , u_char *param , ngx_uint_t len , ngx_str_t *value);
//get http header
ngx_str_t *ngx_http_get_variable_head(ngx_http_request_t *r, u_char *name , size_t len);
//get http variable object by name
ngx_http_variable_value_t *ngx_http_get_variable_req(ngx_http_request_t *r, ngx_str_t *name);
ngx_str_t *ngx_http_get_post_param(ngx_http_request_t *r, u_char *name , size_t len ,ngx_str_t *value);
ngx_str_t *ngx_get_param_value(ngx_str_t *args , u_char *param , ngx_uint_t len , ngx_str_t *value);

//net
ngx_str_t *ngx_inet_ntoa(ngx_uint_t naddr , ngx_str_t *saddr);

//math
ngx_int_t ngx_math_log2(ngx_int_t x);
