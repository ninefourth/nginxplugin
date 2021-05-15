#include "ngx_common_util.h"


ngx_uint_t ngx_str_find_chr_count(u_char *s ,size_t len , u_char c)
{
	ngx_uint_t sz = 0;
	while( len >0 ){
		sz = (s[--len] == c) ? sz+1 : sz ;
	}
	return sz;
}

u_char *ngx_str_sch_next_trimtoken(u_char *s , size_t len, u_char c , ngx_str_t *token)
{
	u_char *c_ret = 0;
	u_char sched = 0;
    ngx_uint_t count=0;
    token->len = 0;
    while(count<len){
        if (*s == ' '){
        	s++;
        	count++;
        	continue;
        }
        if(*s == c){
        	s++;
        	count++;
        	sched = 1;
        	continue;
        }
        if (sched){
        	c_ret = s;
        	break;
        }
        if(token->len == 0){
        	token->data = s;
        }
    	token->len++ ;
    	s++;
    	count++;
    }

    return c_ret;
}

//ngx_str_t to a hash code
ngx_uint_t ngx_chars_2_hash(u_char *s , size_t size)
{
    ngx_uint_t i;
    ngx_uint_t hash = 89;
    for (i = 0; i < size; i++) {
	    hash = (hash * 5051 + s[i]) % 987631;
	}
    return hash;
}

ngx_uint_t ngx_str_2_hash(ngx_str_t *s)
{
	return ngx_chars_2_hash(s->data,s->len);
}


void cpy_chars(u_char *des , u_char *sor , size_t size){
	for( ; size-- >0; des++ ,sor++) {
		*des = *sor;
	}
	*des='\0';
}

ngx_uint_t read_line(u_char *buf)
{
	ngx_uint_t size = 0;
	u_char *pbuf = buf;
	while( *pbuf != '\n' && *pbuf != '\0' ){
		pbuf++;
		size++;
	}
	return size;
}


ngx_int_t ngx_str_startwith(u_char *des , u_char *head , ngx_int_t len)
{
    while( len-- > 0 ){
    	if( *des++ != *head++){
    		return NGX_FALSE;
    	}
    }
    return NGX_TRUE;
}

char*
ngx_strcpy( ngx_pool_t *pool , ngx_str_t *str){
    char *s;
    s=ngx_palloc(pool,str->len+1);
    ngx_memcpy(s,str->data,str->len);
    s[str->len]='\0';
    str->len++;
    return s;
}

u_char*
ngx_strcat(u_char* des , u_char* src , size_t len) {
    ngx_memcpy(des, src, len);
    des += len;
    return des;
}


ngx_str_t *ngx_get_param_value(ngx_str_t *args , u_char *param , ngx_uint_t len , ngx_str_t *value)
{
	ngx_uint_t i,j , k=0;
	value->len=0;

	if(args && args->len > len ){
		for(i=0,j=0; i<args->len; i++){
			if( k==2 ){
				if( args->data[i] == '&'){
					break;
				}
                value->len++;
			}else if( k==1 || i==0 || args->data[i]=='&' ){
				if(args->data[i]=='&') i++;
				if(i >= args->len) break;
				if(j == len && args->data[i] == '='){
                    k=2;
//                    if(i < args->len-2){
                        value->data = &args->data[++i];
                        value->len = 1;
//                    }
                    continue;
				}
				if(args->data[i] == param[j++]){
					k=1;
					continue;
				}else{
					k=0;
					j=0;
				}
			}
		}
	}
	return value;
}


ngx_str_t *ngx_http_get_param_value(ngx_http_request_t *r , u_char *param , ngx_uint_t len , ngx_str_t *value)
{
	ngx_str_t *args = &r->args;
    return ngx_get_param_value(args,param,len,value);
}


ngx_str_t *ngx_http_get_variable_head(ngx_http_request_t *r, u_char *name , size_t len){
	size_t c ,i;
	ngx_table_elt_t *header;
	ngx_str_t s;
    header = r->headers_in.headers.part.elts;
    c = r->headers_in.headers.part.nelts;//get count of headers
    for(i=0 ;len>0 && i<c; i++) {
        s.data = header[i].lowcase_key;
        s.len = header[i].key.len;
        if ( s.len == len && ngx_strncmp( name, s.data, len ) == 0){
            return &header[i].value ;
        }
    }
    return NULL;
}

ngx_http_variable_value_t *ngx_http_get_variable_req(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    ngx_uint_t                 i;

	if (name->len == 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"[ngx_http_get_variable]: invalid variable name : %V",name);
		return NULL;
	}

	cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

	v = cmcf->variables.elts;

	if (v == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"[ngx_http_get_variable]: variables is NULL ");
		return NULL;

	} else {
		for (i = 0; i < cmcf->variables.nelts; i++) {
			if (name->len != v[i].name.len || ngx_strncasecmp(name->data, v[i].name.data, name->len) != 0)
			{
				continue;
			}
			if (v[i].get_handler && v[i].get_handler(r, &r->variables[i], v[i].data) == NGX_OK) {

				if (v[i].flags & NGX_HTTP_VAR_NOCACHEABLE) {
					r->variables[i].no_cacheable = 1;
				}

				return &r->variables[i];
			}
		}
	}

    return NULL;
}


ngx_str_t *ngx_http_get_post_param(ngx_http_request_t *r, u_char *name , size_t len ,ngx_str_t *value)
{
	ngx_str_t args;

	if(r->header_in){
		args.data = r->header_in->pos;
		args.len = r->header_in->last - r->header_in->pos;
		ngx_get_param_value(&args,name,len,value);
		return value;
	}
    return NULL;
}
