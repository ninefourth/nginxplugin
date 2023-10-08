#include "ngx_common_util.h"
#include <ngx_channel.h>

static ngx_str_t http_head=ngx_string("http_");
static ngx_str_t http_param=ngx_string("arg_");
static ngx_str_t http_uri=ngx_string("uri");
static ngx_str_t http_body_param=ngx_string("body_");
static ngx_str_t http_body=ngx_string("body");
static ngx_str_t http_arg=ngx_string("arg");

ngx_pool_t *ngx_global_pool = NULL;
extern ngx_uint_t  ngx_pagesize;
extern ngx_uint_t  ngx_pagesize_shift;

ngx_uint_t ngx_str_find_element_count(u_char *s ,size_t len , u_char c)
{
	ngx_uint_t i = 0 ,p1 = 0, p2 = 0 ,sz = 0 ,sp =1;
	while( i < len){
		p2 = i;
		if( s[i] == c ) {
			if ( ((p2 == 1 && p1 == 0) || p2 > p1+1) && sp == 0) sz++ ;
			p1=p2;
			sp=1;
		}else if (s[i] != ' ' && s[i] != '\t') {
			sp =0;
		}
		i++;
	}
	if (p2 > p1 && sp == 0) sz++ ;

	/*ngx_uint_t sz = 0;
	while( len >0 ){
		sz = (s[--len] == c) ? sz+1 : sz ;
	}
	if(s[len] == c) sz--;*/
	return sz;
}

ngx_int_t ngx_str_sch_last_trimtoken(u_char *s , size_t len, u_char c , ngx_str_t *left , ngx_str_t *right)
{
	u_char begin = 0, found=0;
	u_char tmp_c;
	ngx_str_t	l,r;
	//
	if(c == '\t') {
		c = ' ';
	}
	//
	if(left == NULL) {
		left = &l;
	}
	if(right == NULL ) {
		right = &r;
	}
	//
	left->data = right->data = s;
	left->len = len;
	right->len = 0;
	s+=len-1;
	while( len > 0 ){
		tmp_c = *s;
		if(tmp_c == '\t') tmp_c=' ';
		len--;
		left->len--;
		if(tmp_c ==' ' && begin == 0){
			s--;
			continue;
		}else {
			begin=1;
		}
		//
		if(found == 0){
			if(tmp_c == c){
				right->data = s+sizeof(u_char);
				found =1;
				s--;
				continue;
			}
			right->len++;
		}

		if(tmp_c != c && found == 1){
			left->len++;
			break;
		}
		s--;
	}

	return left->data != right->data;
}

ngx_int_t ngx_str_sch_idx_trimtoken(u_char *s , size_t len, u_char c , ngx_int_t idx, ngx_str_t *token)
{
	u_char *s_t;
	while(idx-- >= 0){
		s_t = ngx_str_sch_next_trimtoken(s,len,c,token);
		if(token->len == 0) return NGX_FALSE;
		len = len - (s_t - s);
		s = s_t;
	}
	return NGX_TRUE;
}

u_char *ngx_str_sch_next_trimtoken(u_char *s , size_t len, u_char c , ngx_str_t *token)
{
	u_char *c_ret = 0;
	u_char sched = 0;
    ngx_uint_t count=0;
    u_char tmp_c;
    token->len = 0;
    if(c == '\t') {
    	c = ' ';
    }
    while( count<len && s != NULL) {
    	tmp_c = *s;
    	if(tmp_c == '\t') tmp_c=' ';
        if (tmp_c == ' ' && c != ' '){
        	s++;
        	count++;
        	continue;
        }
        if(tmp_c == c){
        	s++;
        	count++;
        	if(token->len > 0){
        	    sched = 1;
        	}
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

//idx is token index
void ngx_str_replace_pos(u_char *s , u_char c , ngx_int_t idx, u_char *st, size_t len)
{
	ngx_int_t count, ln;
	ngx_str_t tk, tk1;
	ngx_uint_t desp, sorp;
	ln = strlen((char*)s);
	count = ngx_str_find_element_count(s, ln, c);
	if (idx < count) {
		ngx_str_sch_idx_trimtoken(s, ln, c, idx, &tk);
		if (tk.len > 0) {
			desp = (tk.data - s)/sizeof(u_char) + len;
			if (idx < count - 1) {
				ngx_str_sch_idx_trimtoken(tk.data, ln - desp + 1, c, 1, &tk1);
				sorp = (tk1.data - s)/sizeof(u_char) - 1; // -1 is c
				ngx_memzero(tk.data, tk.len);
				ngx_array_mem_move(s, desp, sorp, sizeof(u_char), ln, NULL);
				count = (sorp - desp)/sizeof(u_char);
				if( count > 0 ) {
					ngx_memzero(s + ln - count, count);
				}
			} else {
				ngx_memzero(tk.data, tk.len);
			}
			ngx_memcpy(tk.data, st, len);
		}
	}
}

//阶加位置从1开始
void ngx_reverse_termial(ngx_uint_t *c , ngx_uint_t *f, ngx_uint_t n)
{
	ngx_uint_t t = termial(*f);
	if(t >= n){
		*c = t-n;
		return;
	}else {
		(*f)++;
		ngx_reverse_termial(c,f,n);
	}
}
/*
 * 第四阶	0000
 * 第三阶	 000
 * 第二阶	  00
 * 第一阶	   0
 * 本函数计算所有包含分隔符的情况，比如 a/b/c,以/为分隔符，穷举为 , a,a/b,a/b/c,b,b/c,c，所以这是一个 阶加(termial) 的过程。
 * 以 阶数-索引-索引... 做为标识，大排行的例子(上面的阶表)依次为，1-0, 2-0-1, 2-0, 3-0-1-2, 3-1-2, 3-2, 4-0-1-2-3, 4-1-2-3, 4-2-3, 4-3...
 * s要查找的串，sz共有多少个被分隔的字串，pos要查找几个字符(从0开始)，c分隔符，token返回值
 * */
u_char*
ngx_str_sch_next_trimtoken_full(ngx_str_t *s ,ngx_uint_t sz, ngx_uint_t pos, u_char c , ngx_str_t *token)
{
	ngx_str_t s_tmp;
	ngx_uint_t col=0,f=1;//代表某阶的第几列，和某阶
	ngx_reverse_termial(&col,&f,pos+1);//查找pos位置属于某阶的第几个位置
	ngx_str_sch_idx_trimtoken(s->data,s->len,c,sz-f,token);
	if(col > 0){
		ngx_str_sch_idx_trimtoken(s->data,s->len,c,sz-f+col,&s_tmp);
		token->len += s_tmp.len + 1; //包含1位分隔符
	}
	return token->data;
}

//ngx_str_t to a hash code
ngx_uint_t ngx_chars_2_hash(u_char *s , size_t size)
{
    return ngx_chars_2_hash2(s,size,89);
}

ngx_uint_t ngx_str_2_hash(ngx_str_t *s)
{
	return ngx_chars_2_hash(s->data,s->len);
}

ngx_uint_t ngx_str_2_hash2(ngx_str_t *s, ngx_uint_t factor)
{
	return ngx_chars_2_hash2(s->data,s->len,factor);
}

ngx_uint_t ngx_chars_2_hash2(u_char *s , size_t size , ngx_uint_t factor)
{
    ngx_uint_t i;
    ngx_uint_t hash = factor;
    for (i = 0; i < size; i++) {
	    hash = (hash * 5051 + s[i]) % 987631;
	}
    return hash;
}

ngx_uint_t ngx_factors[] ={71,167,271,389,503,631,757,883,1021,1153,1301,1471,1609,1777,1949,2099,2273,2417,2593,
		2719,2861,3037,3209,3359,3527,3673,3851,4019,4211,4373,4561,4733,4931,5059,5233,5417,5563,5717,5867,6067};

ngx_uint_t ngx_str_2_hash_evenly(u_char *s , size_t size)
{
	ngx_uint_t sz;
	sz = sizeof(ngx_factors)/sizeof(ngx_factors[0]);
    ngx_uint_t i,j = 0;
    ngx_uint_t hash = ngx_factors[j++];
    for (i = 0; i < size; i++) {
    	if( j + 2 > sz) {
    		j = 0;
    	}
    	hash = hash * ngx_factors[j++] + s[i] ;
    	hash %= ngx_factors[j++];

//	    hash = (hash * ngx_factors[j++] + s[i]) % ngx_factors[j++];
	}
    return hash;
}

void cpy_chars(u_char *des , u_char *sor , size_t size){
	ngx_memcpy(des,sor,size);
	/*for( ; size-- >0; des++ ,sor++) {
		*des = *sor;
	}*/
	des[size]='\0';
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

ngx_int_t
ngx_str_index_of(u_char *s , size_t len, u_char c,ngx_uint_t begin)
{
	size_t i =begin;
	while( i < len) {
		if( s[i] == c ) {
			return i;
		}
		i++;
	}
	return -1;
}

ngx_int_t
ngx_str_to_int(u_char *line, size_t n)
{
    ngx_int_t  value, cutoff, cutlim;
    ngx_uint_t  flag = 0;

    if (n == 0) {
        return NGX_ERROR;
    }

    cutoff = NGX_MAX_INT_T_VALUE / 10;
    cutlim = NGX_MAX_INT_T_VALUE % 10;

    if( *line == '-') {
    	flag= 1;
    	line++;
    	n--;
    }else if( *line == '+' ){
    	line++;
    	n--;
    }

    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }

        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return NGX_ERROR;
        }

        value = value * 10 + (*line - '0');
    }
    if(flag == 1){
    	value = -value;
    }

    return value;
}

u_char *ngx_int_to_str(ngx_pool_t* pool,ngx_int_t num)
{
	u_char *s ;
	size_t len = ngx_num_bit_count(num);
	s = ngx_palloc(pool,len+1);
	s[len] = '\0';
	ngx_int_to_str2(s, num);
	return s;
}

void ngx_int_to_str2(u_char* desc,ngx_int_t num)
{
	sprintf((char*)desc, "%ld", num);
}

char*
ngx_strcopy( ngx_pool_t *pool , ngx_str_t *str)
{
    char *s;
    s=ngx_palloc(pool,str->len+1);
    ngx_memcpy(s,str->data,str->len);
    s[str->len]='\0';
    str->len++;
    return s;
}

u_char*
ngx_strcopy2( ngx_pool_t *pool , ngx_str_t *str)
{
	u_char *s;
	s=ngx_palloc(pool,str->len);
	ngx_memcpy(s,str->data,str->len);
	return s;
}

u_char*
ngx_strcat(u_char* des , u_char* src , size_t len)
{
    ngx_memcpy(des, src, len);
    des += len;
    return des;
}

ngx_int_t ngx_str_cmp(ngx_str_t *v1 ,ngx_str_t *v2)
{
	ngx_int_t ret;
	ret = ngx_strncmp( v1->data, v2->data, ngx_min(v1->len,v2->len) );
	return (ret == 0) ? (ngx_int_t)v1->len - (ngx_int_t)v2->len : ret ;
}

ngx_int_t ngx_str_cmp2(ngx_str_t *v1 ,char *v2)
{
	ngx_str_t s;
	s.data = (u_char*)v2;
	s.len = strlen(v2);
	return ngx_str_cmp(v1,&s);
}

ngx_int_t ngx_str_cmp3(char *v1 ,char *v2)
{
	ngx_int_t l1 = strlen(v1) ,l2 = strlen(v2);
	ngx_int_t ret;
	ret = ngx_strncmp( v1, v2, ngx_min(l1,l2) );
	return (ret == 0) ? l1 - l2 : ret ;
}
ngx_int_t ngx_str_index_of_str(ngx_str_t *v1, ngx_str_t *v2)
{
	ngx_int_t p = -1;
	u_char *c;
	if(v1->len >= v2->len){
		c = ngx_strstrn(v1->data, (char*)v2->data, v2->len - 1);
		if(c != NULL) {
			p = c - v1->data;
		}
	}
	return p;
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

ngx_http_variable_value_t *ngx_http_get_variable_req_inner(ngx_http_request_t *r, ngx_str_t *name)
{
	if(name == NULL || name->len == 0 || r == NULL) return NULL;
	ngx_uint_t key = ngx_hash_strlow(name->data, name->data, name->len);
	return ngx_http_get_variable(r, name, key);
}

ngx_str_t *ngx_http_get_post_param(ngx_http_request_t *r, u_char *name , size_t len ,ngx_str_t *value)
{
	ngx_str_t args;

//	if(r->header_in){
	if(r->request_body && r->request_body->bufs && r->request_body->bufs->buf) {
		args.data = r->request_body->bufs->buf->pos;
		args.len = r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos;
//		args.data = r->header_in->pos;
//		args.len = r->header_in->last - r->header_in->pos;
		ngx_get_param_value(&args,name,len,value);
		return value;
	}
    return NULL;
}


ngx_str_t *get_request_value(ngx_http_request_t *r , ngx_str_t *var , ngx_str_t *desc)
{
	u_char	*ivar;
	size_t	isz;
	ngx_str_t *sh;
	ngx_http_variable_value_t *vl;
	ivar = var->data;
	isz = var->len ;
	desc->len=0;
	vl = ngx_http_get_variable_req_inner(r,var);
	if(vl == NULL || vl->not_found == 1){
		if (var->len >= http_head.len && ngx_str_startwith( var->data, http_head.data, http_head.len) ) {//$http_
			sh = ngx_http_get_variable_head(r,var->data+http_head.len , var->len - http_head.len);
			if(sh){
				desc->data = sh->data;
				desc->len = sh->len;
			}
		} else if (var->len >= http_param.len && ngx_str_startwith( var->data, http_param.data, http_param.len) ) {//$arg_
			var->data = var->data+http_param.len;
			var->len = var->len - http_param.len;
			ngx_http_get_param_value(r,var->data,var->len, desc);
		} else if ( !ngx_strncmp(var->data, http_uri.data, http_uri.len) ){//uri
			desc->data = r->uri.data;
			desc->len = r->uri.len;
		} else if ( !ngx_strncmp(var->data, http_arg.data, http_arg.len) ){//arg
			desc->data = r->args.data;
			desc->len = r->args.len;
		} else if (var->len >= http_body_param.len && ngx_str_startwith( var->data, http_body_param.data, http_body_param.len) ) {//post body parameter
			var->data = var->data + http_body_param.len;
			var->len = var->len - http_body_param.len;
			desc->len=0;
			ngx_http_get_post_param(r,var->data,var->len, desc);
		} else if (var->len >= http_body.len && ngx_str_startwith( var->data, http_body.data, http_body.len) ) {//body
			if(r->request_body && r->request_body->bufs && r->request_body->bufs->buf) {
				desc->data = r->request_body->bufs->buf->pos;
				desc->len = r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos;
			} else {
				desc->len = 0;
			}
		} else {
			vl = ngx_http_get_variable_req(r , var);
			if(vl && vl->not_found == 0){
				desc->data = vl->data;
				desc->len = vl->len;
			}
		}
	} else {
		desc->data = vl->data;
		desc->len = vl->len;
	}
	var->data = ivar;
	var->len = isz;
	return desc;
}

ngx_str_t *ngx_inet_ntoa(ngx_uint_t naddr , ngx_str_t *saddr)
{
	saddr->len = ngx_inet_ntop(AF_INET, &naddr, saddr->data, NGX_INET_ADDRSTRLEN);
//	struct in_addr h_addr;
//	char *s;
//	u_char *p;
//	h_addr.s_addr = naddr;

//	p = (u_char*)&naddr;
//	saddr->len = ngx_snprintf(saddr->data, NGX_INET_ADDRSTRLEN, "%ud.%ud.%ud.%ud", p[0],p[1],p[2],p[3]) - saddr->data;

//	s = inet_ntoa(h_addr);
//	saddr->data = (u_char*)s;
	return saddr;
}

ngx_int_t
ngx_create_socketpair(ngx_socket_t *st, ngx_int_t protol ,ngx_log_t *log)
{
	u_long     on;
	if (socketpair(AF_UNIX, SOCK_STREAM, protol, st) == -1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,"get master cmd channel error");
		return NGX_ERROR;
	}
	if (ngx_nonblocking(st[0]) == -1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,"nonblocking master cmd channel[0] error");
		ngx_close_channel(st, log);
		return NGX_ERROR;
	}

	if (ngx_nonblocking(st[1]) == -1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,ngx_nonblocking_n "nonblocking master cmd channel[1] error");
		ngx_close_channel(st, log);
		return NGX_ERROR;
	}

	on = 1;
	if (ioctl(st[0], FIOASYNC, &on) == -1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,"ioctl master cmd channel[0] error");
		ngx_close_channel(st, log);
		return NGX_ERROR;
	}

	if (fcntl(st[0], F_SETOWN, ngx_pid) == -1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,"fcntl master cmd channel[0] error");
		ngx_close_channel(st, log);
		return NGX_ERROR;
	}

	if (fcntl(st[0], F_SETFD, FD_CLOEXEC) == -1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,"fcntl master cmd channel[0] error ");
		ngx_close_channel(st, log);
		return NGX_ERROR;
	}

	if (fcntl(st[1], F_SETFD, FD_CLOEXEC) == -1) {
		ngx_log_error(NGX_LOG_ERR, log, 0,"fcntl master cmd channel[1] error");
		ngx_close_channel(st, log);
		return NGX_ERROR;
	}

	return NGX_OK;
}

ngx_uint_t
ngx_sockaddr_2_port(struct sockaddr *addr)
{
	ngx_uint_t pt;
	pt = (u_char)addr->sa_data[0];
	pt = pt << 8;
	pt |= (u_char)addr->sa_data[1];
	return pt;
}

u_char *ngx_sockaddr_2_str(ngx_pool_t *pool ,struct sockaddr *addr, ngx_str_t *port ,ngx_str_t *str_addr)
{
	u_char *s_p, s_tmp[4];
	size_t s_p_l = 0;
	u_char *buf = NULL , *buf_st ;
	if (port == NULL) {
		ngx_uint_t pt;//端口号
		pt = (u_char)addr->sa_data[0];
		pt = pt << 8;
		pt |= (u_char)addr->sa_data[1];
		s_p = ngx_palloc(pool,sizeof(char)*8);
		ngx_memzero(s_p,strlen((char*)s_p));
		sprintf((char*)s_p,"%lu",pt);
		s_p_l = strlen((char*)s_p);
	} else {
		s_p = port->data;
		s_p_l = port->len;
	}
	str_addr->len = 15+1+s_p_l;// ip:port
	buf_st = buf = ngx_palloc(pool, str_addr->len+1);
	ngx_memzero(buf,str_addr->len+1);
	size_t i;
	for ( i = 2 ; i < 6 ; i++ ){//ip
		ngx_memzero(s_tmp,strlen((char*)s_tmp));
		sprintf((char*)s_tmp,"%d",(u_char)addr->sa_data[i]);
		buf = ngx_strcat(buf ,s_tmp ,strlen((char*)s_tmp));
		if(i == 5 ) {
			buf = ngx_strcat(buf , (u_char*)":" ,1);
		} else {
			buf = ngx_strcat(buf , (u_char*)"." ,1);
		}
	}
	buf = ngx_strcat(buf , s_p ,s_p_l);
	str_addr->data = buf_st;
	str_addr->len = strlen((char*)buf_st);
	return buf_st;
}

char* ngx_str_host_2_chars(ngx_str_t *host, /*out*/char* bytehost)
{
	ngx_str_t ip, port, ip_num;
	ngx_uint_t pt = 80;
	u_char *tp;
	ip.len = 0;
	port.len = 0;
	ngx_str_sch_last_trimtoken(host->data, host->len, ':', &ip, &port);
	ngx_memzero(bytehost,14);
	if( port.len > 0) {
		pt = ngx_atoi(port.data, port.len);
	}
	//port
	bytehost[0] = pt >> 8;
	bytehost[1] = pt - (pt >> 8 << 8);
	//
	if( ip.len > 0){
		for(ngx_uint_t i = 2; i < 6; i++){
			tp = ngx_str_sch_next_trimtoken(ip.data, ip.len, '.', &ip_num);
			bytehost[i] = (char)ngx_atoi(ip_num.data, ip_num.len);
			ip.len = ip.len - (tp - ip.data);
			ip.data = tp;
		}
	}
	return bytehost;
}

/*
 float的结构,共32位
占位数 |  1bit    |    8bit    | 23bit
索引   |   31    |   30...23   |  0
意义   | 符号位  |   指数位   | 尾数位
求对数，只对指数位求解就可以
 */
ngx_int_t ngx_math_log2(ngx_int_t x)
{
    float fx;
    ngx_int_t ix, exp;

    fx = (float)x;
    ix = *(ngx_int_t*)&fx;
    exp = (ix >> 23) & 0xff;//the bits of exponent

    return exp - 126; // 2^7-1
}

ngx_uint_t ngx_math_pow(ngx_uint_t x , ngx_uint_t y)
{
	ngx_uint_t f = x;
	if(y == 0) x = 1;
	while(y-- > 1){
		x *= f;
	}
	return x;
}

ngx_uint_t termial(ngx_uint_t x)
{
	return x*(x+1)/2 ;
}

ngx_uint_t factorial(ngx_uint_t x){
	return (x == 1)? x : x*factorial(x-1);
}

size_t ngx_num_bit_count(ngx_int_t num)
{
	size_t c = 1;
	while( (num /= 10) != 0 ) {
		c++;
	}
	return c;
}

u_char*
ngx_uint2char(u_char* des,ngx_uint_t value,size_t len)
{
	ngx_uint_t l=0 ;
	u_char *v;
	v = (u_char*)(&value);
	while(len > l){
		des[l]=v[l];
		l++;
	}
	return des;
}

ngx_uint_t
ngx_char2uint(u_char* value,size_t len)
{
	ngx_uint_t val = 0, l = 0 ;
	u_char *v;
	v = (u_char*)(&val);
	while(len > l){
		v[l]=value[l];
		l++;
	}
	return val;
}

ngx_array_t *
ngx_parse_path(ngx_pool_t *pool, ngx_str_t *path)
{
    u_char       *p, *last, *end;
    ngx_str_t    *str;
    ngx_array_t  *array;

    array = ngx_array_create(pool, 8, sizeof(ngx_str_t));
    if (array == NULL) {
        return NULL;
    }

    p = path->data + 1;
    last = path->data + path->len;

    while(p < last) {
        end = ngx_strlchr(p, last, '/');
        str = ngx_array_push(array);

        if (str == NULL) {
            return NULL;
        }

        if (end) {
            str->data = p;
            str->len = end - p;

        } else {
            str->data = p;
            str->len = last - p;
        }

        p += str->len + 1;
    }

    return array;
}


ngx_buf_t *
append_printf(ngx_pool_t* pool, ngx_str_t *s, ngx_uint_t rt)
{
	ngx_buf_t                  *buf = NULL;

	buf = ngx_create_temp_buf(pool, s->len+(rt==1));
    if (buf != NULL) {
	    buf->last = (rt==1)? ngx_sprintf(buf->last, "%V\n", s) : ngx_sprintf(buf->last, "%V", s);
	}
    return buf;
}

ngx_buf_t *
more_append_printf(ngx_pool_t* pool, size_t size, ...)
{
	ngx_buf_t                  *buf = NULL;
	ngx_str_t *var;
	buf = ngx_create_temp_buf(pool, size);

    if (buf != NULL) {
		va_list   args;
		va_start(args, size);
		while(size > 0) {
			var = va_arg( args , ngx_str_t* );
			buf->last = ngx_sprintf(buf->last, "%V", var);
			size -= var->len ;
		}
		va_end(args);
		buf->last = ngx_sprintf(buf->last, "\n");
	}

    return buf;
}

ngx_link_t *ngx_link_init_link(ngx_link_t *link)
{
	link->last = link->first = NULL;
	link->size = 0;
	return link;
}

ngx_link_item_t *ngx_link_add_item(ngx_link_t *link ,ngx_link_item_t *data, ngx_link_item_compare cb)
{
	ngx_link_item_t *item ;
	size_t     i = 0;
	if(link->size == 0){
		link->first = link->last = data;
		link->size++;
		data->first = data->last = data;
		data->next = data->prev = NULL;
	} else {
		item = link->first;
		while(i++ < link->size) {
			if(cb(data,item) <0) {
				break;
			}
			item = item->next;
		}
		data->prev = item->prev;
		data->next = item;
		if(item->prev != NULL) {
			item->prev->next = data;
		} else {
			link->first = data;
		}
		item->prev = data;
		if(i == link->size){
			link->last = data;
		}
		link->size++;
	}
	return data;
}

ngx_link_item_t *ngx_link_find_item(ngx_link_t *link ,ngx_link_item_t *data , ngx_link_item_compare cb)
{
	ngx_link_item_t *item ;
	size_t     i = 0;

	item = link->first;
	while(i++ < link->size) {
		if(cb(data,item) == 0) {
			return item;
		}
		item = item->next;
	}
	return NULL;
}

void ngx_append_line_file( ngx_str_t *cnf_file , ngx_str_t *line )
{
	ngx_fd_t          fd;

	fd = ngx_open_file(cnf_file->data, NGX_FILE_APPEND, NGX_FILE_OPEN, NGX_FILE_DEFAULT_ACCESS);
	if (fd != NGX_INVALID_FILE) {
//		ngx_linefeed(line->data);
		ngx_write_fd(fd, line->data ,line->len);
		ngx_write_fd(fd, NGX_LINEFEED ,NGX_LINEFEED_SIZE);  //eol
		if (ngx_close_file(fd) == NGX_FILE_ERROR) {
			//
		}
	}
}

/** binary_tree **/
ngx_binary_tree_node_t *ngx_init_binary_tree(ngx_binary_tree_node_t *root)
{
	root->data = NULL;
	root->left = root->right = root->parent = 0;
	return root;
}
/*
ngx_uint_t ngx_binary_tree_is_root(ngx_binary_tree_node_t *node)
{
	return (node->parent == node->left) && (node->parent == node->right) ;
}
*/
ngx_binary_tree_node_t *ngx_binary_tree_get_node(ngx_binary_tree_node_t *root , ngx_int_t offset)
{
	return ((ngx_binary_tree_node_t*)(root+offset));
}

ngx_binary_tree_node_t *pri_ngx_binary_tree_add_node(ngx_binary_tree_node_t *root , ngx_binary_tree_node_t *parent , ngx_binary_tree_node_t *node ,ngx_binary_tree_node_compare cb)
{
	ngx_binary_tree_node_t *current_node = parent ;
	ngx_int_t *offset;
	ngx_int_t i = cb(current_node,node);
	if( i >0 ){
		offset = &current_node->left;
	}else if(i <0) {
		offset = &current_node->right ;
	} else {
		current_node->data = node->data ;
		return current_node;
	}
	if (*offset == 0){
		node->parent = parent - root ;
		*offset = node - root;
	} else {
		pri_ngx_binary_tree_add_node(root , root+(*offset) , node ,cb);
	}
	return node;
}

ngx_binary_tree_node_t *ngx_binary_tree_add_node(ngx_binary_tree_node_t *root , ngx_binary_tree_node_t *node ,ngx_binary_tree_node_compare cb)
{
	return pri_ngx_binary_tree_add_node(root,root,node,cb);
}

ngx_binary_tree_node_t *pri_ngx_binary_tree_find(ngx_binary_tree_node_t *root ,ngx_binary_tree_node_t *parent , ngx_binary_tree_node_t *data ,ngx_binary_tree_node_compare cb)
{
	ngx_binary_tree_node_t *current_node = parent , *patch;
	ngx_int_t i = cb(current_node,data);

	if( i >0 ){
		patch = root+current_node->left;
	}else if(i < 0) {
		patch = root+current_node->right ;
	} else {
		return current_node;
	}

	if (patch == root){
		current_node = NULL;
	} else {
		current_node = pri_ngx_binary_tree_find(root ,patch , data ,cb);
	}
	return current_node;
}

ngx_binary_tree_node_t *ngx_binary_tree_find(ngx_binary_tree_node_t *root , ngx_binary_tree_node_t *data ,ngx_binary_tree_node_compare cb)
{
	return pri_ngx_binary_tree_find(root ,root,data,cb);
}
/*
ngx_binary_tree_node_t *ngx_binary_tree_remove_node(ngx_binary_tree_node_t *root , ngx_binary_tree_node_t *data ,ngx_binary_tree_node_compare cb)
{
	ngx_binary_tree_node_t *right_node,*left_node,*tmp_node,*t_node;
	data = ngx_binary_tree_find(root,data,cb);
	if(data != NULL) {
		if( !ngx_binary_tree_is_root(data) ) {
			t_node = ngx_binary_tree_get_node(root , data->parent) ;
		}
		if (ngx_binary_tree_is_root(data) || cb(t_node,data) > 0 ) { //remove left node,删除节点为左节点，删除节点的右子节点为替代节点。
			// 替代节点：
			// 1. 右子一添加到左子一的右叶子
			// 2. 左子一变为右子一,此时替代节点左子一位置为空
			// 3. 删除节点变为替代节点的左子一,此时删除节点右子位置为空
			// 4. 将删除节点的左子节点位置替代删除节点
			//
			if (data->right != 0) { //
				t_node = ngx_binary_tree_get_node(root,data->right);
				if(t_node->right !=0 ){//右子一
					right_node = (ngx_binary_tree_node_t*)(root+t_node->right);//右子一
					if(t_node->left != 0) { //左子一
						left_node = (ngx_binary_tree_node_t*)(root+t_node->left); //左子一
						tmp_node = left_node;
						while ( tmp_node->right != 0 ) {//左子一的右叶子
							tmp_node = (ngx_binary_tree_node_t*)(root+tmp_node->right);
						}
						tmp_node->right = right_node - root ;// 1. 右子一添加到左子一的右叶子
						right_node->parent = tmp_node - root ;
					}
				}
				if( t_node->left !=0 ){// 2. 左子一变为右子一,此时替代节点左子一位置为空
					left_node = (ngx_binary_tree_node_t*)(root+t_node->left); //左子一
					t_node->right = left_node - root;
					t_node->left = 0;
				}
				//3. 删除节点变为替代节点的左子一,之后删除节点右子位置为空
				t_node->left = data - root;
				t_node->parent = data->parent;
				data->parent = t_node - root;

			}
			if (data->left != 0) { //4. 将删除节点的左子节点位置替代删除节点
				t_node = ngx_binary_tree_get_node(root,data->left); //
				if(!ngx_binary_tree_is_root(data)) {
					tmp_node = ngx_binary_tree_get_node(root,data->parent);
					tmp_node->left = data->left;
				}
				t_node->parent = data->parent;
			}
			data->parent = data->left = data->right = 0;
		} else { //remove right node

		}
	}
	return root;
}
*/
/** **/

////share memory
//预估分配空间, 申请共享日志空间,数据空间在分配时，还需要将承载数据的结构体空间计算在内！
size_t
ngx_shm_estimate_size(size_t size)
{
	size_t esize,pages,n; //
	// size/ngx_pagesize 预估数据部分需要多少页。
	pages = (size >> ngx_pagesize_shift) + ((size % ngx_pagesize) ? 1 : 0) + 1; //+1是为了访问对齐计算挤掉一页，所以在预估情况下加1冗余
	esize = pages * (ngx_pagesize + sizeof(ngx_slab_page_t)); //每页加上ngx_slab_page_t结构大小重新计算需要空间
	n = ngx_pagesize_shift - 3; //pool->min_shift=3;
	esize += sizeof(ngx_slab_pool_t) + n*(sizeof(ngx_slab_page_t) + sizeof(ngx_slab_stat_t)) ; //计算包含pool以及存储有效数据所需要结构体的大小，就是总共需要分配的空间
	return esize;
}

//申请共享空间
ngx_shm_zone_t *
ngx_shm_zone_init(ngx_conf_t *cf, ngx_module_t *module ,ngx_str_t *name, size_t size, void *data,ngx_shm_zone_init_pt shm_zone_init)
{
	ngx_shm_zone_t                       *shm_zone;
	shm_zone = ngx_shared_memory_add(cf, name, size, module); //初始预分配共享空间
	shm_zone->data = data; //初始化空间时传入的数据
	shm_zone->init = shm_zone_init; //初始化空间
	return shm_zone;
}

//查找已分配的共享空间
ngx_shm_zone_t *
ngx_shared_memory_find(ngx_cycle_t *cycle, ngx_str_t *name, void *tag)
{
    ngx_uint_t        i;
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;

    part = (ngx_list_part_t *) &(cycle->shared_memory.part);
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }
        if (name->len != shm_zone[i].shm.name.len) {
            continue;
        }
        if (ngx_strncmp(name->data, shm_zone[i].shm.name.data, name->len) != 0){
            continue;
        }
        if (tag != shm_zone[i].tag) {
            continue;
        }
        return &shm_zone[i];
    }
    return NULL;
}

void
ngx_array_remove_by_index(ngx_array_t *a, ngx_uint_t idx, ngx_array_remove_item_ptr itemcb)
{
//	ngx_uint_t i ;
//	void *des, *sor;
	if( a->nelts > idx ) {
		ngx_array_mem_move(a->elts, idx, idx + 1, a->size, a->nelts, itemcb);
		a->nelts--;
//		des = (void*)((uintptr_t)a->elts + idx * a->size);
//		sor = (void*)((uintptr_t)a->elts + (idx+1) * a->size);
//		ngx_memcpy(des, sor, (a->nelts - idx) * a->size);
//		if( itemcb != NULL) {
//			for( i = idx; i < a->nelts; i++ ) {
//				itemcb(  (void*)((uintptr_t)a->elts + i * a->size), i );
//			}
//		}
	}
}

void
ngx_array_remove_by_item(ngx_array_t *a, void *item)
{
	ngx_uint_t i, sz;
	void *it;
	sz = a->nelts;
	for( i = 0; i < sz; i++) {
		it = (void*)((uintptr_t)a->elts + i * a->size);
		if( it == item ) {
			ngx_array_remove_by_index(a, i, NULL);
			break;
		}
	}
}

void
ngx_array_mem_move(void *ar, ngx_uint_t desidx, ngx_uint_t soridx, size_t sz, size_t len, ngx_array_remove_item_ptr itemcb )
{
	ngx_uint_t i, l;
	l = len - soridx;
	if( desidx != soridx) {
		void *des, *sor, *temp;
		des = (void*)((uintptr_t)ar + desidx * sz);
		sor = (void*)((uintptr_t)ar + soridx * sz);
		temp = ngx_palloc(ngx_cycle->pool, sz * l);
		ngx_memcpy(temp, sor, sz * l);
		ngx_memcpy(des, temp, sz * l);
//		ngx_memcpy(des, sor, sz * len);
		ngx_pfree(ngx_cycle->pool, temp);
		//
	}
	if( itemcb != NULL) {
		for( i = desidx; i < l + desidx; i++ ) {
			itemcb(  (void*)((uintptr_t)ar + i * sz), i );
		}
	}
}

void
ngx_array_direct_mem_move(void *ar, ngx_uint_t desidx, ngx_uint_t soridx, size_t sz, size_t len, ngx_array_remove_item_ptr itemcb )
{
	if( desidx < soridx) {
		void *des, *sor;
		ngx_uint_t i;
		des = (void*)((uintptr_t)ar + desidx * sz);
		sor = (void*)((uintptr_t)ar + soridx * sz);
		len -= soridx;
		for( i = desidx; i < desidx + len; i++) {
			ngx_memcpy(des, sor, sz);
			if( itemcb != NULL) {
				itemcb( des, i );
			}
			des = (void*)((uintptr_t)des + sz);
			sor = (void*)((uintptr_t)sor + sz);
		}
	}
}

void ngx_pool_create(ngx_log_t *log)
{
	ngx_global_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, log);
}
