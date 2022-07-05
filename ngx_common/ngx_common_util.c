#include "ngx_common_util.h"

static ngx_str_t http_head=ngx_string("http_");
static ngx_str_t http_param=ngx_string("arg_");
static ngx_str_t http_uri=ngx_string("uri");
static ngx_str_t http_body_param=ngx_string("body_");
static ngx_str_t http_body=ngx_string("body");
static ngx_str_t http_arg=ngx_string("arg");

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
	//
	if(c == '\t') {
		c = ' ';
	}
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
		if(vl){
			desc->data = vl->data;
			desc->len = vl->len;
		}
	}
	var->data = ivar;
	var->len = isz;
	return desc;
}

ngx_str_t *ngx_inet_ntoa(ngx_uint_t naddr , ngx_str_t *saddr)
{
	struct in_addr h_addr;
	char *s;
	h_addr.s_addr = naddr;
	s = inet_ntoa(h_addr);
	saddr->data = (u_char*)s;
	saddr->len = strlen(s);
	return saddr;
}


ngx_int_t ngx_math_log2(ngx_int_t x)
{
    float fx;
    ngx_int_t ix, exp;

    fx = (float)x;
    ix = *(ngx_int_t*)&fx;
    exp = (ix >> 23) & 0xff;//the bits of exponent

    return exp - 126;
}

ngx_uint_t ngx_math_pow(ngx_uint_t x , ngx_uint_t y)
{
	if(y == 0) x = 1;
	while(y-- > 1){
		x *= x;
	}
	return x;
}

size_t ngx_num_bit_count(ngx_int_t num)
{
	size_t c = 1;
	while( (num /= 10) != 0 ) {
		c++;
	}
	return c;
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
