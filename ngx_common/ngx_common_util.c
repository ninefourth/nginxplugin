#include "ngx_common_util.h"


ngx_uint_t ngx_str_find_element_count(u_char *s ,size_t len , u_char c)
{
	ngx_uint_t i = 0 ,p1 = 0, p2 = 0 ,sz = 0 ,sp =1;
	while( i < len){
		p2 = i;
		if( s[i] == c ) {
			if (p2 > p1+1 && sp == 0) sz++ ;
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

/** binary_tree **/
ngx_binary_tree_node_t *ngx_init_binary_tree(ngx_binary_tree_node_t *root)
{
	root->data = NULL;
	root->left = root->right = root->parent = 0;
	return root;
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

/** **/
