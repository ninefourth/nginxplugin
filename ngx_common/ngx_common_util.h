#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_TRUE                  1
#define NGX_FALSE                 0

/* binary tree */
typedef struct ngx_binary_tree_node_s ngx_binary_tree_node_t;
typedef ngx_int_t (*ngx_binary_tree_node_compare) (ngx_binary_tree_node_t *node1 , ngx_binary_tree_node_t *node2);
struct ngx_binary_tree_node_s {
	ngx_int_t     parent; //parent node ,offset from root
	void				  *data;
	ngx_int_t     left;   //left node ,offset from root
	ngx_int_t     right;  //right node ,offset from root
} ;
ngx_binary_tree_node_t *ngx_init_binary_tree(ngx_binary_tree_node_t *root);
ngx_binary_tree_node_t *ngx_binary_tree_add_node(ngx_binary_tree_node_t *root , ngx_binary_tree_node_t *node ,ngx_binary_tree_node_compare cb);
ngx_binary_tree_node_t *ngx_binary_tree_find(ngx_binary_tree_node_t *root , ngx_binary_tree_node_t *data ,ngx_binary_tree_node_compare cb);
/* */

/* link */
typedef struct ngx_link_item_s ngx_link_item_t;

typedef ngx_int_t (*ngx_link_item_compare) (ngx_link_item_t *newitem , ngx_link_item_t *olditem);

struct ngx_link_item_s{
	ngx_link_item_t        *first;
	ngx_link_item_t		*prev;
	void					*data;
	ngx_link_item_t		*next;
	ngx_link_item_t        *last;
} ;

typedef struct {
	ngx_link_item_t        *first;
	ngx_link_item_t        *last;
	size_t                size;
} ngx_link_t ;
ngx_link_t *ngx_link_init_link(ngx_link_t *link);
ngx_link_item_t *ngx_link_add_item(ngx_link_t *link ,ngx_link_item_t *data, ngx_link_item_compare cb);
ngx_link_item_t *ngx_link_find_item(ngx_link_t *link ,ngx_link_item_t *data , ngx_link_item_compare cb);
/*  */

/*string function*/
ngx_uint_t ngx_chars_2_hash(u_char *s , size_t size);
ngx_uint_t ngx_str_2_hash(ngx_str_t *s);
void cpy_chars(u_char *des , u_char *sor , size_t size);
char *ngx_strcpy( ngx_pool_t *pool , ngx_str_t *str);
u_char *ngx_strcat(u_char* des , u_char* src , size_t len);
ngx_uint_t read_line(u_char *buf);
ngx_int_t ngx_str_startwith(u_char *des , u_char *head , ngx_int_t len);
ngx_uint_t ngx_str_find_element_count(u_char *s ,size_t len , u_char c);
u_char *ngx_str_sch_next_trimtoken(u_char *s , size_t len, u_char c , ngx_str_t *token);
size_t ngx_num_bit_count(ngx_int_t num);

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
