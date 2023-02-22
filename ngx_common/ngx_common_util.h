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
ngx_uint_t *ngx_binary_tree_is_root(ngx_binary_tree_node_t *node);
ngx_binary_tree_node_t *ngx_binary_tree_get_node(ngx_binary_tree_node_t *root , ngx_int_t offset);
ngx_binary_tree_node_t *ngx_binary_tree_add_node(ngx_binary_tree_node_t *root , ngx_binary_tree_node_t *node ,ngx_binary_tree_node_compare cb);
ngx_binary_tree_node_t *ngx_binary_tree_find(ngx_binary_tree_node_t *root , ngx_binary_tree_node_t *data ,ngx_binary_tree_node_compare cb);
//ngx_binary_tree_node_t *ngx_binary_tree_remove_node(ngx_binary_tree_node_t *root , ngx_binary_tree_node_t *data ,ngx_binary_tree_node_compare cb);
//ngx_binary_tree_node_t *ngx_binary_tree_add_tree(ngx_binary_tree_node_t *root , ngx_binary_tree_node_t *data ,ngx_binary_tree_node_compare cb);
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

/**string function*/
////字符串转哈希系列
ngx_uint_t ngx_chars_2_hash(u_char *s , size_t size);
ngx_uint_t ngx_str_2_hash(ngx_str_t *s);
ngx_uint_t ngx_str_2_hash2(ngx_str_t *s, ngx_uint_t factor);
ngx_uint_t ngx_chars_2_hash2(u_char *s , size_t size , ngx_uint_t factor);
ngx_uint_t ngx_str_2_hash_evenly(u_char *s , size_t size);
//字符串拷贝
void cpy_chars(u_char *des , u_char *sor , size_t size);
char *ngx_strcopy( ngx_pool_t *pool , ngx_str_t *str);
u_char *ngx_strcat(u_char* des , u_char* src , size_t len);
//以指定字符串开头
ngx_int_t ngx_str_startwith(u_char *des , u_char *head , ngx_int_t len);
////token系列
//根据指定字符计算token个数
ngx_uint_t ngx_str_find_element_count(u_char *s ,size_t len , u_char c);
//得到下一个token
u_char *ngx_str_sch_next_trimtoken(u_char *s , size_t len, u_char c , ngx_str_t *token);
//得到下一个token(包含分隔符,所以是全匹配)
u_char *ngx_str_sch_next_trimtoken_full(ngx_str_t *s ,ngx_uint_t sz, ngx_uint_t pos, u_char c , ngx_str_t *token);
//得到指定索引之后的token
ngx_int_t ngx_str_sch_idx_trimtoken(u_char *s , size_t len, u_char c , ngx_int_t idx, ngx_str_t *token);
//得到指定字符左右两边的字符串
ngx_int_t ngx_str_sch_last_trimtoken(u_char *s , size_t len, u_char c , ngx_str_t *left , ngx_str_t *right);
//查找begin之后指定字符的索引位
ngx_int_t ngx_str_index_of(u_char *s , size_t len, u_char c ,ngx_uint_t begin);
//字符串转数字
ngx_int_t ngx_str_to_int(u_char *line, size_t n);
ngx_uint_t ngx_char2uint(u_char* value,size_t len);
//数字转字符串
u_char *ngx_int_to_str(ngx_pool_t* pool,ngx_int_t num);
u_char* ngx_uint2char(u_char* des,ngx_uint_t value,size_t len);
void ngx_int_to_str2(u_char* desc,ngx_int_t num);
//比较两个字符串
ngx_int_t ngx_str_cmp(ngx_str_t *v1 ,ngx_str_t *v2);
ngx_int_t ngx_str_cmp2(ngx_str_t *v1 ,char *v2);
ngx_int_t ngx_str_cmp3(char *v1 ,char *v2);
//得到以\n或\0结尾字符串的长度，用于统计从文件中读出的一行有多少字符
ngx_uint_t read_line(u_char *buf);
//将地址以/为分隔符转成字符串数组
ngx_array_t *ngx_parse_path(ngx_pool_t *pool, ngx_str_t *path);
//创建缓冲并将指定字符串添加进去，rt批是否添加回车符
ngx_buf_t *append_printf(ngx_pool_t* pool, ngx_str_t *s, ngx_uint_t rt);
//创建缓冲并将多个字符串添加进来
ngx_buf_t *more_append_printf(ngx_pool_t* pool, size_t size, ...);

/**http request function*/
//get http url parameter
ngx_str_t *ngx_http_get_param_value(ngx_http_request_t *r , u_char *param , ngx_uint_t len , ngx_str_t *value);
//get http header
ngx_str_t *ngx_http_get_variable_head(ngx_http_request_t *r, u_char *name , size_t len);
//get http variable object by name
ngx_http_variable_value_t *ngx_http_get_variable_req(ngx_http_request_t *r, ngx_str_t *name);
//get the post parameter
ngx_str_t *ngx_http_get_post_param(ngx_http_request_t *r, u_char *name , size_t len ,ngx_str_t *value);
ngx_str_t *ngx_get_param_value(ngx_str_t *args , u_char *param , ngx_uint_t len , ngx_str_t *value);

ngx_str_t *get_request_value(ngx_http_request_t *r , ngx_str_t *var , ngx_str_t *desc);

////net
ngx_str_t *ngx_inet_ntoa(ngx_uint_t naddr , ngx_str_t *saddr);//将ip转成字符串
ngx_int_t ngx_create_socketpair(ngx_socket_t *st, ngx_int_t protol ,ngx_log_t *log);//创建socket pair,一个用于读一个用于写
u_char *ngx_sockaddr_2_str(ngx_pool_t *pool ,struct sockaddr *addr, ngx_str_t *port ,ngx_str_t *str_addr); //将sockaddr转换为字符串地址

////math
ngx_int_t ngx_math_log2(ngx_int_t x); //以2为底的对数
ngx_uint_t ngx_math_pow(ngx_uint_t x , ngx_uint_t y); //x的y次方
ngx_uint_t termial(ngx_uint_t x); //阶加
ngx_uint_t factorial(ngx_uint_t x); //阶乘
size_t ngx_num_bit_count(ngx_int_t num);//判断给定整数num是几位数

////file
void ngx_append_line_file(ngx_str_t *cnf_file , ngx_str_t *line );//向指定文件尾添加一行

////share memory
size_t ngx_shm_estimate_size(size_t size);
ngx_shm_zone_t *ngx_shm_zone_init(ngx_conf_t *cf, ngx_module_t *module ,ngx_str_t *name, size_t size, void *data,ngx_shm_zone_init_pt shm_zone_init);
ngx_shm_zone_t *ngx_shared_memory_find(ngx_cycle_t *cycle, ngx_str_t *name, void *tag);
