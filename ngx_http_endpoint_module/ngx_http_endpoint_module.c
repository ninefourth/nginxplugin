/**
 * 本文件有三大块内容，
 * 1. partA: 是endpoint，由nginx指令访问的入口模块及指令处理
 * 2. partB: 是全局的共享内存shm_process
 * 3. partC: 是所有work processer(简称wp)间通讯的socket注册表ngx_chs, 相关函数ngx_get_msg, ngx_broadcast_processes
 *
 * 关于 pool，是有生命期的，如果是 r->pool 生命期只限于会话，如果有需要长期保留的变量就使用 ngx_cycle->pool，这是nginx全局的。所以使用
 * ngx_palloc分配的空间要先确定保留的范围
 * */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_channel.h>
#include <ngx_http_endpoint_module.h>
#include "../ngx_common/ngx_common_util.h"

#if (NGX_HTTP_UPSTREAM_XFDF_IP_HASH)
#include "ngx_http_upstream_xfdf_ip_hash_module.h"
#endif

#if (NGX_HTTP_UPSTREAM_CHECK)
#include "ngx_http_upstream_check_module.h"
#endif

#if(NGX_HTTP_REQUEST_CHAIN)
#include "ngx_http_request_chain_module.h"
#endif

#if(NGX_HTTP_WAF_MODULE)
#include "ngx_http_waf_module_config.h"
#endif

#if(NGX_HTTP_REQUEST_LOG)
#include "ngx_http_request_log_module.h"
#endif
/** define */
/** partA */
static char *ngx_http_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_var_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
//static void *ngx_http_endpoint_create_srv_conf(ngx_conf_t *cf);

//模块指令
static ngx_command_t  ngx_http_endpoint_commands[] = {

    { ngx_string("endpoint"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_endpoint,
      0,
      0,
      NULL },
	{ ngx_string("var_conf"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
	  ngx_http_var_conf,
	  0,
	  0,
	  NULL },
      ngx_null_command
};

static char *ngx_http_endpoint_init_main_conf(ngx_conf_t *cf, void *conf);

//模块环境参数
static ngx_http_module_t  ngx_http_endpoint_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
	ngx_http_endpoint_init_main_conf,              /* init main configuration */

    NULL,  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

static ngx_int_t ngx_http_endpoint_init_process(ngx_cycle_t *cycle);
static void ngx_http_endpoint_exit_process(ngx_cycle_t *cycle);

//模块入口
ngx_module_t  ngx_http_endpoint_module = {
    NGX_MODULE_V1,
    &ngx_http_endpoint_module_ctx, /* module context */
    ngx_http_endpoint_commands,    /* module directives */
    NGX_HTTP_MODULE,                     /* module type */
	NULL,					                /* init master */
    NULL,                                  /* init module */
	ngx_http_endpoint_init_process,               /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
	ngx_http_endpoint_exit_process,               /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/** partC */
struct ngx_process_cmd_channel_s {
	ngx_socket_t	channel_pair[2];
	ngx_event_t 	ev;
};
typedef struct ngx_process_cmd_channel_s ngx_process_cmd_channel;

//work process的 socket pair登记表, main中赋的值，所以所有 worker共有
struct ngx_processes_cmd_channel_s {
	ngx_int_t 				count;
	ngx_process_cmd_channel	chs[1];
};
typedef struct ngx_processes_cmd_channel_s ngx_processes_cmd_channel;
ngx_processes_cmd_channel	*ngx_chs; //所有master/worker共有

typedef struct {
	ngx_int_t				pos; //当前work process在 ngx_chs 取得的值的位置。worker process的标号，全局的ngx_process_slot标识连同失效的也算在内，本变量只标识有效
	size_t				ngx_msg_size ; //当前传递的消息实际内容的长度
} ngx_process_args;
ngx_process_args		ngx_args; //当前 work process 的特有变量

typedef ngx_int_t (*msg_handler)(void *msg, ngx_str_t *emsg); //接收消息后，回调处理信息
static ngx_int_t dn_msg_handler(void *msg, ngx_str_t *emsg); //域名刷新的回调
static ngx_int_t up_srv_add_msg_handler(void *msg, ngx_str_t *emsg); //动态添加server的回调
static ngx_int_t up_srv_main_add_msg_handler(void *msg, ngx_str_t *emsg);
static ngx_int_t up_srv_remove_msg_handler(void *msg, ngx_str_t *emsg); //动态删除server的回调
static ngx_int_t up_srv_main_remove_msg_handler(void *msg, ngx_str_t *emsg);
static ngx_int_t remove_up_srv(ngx_str_t *up, ngx_str_t *sv);
static ngx_int_t _up_srv_main_add_msg_handler(ngx_str_t *s);
static ngx_int_t _up_srv_main_remove_msg_handler(ngx_str_t *s);

static void update_dyn_up_srv_wt(ngx_str_t *up, ngx_str_t *sr, ngx_int_t w);
static void update_dyn_up_srv_rg(ngx_str_t *up, ngx_str_t *sr, ngx_int_t r);

#ifdef NGX_HTTP_REQUEST_LOG
static ngx_int_t request_log_msg_handler(void *msg, ngx_str_t *emsg);//请求日志的回调
static ngx_int_t request_log_disable_handler(void *msg, ngx_str_t *emsg);//关闭日志的回调
static ngx_int_t request_log_enable_handler(void *msg, ngx_str_t *emsg); //打开日志的回调
#endif

#ifdef NGX_HTTP_WAF_MODULE
static ngx_int_t waf_reload_msg_handler(void *msg, ngx_str_t *emsg);//waf 名单回调
static ngx_int_t waf_onoff_msg_handler(void *msg, ngx_str_t *emsg);//waf开关回调
static ngx_int_t waf_reload_mode_handler(void *msg, ngx_str_t *emsg);//waf_mode 设置回调
#endif

#define CMD_PAYLOAD_SIZE	1   //消息传递指令，指示本消息是头信息，表现后面的消息体的大小
#define CMD_PROCESS			2   //消息传递指令，指示本消息是要处理的业务
typedef struct {
	ngx_int_t			cmd; 	//命令
	ngx_fd_t    		fd; 		//如果要传输本地描述符,做控制信息传递
	msg_handler		handler;	//因为所有work process的地址是统一的,因此传递回调函数的地址是可以的
	size_t			size; //要传递的消息大小
	char				data[1]; 	//实际传输的数据
} ngx_channel_msg; //传递的消息

ngx_int_t ngx_broadcast_processes(ngx_channel_msg *msg, size_t size, ngx_log_t *log, ngx_int_t pos); //对所其它子进程广播消息
static size_t ngx_get_msg(ngx_channel_msg **msg, ngx_pool_t *pool, void *data, size_t size , msg_handler handler); //创建一个ngx_channel_msg用于传递，返回消息体和整个消息的大小

static void ngx_http_endpoint_channel_task(ngx_cycle_t *cycle,ngx_event_t *ev);

/** partB */
#define	max_dns		10
#define	max_dns_len	100
#define	max_waf_item		20
#define	max_waf_item_len	20
#define	max_dyn_up_srv		500
#define	max_dyn_up_srv_len		100
typedef struct {
	u_char			dns[max_dns][max_dns_len];
	size_t			count;
}domainnames;
typedef struct {
	u_char			waf_item[max_waf_item][max_waf_item_len];
	size_t			count;
}waf_items;
typedef struct {
	uintptr_t			waf_addrs[max_waf_item_len];
	u_short			onff[max_waf_item_len];
}waf_onff;
typedef struct {
	u_char			waf_mode[max_waf_item][max_waf_item_len];
	size_t			count;
}waf_modes;
typedef struct {
    ngx_shmtx_t                              mutex;
#if (nginx_version >= 1002000)
    ngx_shmtx_sh_t                           lock;
#else
    ngx_atomic_t                             lock;
#endif
    u_short			loaded;
	u_char			up_srvs[max_dyn_up_srv][max_dyn_up_srv_len];
	size_t			count;
}dyn_up_srvs;
typedef struct {
	//TODO 有需要添加的共享内存数据就放到此结构体里
	domainnames		dns;//如果有通过 domain/resovle/ 指令要求重新解析域名的在此做个记录，防止 某 work process被kill后能重新resolve,因为所有子进程重新启动后只是复制主进程的内容
	waf_items		wfs; //waf的各项, 指令/waf/reload/[name]/ipv4 ，kill后的重加载
	waf_onff			ws; //waf的开关
	waf_modes		wfms; //waf_mode的重载 /waf/reloadmode/!STD
	dyn_up_srvs		dus; //动态添加 /add/[upstream]/[server]/[region]/[weight]/[check_down]/[force_down]
	ngx_atomic_t		debug_log; //是否输出调试日志
} ngx_endpoint_shm_t;

ngx_slab_pool_t *shpool = NULL;
ngx_endpoint_shm_t *shm_process = NULL; //共享内存的本地变量

static ngx_str_t shm_endpoint = ngx_string("shm_endpoint");//共享内存的名称
/*typedef struct{
	size_t		size;
	void			*data;
} ngx_endpoint_catch_data;
ngx_endpoint_catch_data catch_data; //创建共享内存时，携带给初始化操作的数据
*/
/** - */
#ifdef NGX_HTTP_WAF_MODULE
typedef struct {
	ngx_http_waf_loc_conf_t	*waf_cnf;
	char					flag[max_waf_item];
} waf_data;
#endif

#define ngx_msg_str(str_t,s)     { str_t.len = strlen((char*)s); str_t.data = s; }

static ngx_str_t sucs = ngx_string("success");
static ngx_str_t fail = ngx_string("failure");

void ngx_append(ngx_chain_t *p , ngx_chain_t *c);

ngx_int_t is_debug_log()
{
	return (shm_process != NULL && shm_process->debug_log == 1);
}

/** content */
//将内容val添加到输出链out,当输出内容长度大于 pool一次可以提供的大小时，就截断到链里
static size_t
ngx_http_out_content( ngx_pool_t *pool, ngx_str_t *val, ngx_chain_t *out, ngx_uint_t tail )
{
	ngx_buf_t					*buf;
	ngx_chain_t				*out_native;
	ngx_str_t					val_native;
	size_t					len=0;
	if(val->len > pool->max) {
		out_native = ngx_pcalloc(pool, sizeof(ngx_chain_t));
		val_native.data = val->data;
		val_native.len = pool->max;
		buf = append_printf(pool, &val_native,0);
		len = ngx_buf_size(buf);
		out->buf = buf;
		out->next = out_native;
		val_native.data = val->data+pool->max;
		val_native.len = val->len - pool->max;
		len+=ngx_http_out_content(pool, &val_native ,out_native,tail);
	}else{
		buf = append_printf(pool, val, (tail == 1) );
		len = ngx_buf_size(buf);
		out->buf = buf;
		if(tail == 1) {
			buf->last_buf = 1;
			out->next = NULL;
		}
	}
	return len;
}

static size_t
ngx_http_chain_content(ngx_buf_t *buf, ngx_chain_t *out)
{
	size_t len = ngx_buf_size(buf);
	out->buf = buf;
	buf->last_buf = 1;
	out->next = NULL;
	return len;
}

//将一个缓存链添加到另一个尾部
void
ngx_append(ngx_chain_t *p , ngx_chain_t *c)
{
	if(p->next == NULL) {
		p->next = c;
	}else{
		ngx_append(p->next,c);
	}
}

/**
 * 将字符串s添加到字符串数组data中
 * sz表示字符串数组的字符串数量
 * size表示字符串数的最大数量
 * tl 表示字符串数组是每个字符串的最大长度
 * */
u_char* ngx_http_endpoint_item_shm_process_directive(/*out*/u_char *data, /*out*/size_t *sz, size_t size, size_t tl, ngx_str_t *s)
{
	ngx_uint_t i;
	u_char *ret = NULL;
	for( i = 0; i < size ; i++, data+=sizeof(u_char)*tl ) {
//		u_char *d = data;//shm_process->dns.dns[i];
		if(data[0] == '\0') {
			ngx_memcpy(data, s->data, s->len);
			(*sz)++;
			ret = data + s->len;
			break;
		}
		if( ngx_str_cmp2(s,(char*)data) == 0){
			ret = data + s->len;
			break;
		}
	}
	return ret;
}

//删除指定变量内容,fuzzy=1代表包含, =0代表等于
void ngx_http_endpoint_item_shm_process_remove_directive(/*out*/u_char *data, /*out*/size_t *sz, size_t size, size_t tl, ngx_str_t *s, ngx_int_t fuzzy)
{
	ngx_uint_t i;
	ngx_str_t s1;
	u_char *p = data;
	for( i = 0; i < size ; i++, data+=sizeof(u_char)*tl ) {
		s1.data = data;
		s1.len = strlen((char*)data);
		if( (fuzzy && ngx_str_index_of_str(&s1, s) >=0) || (!fuzzy && ngx_str_cmp2(s,(char*)data) == 0) ) {
			ngx_array_mem_move(p, i, i+1, sizeof(u_char)*tl, size, NULL);
			(*sz)--;
			break;
		}
	}
}

//重新解析域名
ngx_int_t
ngx_http_endpoint_reslove_dn(ngx_pool_t *pool,ngx_str_t *dn)
{
	ngx_http_upstream_main_conf_t		 *umcf;
	ngx_http_upstream_srv_conf_t  		**uscfp;
//	ngx_http_upstream_server_t			*srv;
	ngx_http_upstream_rr_peers_t			*peers;
	ngx_http_upstream_rr_peer_t			*peer;
	//
	ngx_url_t                    u;
	ngx_str_t 					s_token;
	ngx_memzero(&u, sizeof(ngx_url_t));
	u.url.data = dn->data;
	u.url.len = dn->len;
	u.default_port = 80;
	if (ngx_parse_url(pool, &u) != NGX_OK) { //解析地址,如果是域名会得到有效的ip,并转成sockaddr.
		if (u.err) {
			ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "%s in upstream when resolve domain \"%V\"", u.err, &u.url);
			return NGX_ERROR;
		}
	}
	//
	ngx_uint_t i;
//	ngx_uint_t j;

	umcf = ngx_http_cycle_get_module_main_conf(ngx_cycle,ngx_http_upstream_module);
	uscfp = umcf->upstreams.elts;
	for (i = 0; i < umcf->upstreams.nelts; i++) {
		if (uscfp[i]->peer.data != NULL ){
			peers = (ngx_http_upstream_rr_peers_t*)uscfp[i]->peer.data;
			size_t k=0 ;
			ngx_http_upstream_rr_peer_t *p_p = NULL ;
			/*
			 同一个域名可能会被解析成多个ip, 在ip与原peer一对一对等的情况下只需要修改相应的peer; 在ip多于peer的情况下，修改相应的peer并
			 且添加新peer与ip数量相同; 如果原peer多于ip，则修改相应的peer并且清除多余的peer
			*/
			for( peer = peers->peer ; peer ; peer = peer->next) {
				if(peer->server.len == 0) {
					ngx_str_sch_next_trimtoken(peers->name->data ,peers->name->len ,':',&s_token);//非upstream定义的服务
				}else {
					ngx_str_sch_next_trimtoken(peer->server.data ,peer->server.len ,':',&s_token);//upstream内定义的服务
				}
				if( s_token.len == 0 || ngx_str_cmp(&s_token,dn) != 0 ) {
					if(u.naddrs > k && k > 0 && p_p != NULL){ //有多地址没有对应的peer，则建立对应的peer再回拨
						ngx_http_upstream_rr_peer_t *p = ngx_palloc(pool, sizeof(ngx_http_upstream_rr_peer_t));
						ngx_memcpy(p,p_p,sizeof(ngx_http_upstream_rr_peer_t));
						p->sockaddr = ngx_palloc(pool, sizeof(struct sockaddr));
						ngx_memcpy(p->sockaddr,p_p->sockaddr,sizeof(struct sockaddr));
						p_p->next = p;
						peer = p_p;
						peers->number++;
						continue;
					}
				} else {
					peers->single = (peers->single ==1 && u.naddrs == 1);
					if(u.naddrs <= k) {//如果符合条件的peer数量多于u的addr数量
						p_p->next = peer->next;
						peer = p_p;
						ngx_pfree(pool,peer->sockaddr);
						ngx_pfree(pool,peer);
						peers->number--;
						continue;
					}
//				if( s_token.len > 0 && ngx_str_cmp(&s_token,dn) == 0 ){
					//将新解析的地址sockaddr，重新置回peer中
					//sockaddr->sa_data 共14个字节，前2个byte是端口，后面4个byte是ip，剩下的byte保留没有作用
					p_p = peer;
					peer->socklen = u.addrs[k].socklen;
					ngx_memcpy(peer->sockaddr->sa_data+2, u.addrs[k].sockaddr->sa_data+2, 4);//前2byte是端口，保留。后4byte是地址，复制
					ngx_pfree(pool,peer->name.data);
					ngx_sockaddr_2_str(pool,peer->sockaddr,NULL,&peer->name);//log中用于显示的地址名称
					k++;
					if( peer->next == NULL && u.naddrs > k) {//当peer最末时，还有更多的addr则增加peer
						ngx_http_upstream_rr_peer_t *p = ngx_palloc(pool, sizeof(ngx_http_upstream_rr_peer_t));
						ngx_memcpy(p,peer,sizeof(ngx_http_upstream_rr_peer_t));
						p->sockaddr = ngx_palloc(pool, sizeof(struct sockaddr));;
						ngx_memcpy(p->sockaddr,peer->sockaddr,sizeof(struct sockaddr));
						peer->next = p;
						peers->number++;
						continue;
					}
				}
			}
		}
		/*if (uscfp[i]->servers != NULL ) {
			for (j = 0; j < uscfp[i]->servers->nelts ; j++) {
				srv = (ngx_http_upstream_server_t*)uscfp[i]->servers->elts + j;
				ngx_str_sch_next_trimtoken(srv->name.data ,srv->name.len ,':',&s_token);
				ngx_addr_t *tmp_addr , *tmp_addrs = srv->addrs;
				if( s_token.len > 0 && ngx_str_cmp(&s_token,dn) == 0 ){
					if(srv->naddrs < u.naddrs){
						tmp_addrs = ngx_palloc(pool, sizeof(ngx_addr_t)*u.naddrs);
					}
					srv->naddrs = u.naddrs;
					tmp_addr = srv->addrs;
					for (size_t k = 0; k < u.naddrs ; k++) {
						memcpy(&tmp_addrs[k],tmp_addr,sizeof(ngx_addr_t));
						tmp_addrs[k].socklen = u.addrs[k].socklen;
						ngx_memcpy(tmp_addrs[k].sockaddr->sa_data+2, u.addrs[k].sockaddr->sa_data+2, 4);//前2byte是端口，保留。后4byte是地址，复制
						ngx_pfree(pool,tmp_addrs[k].name.data);
						ngx_sockaddr_2_str(pool,tmp_addrs[k].sockaddr,NULL,&tmp_addrs[k].name);
					}
					srv->addrs = tmp_addrs;
				}
			}
		} else {
			if (uscfp[i]->peer.data != NULL ){
				peers = (ngx_http_upstream_rr_peers_t*)uscfp[i]->peer.data;
//				ngx_str_sch_next_trimtoken(peers->name->data ,peers->name->len ,':',&s_token);
//				ngx_str_sch_next_trimtoken(s_token.data ,s_token.len ,'/',&s_token);
				if( peers->name->len > 0 && ngx_str_cmp(peers->name,dn) == 0 ) {
					if(peers->number < u.naddrs) {
						//
					}
					size_t k=0 ;
					for( peer = peers->peer ; peer ; peer = peer->next, k++) {
						peer->socklen = u.addrs[k].socklen;
						ngx_memcpy(peer->sockaddr->sa_data+2, u.addrs[k].sockaddr->sa_data+2, 4);//前2byte是端口，保留。后4byte是地址，复制
						ngx_pfree(pool,peer->name.data);
						ngx_sockaddr_2_str(pool,peer->sockaddr,NULL,&peer->name);
					}
				}
			}
		}*/
	}
	//
	/*if (check_peers_ctx == NULL) {
		return NGX_ERROR;
	}

	p = check_peers_ctx->peers.elts;

	//将新解析的地址sockaddr，重新置回peer中
	//sockaddr->sa_data 共14个字节，前2个byte是端口，后面4个byte是ip，剩下的byte保留没有作用
	for (i =0 ; i < check_peers_ctx->peers.nelts ; i++){
		pr = p[i].peer_mem_addr;
		s_token.len = 0;
		ngx_str_sch_next_trimtoken(pr->server.data ,pr->server.len ,':',&s_token);
		if( s_token.len > 0 && ngx_str_cmp(&s_token,dn) == 0 ){
			pr->socklen = u.socklen;
			ngx_memcpy(pr->sockaddr->sa_data+2, u.sockaddr.sockaddr.sa_data+2, 4);//前2byte是端口，保留。后4byte是地址，复制
		}
	}*/

	return NGX_OK;
}


/** partA */
ngx_str_t                  arg_cf=ngx_string("conf") , ip = ngx_string("ip"), tab = ngx_string("\t") , arg_fl=ngx_string("file");
u_char 					*s_t;
ngx_str_t                  val_tmp;
ngx_str_t                  *con;

#ifdef NGX_HTTP_REQUEST_LOG
static void make_request_log_filename(ngx_str_t *fl, ngx_pool_t *pool)
{
	size_t sz;
	u_char *snm, *nm;
	sz = fl->len+ngx_num_bit_count(ngx_pid)+1;
	snm = nm = ngx_palloc(pool,sz);//tail is "."
	ngx_memzero(nm,sz);
	nm = ngx_strcat(nm,fl->data,fl->len);
	nm = ngx_strcat(nm,(u_char*)".",1);
	ngx_int_to_str2(nm,ngx_pid);
	fl->data = snm; //ac.log.[pid]
	fl->len = sz;
}
#endif

static ngx_int_t
ngx_http_endpoint_do_get(ngx_http_request_t *r, ngx_array_t *resource)
{
    ngx_int_t                  rc,status;
    ngx_chain_t                out;
    ngx_str_t                  *value, errmsg;
	size_t					buf_sz = 0;
	ngx_buf_t	 				*buf;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    con = NULL;
    out.next = NULL;
    if (resource->nelts == 0) {
        return NGX_HTTP_NOT_FOUND;
    }

    value = resource->elts;

    if (value[0].len == 4 && ngx_strncasecmp(value[0].data, (u_char *)"list", 4) == 0) {
#ifdef NGX_HTTP_UPSTREAM_XFDF_IP_HASH
        con = ngx_xfdf_list_upstreams(r->pool);
//        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "-- %l ---%V----",con->len, con);
        if (con != NULL && con->len >0 ) {
        	buf_sz = ngx_http_out_content(r->pool,con,&out,1);
        }
#endif
    } else if(value[0].len == 4 && ngx_strncasecmp(value[0].data, (u_char *)"down", 4) == 0) {
#ifdef NGX_HTTP_UPSTREAM_XFDF_IP_HASH
    	rc = -1;
    	ngx_str_t *up,*sr;
        if( resource->nelts == 3  ){
            up = &value[1]; //upstream
            sr = &value[2]; //server
            rc = 1;
        }
        if( resource->nelts == 4  ) {
            up = &value[1]; //upstream
            sr = &value[2]; //server
            if(ngx_strncasecmp(value[3].data, (u_char *)"log", 3) == 0) {
                rc = 2;
            }
        }
        if(rc > 0) {
        	s_t = sr->data;
            while(s_t){
            	s_t = ngx_str_sch_next_trimtoken(sr->data ,sr->len ,',',&val_tmp);
				ngx_xfdf_deal_server(up,&val_tmp,rc);
				if(s_t != NULL){
					sr->len = sr->len - (s_t - sr->data);
					sr->data = s_t;
				}
            }
//            ngx_xfdf_deal_server(up,sr,1);
            buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        }
#endif
    } else if(value[0].len == 2 && ngx_strncasecmp(value[0].data, (u_char *)"up", 2) == 0) {
#ifdef NGX_HTTP_UPSTREAM_XFDF_IP_HASH
        if( resource->nelts == 3  ){
            ngx_str_t *up = &value[1]; //upstream
            ngx_str_t *sr = &value[2]; //server
            s_t = sr->data;
			while(s_t){
				s_t = ngx_str_sch_next_trimtoken(sr->data ,sr->len ,',',&val_tmp);
				ngx_xfdf_deal_server(up,&val_tmp,0);
				if(s_t != NULL){
					sr->len = sr->len - (s_t - sr->data);
					sr->data = s_t;
				}
			}
            //
            buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        }
#endif
    } else if(value[0].len == 7 && ngx_strncasecmp(value[0].data, (u_char *)"nocheck", 7) == 0) {
#ifdef NGX_HTTP_UPSTREAM_XFDF_IP_HASH
        if( resource->nelts == 3  ){
            ngx_str_t *up = &value[1]; //upstream
            ngx_str_t *sr = &value[2]; //server
            s_t = sr->data;
			while(s_t){
				s_t = ngx_str_sch_next_trimtoken(sr->data ,sr->len ,',',&val_tmp);
				ngx_xfdf_deal_server(up,&val_tmp,3);
				if(s_t != NULL){
					sr->len = sr->len - (s_t - sr->data);
					sr->data = s_t;
				}
			}
            //
			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        }
#endif
    } else if(value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"weight", 6) == 0) {
#ifdef NGX_HTTP_UPSTREAM_XFDF_IP_HASH
        if( resource->nelts == 4  ){
            ngx_str_t *up = &value[1]; //upstream
            ngx_str_t *sr = &value[2]; //server
            ngx_str_t *wt = &value[3]; //weight
            ngx_int_t w = ngx_atoi(wt->data, wt->len);
            if(w < 0) {
				ngx_msg_str(errmsg,(u_char*)"weight error!!!");
				buf_sz = ngx_http_out_content(r->pool,&errmsg,&out,1);
				goto tail;
			}
            ngx_xfdf_deal_peer_weight(up,sr,(ngx_uint_t)w);
            sr = ngx_xfdf_peer_server(up, sr); //
            update_dyn_up_srv_wt(up, sr, w);
            buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        }
#endif
    } else if (value[0].len == 9 && ngx_strncasecmp(value[0].data, (u_char *)"variables", 9) == 0 ) {
#ifdef NGX_HTTP_UPSTREAM_CHECK
    	if( resource->nelts == 2 ){
    		ngx_str_t *varname = &value[1]; //variable name
        	ngx_str_t f;
            ngx_http_get_param_value(r,arg_cf.data , arg_cf.len , &f);
        	if(f.len >0 ){
    			f.data = (u_char*)ngx_strcopy(r->pool,&f);
    			ngx_reload_var_conf(&f,varname);
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
			}
    	}else if( resource->nelts == 3 &&  value[2].len == 4 && ngx_strncasecmp(value[2].data, (u_char *)"list", 4) == 0){
			ngx_str_t *varname = &value[1]; //variable name
			out.buf = ngx_list_var(r->pool,varname);
			out.buf->last_buf = 1;
			out.next = NULL;
			buf_sz = ngx_buf_size(out.buf);
    	}
#endif
	} else if (value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"region", 6) == 0 ) {
#ifdef NGX_HTTP_UPSTREAM_CHECK
    	if( resource->nelts == 2 ){ // /region/[upstream]?conf=...
    		ngx_str_t *upstream = &value[1]; //upstream name
        	ngx_str_t f;
            ngx_http_get_param_value(r,arg_cf.data , arg_cf.len , &f);
        	if(f.len >0 ){
    			f.data = (u_char*)ngx_strcopy(r->pool,&f);
    			ngx_reload_region_conf(&f,ngx_str_2_hash(upstream));
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        	}
    	}
    	//
    	if( resource->nelts == 4 ){ // /region/[upstream]/[name]/[region]
    		ngx_str_t *upstream = &value[1]; //upstream name
    		ngx_str_t *srnm = &value[2]; //name
    		ngx_int_t rg;
    		ngx_http_upstream_rr_peer_t *p;
    		rg = ngx_atoi(value[3].data,value[3].len); //region
			if(rg == NGX_ERROR) {
				ngx_msg_str(errmsg,(u_char*)"region error!!!");
				buf_sz = ngx_http_out_content(r->pool,&errmsg,&out,1);
				goto tail;
			}
			//
			p = ngx_xfdf_deal_server_get_peer(NULL, upstream, srnm);
			if( p != NULL){
				ngx_set_region(ngx_str_2_hash(upstream), &p->server, rg);
				srnm = ngx_xfdf_peer_server(upstream, srnm); //
				update_dyn_up_srv_rg(upstream, srnm, rg);
				buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
			}
    	}
#endif
    } else if (value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"router", 6) == 0 ) {
#ifdef NGX_HTTP_UPSTREAM_CHECK
    	if( resource->nelts == 2 ){
    		ngx_str_t *router_name = &value[1]; //router name
        	ngx_str_t f;
            ngx_http_get_param_value(r,arg_cf.data , arg_cf.len , &f);
        	if(f.len >0 ){
    			f.data = (u_char*)ngx_strcopy(r->pool,&f);
    			ngx_reload_router(r->pool,router_name ,&f);
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        	}
    	} else if( resource->nelts == 4 ){// /router/[name]/[add|exist|get]/[variable]
    		ngx_str_t *router_name = &value[1]; //router name
    		if( value[2].len == 9 && ngx_strncasecmp(value[2].data, (u_char *)"variables", 9) == 0
    			&& value[3].len == 4 && ngx_strncasecmp(value[3].data, (u_char *)"list", 4) == 0 ){// /router/[name]/variables/list
    			buf = ngx_list_router_var(r->pool,router_name);
    			buf_sz = ngx_http_chain_content(buf, &out);
    		} else if( value[2].len == 3 && ngx_strncasecmp(value[2].data, (u_char *)"add", 3) == 0){
    			ngx_str_t *v = &value[3];
    			ngx_set_router_variable(r->pool ,router_name,v);
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
    		} else if( value[2].len == 5 && ngx_strncasecmp(value[2].data, (u_char *)"exist", 5) == 0){
    			ngx_str_t *v = &value[3];
    			char rn[4];
    			rc = ngx_get_router_variable_region(router_name,v);
    			sprintf(rn,"%ld",rc);
    			val_tmp.data = (u_char*)rn;
    			val_tmp.len = strlen(rn);
    			buf_sz = ngx_http_out_content(r->pool,&val_tmp,&out,1);
    		} else if( value[2].len == 3 && ngx_strncasecmp(value[2].data, (u_char *)"get", 3) == 0){
    			ngx_chain_t out_1,out_2;
    			ngx_str_t *v = &value[3];
    			ngx_str_t v_tmp;
    			out_1.next = NULL;
    			out_2.next = NULL;
    			v_tmp.len = 0;
				char rn[4];
				rc = ngx_router_key_get_region(router_name,v,&v_tmp);
				sprintf(rn,"%ld",rc);
				val_tmp.data = (u_char*)rn;
				val_tmp.len = strlen(rn);
				buf_sz = ngx_http_out_content(r->pool,&val_tmp,&out,0);
				ngx_append(&out,&out_1);
				buf_sz += ngx_http_out_content(r->pool,&tab,&out_1,0);
				ngx_append(&out_1,&out_2);
				buf_sz += ngx_http_out_content(r->pool,&v_tmp,&out_2,1);
    		}
    	}/*else if( resource->nelts == 5 ){// /router/[name]/index/remove/[key]
    		ngx_str_t *router_name = &value[1]; //router name
    		if( value[3].len == 6 && ngx_strncasecmp(value[3].data, (u_char *)"remove", 6) == 0){
    			ngx_str_t *idxt = &value[2]; //variable index
    			ngx_uint_t idx = ngx_atoi(idxt->data, idxt->len);
    			ngx_str_t *k = &value[4];
    			ngx_add_router_item(r->pool ,router_name,idx,k);
    			buf = append_printf(r->pool, &sucs);
    		}
    	}*/else if( resource->nelts == 6 ){// /router/[name]/index/add/[key]/[value]
    		ngx_str_t *router_name = &value[1]; //router name
    		if( value[3].len == 3 && ngx_strncasecmp(value[3].data, (u_char *)"add", 3) == 0){
    			ngx_str_t *idxt = &value[2]; //variable index
    			ngx_int_t idx = ngx_atoi(idxt->data, idxt->len);
    			if(idx < 0) {
					ngx_msg_str(errmsg,(u_char*)"index error!!!");
					buf_sz = ngx_http_out_content(r->pool,&errmsg,&out,1);
					goto tail;
				}
    			ngx_str_t *k = &value[4];
    			ngx_str_t *v = &value[5];
    			ngx_add_router_item(r->pool ,router_name,(ngx_uint_t)idx,k,ngx_atoi(v->data, v->len));
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
    		}
    	}
#endif
    } else if (value[0].len == 7 && ngx_strncasecmp(value[0].data, (u_char *)"address", 7) == 0 ) {
#ifdef NGX_HTTP_UPSTREAM_CHECK
    	if( resource->nelts == 2  ){
    	    ngx_str_t address;
			ngx_http_get_param_value(r,ip.data , ip.len , &address);
			if(address.len > 0){
				ngx_str_t *opt = &value[1];//deny or allow
				if (ngx_strncasecmp(opt->data, (u_char *)"deny", 4) == 0){
					ngx_http_add_address_rule(r,&address,1);
				} else if (ngx_strncasecmp(opt->data, (u_char *)"allow", 5) == 0){
					ngx_http_add_address_rule(r,&address,0);
				}
				buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
			}
    	} else if( resource->nelts == 3  ){
    		if (ngx_strncasecmp(value[1].data, (u_char *)"deny", 4) == 0){
				if (ngx_strncasecmp(value[2].data, (u_char *)"list", 4) == 0){
					con = ngx_http_deny_list(r->pool);
					if (con != NULL) {
						buf_sz = ngx_http_out_content(r->pool,con,&out,1);
					}
				}
    		}
    	}
#endif
    } else if(value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"domain", 6) == 0) {// /domain/resolve/[fx.com|all]
    	if( resource->nelts == 3 ){
			if (value[1].len == 7 && ngx_strncasecmp(value[1].data, (u_char *)"resolve", 7) == 0){
				ngx_str_t *dn = &value[2]; //domain name
				if (dn->len == 3 && ngx_strncasecmp(dn->data, (u_char *)"all", 3) == 0){
					//
				}else {
					ngx_channel_msg *msg;
					buf_sz = ngx_get_msg(&msg,r->connection->pool,dn->data,dn->len,dn_msg_handler);
					ngx_broadcast_processes(msg,buf_sz,r->connection->log, -1);
					if (ngx_http_endpoint_reslove_dn(ngx_cycle->pool,dn) == NGX_OK) {
						buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
					} else {
						buf_sz = ngx_http_out_content(r->pool,&fail,&out,1);
					}
					ngx_http_endpoint_item_shm_process_directive((u_char*)shm_process->dns.dns,&shm_process->dns.count,max_dns,max_dns_len,dn);
					/*ngx_uint_t i;
					for( i = 0; i < max_dns ; i++) {
						u_char *d = shm_process->dns.dns[i];
						if(d[0] == '\0') {
							ngx_memcpy(d, dn->data, dn->len);
							shm_process->dns.count++;
							break;
						}
						if( dn->len == strlen((char*)d) && ngx_strncmp(dn->data , d, dn->len) == 0){
							break;
						}
					}*/
				}
			}
    	}
    	goto tail;
    } else if(ngx_str_cmp2(&value[0],"waf") == 0) { // waf
		#ifdef NGX_HTTP_WAF_MODULE
    	ngx_str_t on = ngx_string("on");
    	ngx_str_t off = ngx_string("off");
    	ngx_str_t *nm = &value[2], *tmp_nm;
		ngx_http_waf_loc_conf_t **wcf = NULL ;
		size_t i = 0;
		ngx_channel_msg *msg;
		for(; i < waf_env_conf.count ; i++) {
			tmp_nm = waf_env_conf.name->elts;
			if (ngx_str_cmp(&tmp_nm[i],nm) == 0){
				wcf = waf_env_conf.waf_cf->elts;
				break;
			}
		}
		if( resource->nelts == 3) {
			if( ngx_str_cmp2(&value[1],"show") == 0 ){
				if (wcf != NULL) { // /waf/show/[name]
					if (wcf != NULL) {
						ngx_str_t *rst ;
						rst = (wcf[i]->waf == 1)? &on : &off;
						buf_sz = ngx_http_out_content(r->pool,rst,&out,1);
					}else {
						buf_sz = ngx_http_out_content(r->pool,&fail,&out,1);
					}
				}
			} else if( (ngx_str_cmp2(&value[1],"enable") == 0 || ngx_str_cmp2(&value[1],"disable") == 0)) {// /waf/[enable|disable]/[name]
				if (wcf != NULL) {
					wcf[i]->waf = (ngx_str_cmp2(&value[1],"enable") == 0) ;
					waf_data	data;
					ngx_memzero(&data, sizeof(waf_data));
					data.waf_cnf = wcf[i];
					ngx_memcpy(data.flag,&wcf[i]->waf,sizeof(ngx_int_t));
					buf_sz = ngx_get_msg(&msg,r->connection->pool,&data,sizeof(waf_data),waf_onoff_msg_handler);
					ngx_broadcast_processes(msg,buf_sz,r->connection->log, -1);
					for(ngx_int_t j = 0; j < max_waf_item_len; j++) {
						if(shm_process->ws.waf_addrs[j] == 0) {
							shm_process->ws.waf_addrs[j] = (uintptr_t)wcf[i];
							shm_process->ws.onff[j] = wcf[i]->waf;
							break;
						}else if(shm_process->ws.waf_addrs[j] == (uintptr_t)wcf[i]) {
							shm_process->ws.onff[j] = wcf[i]->waf;
							break;
						}
					}
				}
				buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
			}
		}else if( resource->nelts == 4 ) { // /waf/reload/[name]/ipv4
			if( ngx_str_cmp2(&value[1],"reload") == 0 ) {
				ngx_conf_t cnf;
//				cnf.pool = ngx_cycle->pool;
//				cnf.log = ngx_cycle->log;
//				cnf.conf_file = NULL;
				cnf.pool = NULL;
				cnf.log = r->connection->log;
				cnf.conf_file = NULL;
	//    		if( ngx_str_cmp2(&value[3],NGX_HTTP_WAF_IPV4_FILE) == 0 ) {
				if (wcf != NULL){
					waf_data	data;
					ngx_memzero(&data, sizeof(waf_data));
					data.waf_cnf = wcf[i];
					ngx_memcpy(data.flag,value[3].data,value[3].len);
					buf_sz = ngx_get_msg(&msg,r->pool,&data,sizeof(waf_data),waf_reload_msg_handler);
					ngx_broadcast_processes(msg,buf_sz,r->connection->log, -1);
					//TODO 访问加锁防止清除旧数据时有进程的访问
					if(ngx_http_waf_reload(&cnf,wcf[i],data.flag) != NGX_OK) {
						ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "waf: reload [%V] error ",&value[3]);
						buf_sz = ngx_http_out_content(r->pool,&fail,&out,1);
						goto tail;
					}
					ngx_http_endpoint_item_shm_process_directive((u_char*)shm_process->wfs.waf_item,&shm_process->wfs.count,max_waf_item,max_waf_item_len,&value[3]);
				}
    		} else if( ngx_str_cmp2(&value[1],"reloadmode") == 0 ) {
    			if (wcf != NULL){
    				waf_data	data;
					ngx_memzero(&data, sizeof(waf_data));
					data.waf_cnf = wcf[i];
					ngx_memcpy(data.flag,value[3].data,value[3].len);
					buf_sz = ngx_get_msg(&msg,r->pool,&data,sizeof(waf_data),waf_reload_mode_handler);
					ngx_broadcast_processes(msg,buf_sz,r->connection->log, -1);
    				if(ngx_http_waf_mode_reload(&value[3],1,wcf[i]) == NGX_ERROR) {
    					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "waf: reload mode [%V] error ",&value[3]);
    					buf_sz = ngx_http_out_content(r->pool,&fail,&out,1);
    					goto tail;
    				}
    				ngx_http_endpoint_item_shm_process_directive((u_char*)shm_process->wfms.waf_mode,&shm_process->wfms.count,max_waf_item,max_waf_item_len,&value[3]);
    			}
    		}
			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
    	}
		#endif
		//		buf = append_printf(r->pool, &sucs);
	} else if(ngx_str_cmp2(&value[0],"log") == 0) {
#ifdef NGX_HTTP_REQUEST_LOG
		if( resource->nelts == 2){
			if(ngx_str_cmp2(&value[1],"print") == 0) { // /log/print?file=ac.log
				ngx_str_t f;
				size_t sz;
				ngx_http_get_param_value(r, arg_fl.data, arg_fl.len, &f);
				if(f.len >0 ){
					sz = f.len;
					f.data = (u_char*)ngx_strcopy(r->pool,&f);
					f.len = sz;
					make_request_log_filename(&f,r->pool);
					ngx_http_request_log_print(&f,r);
					//
					ngx_channel_msg *msg;
					f.len = sz ;
					buf_sz = ngx_get_msg(&msg,r->connection->pool,f.data,f.len,request_log_msg_handler);
					ngx_broadcast_processes(msg,buf_sz,r->connection->log, -1);
					//
					buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
				}
			} else if(ngx_str_cmp2(&value[1],"disable") == 0) { // /log/disable
				ngx_http_request_log_disable();
				ngx_channel_msg *msg;
				buf_sz = ngx_get_msg(&msg,r->connection->pool,NULL,0,request_log_disable_handler);
				ngx_broadcast_processes(msg,buf_sz,r->connection->log, -1);
				buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
			} else if(ngx_str_cmp2(&value[1],"enable") == 0) { // /log/enable
				ngx_http_request_log_enable();
				ngx_channel_msg *msg;
				buf_sz = ngx_get_msg(&msg,r->connection->pool,NULL,0,request_log_enable_handler);
				ngx_broadcast_processes(msg,buf_sz,r->connection->log, -1);
				buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
			}
		}
#endif
		if( resource->nelts == 3){
			if(ngx_str_cmp2(&value[1],"debug") == 0) {
				if(ngx_str_cmp2(&value[2],"disable") == 0) { // /log/debug/disable
					shm_process->debug_log = 0;
					buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
				} else if(ngx_str_cmp2(&value[2],"enable") == 0) { // /log/debug/enable
					shm_process->debug_log = 1;
					buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
				}
			}
		}
	} else if(resource->nelts == 5 && ngx_str_cmp2(&value[0],"add") == 0 ) { //  /add/[upstream]/[host]/[region]/[weight]
		ngx_channel_msg *msg;
		ngx_int_t rg,wt;
		rg = ngx_atoi(value[3].data,value[3].len); //region
		if(rg == NGX_ERROR) {
			ngx_msg_str(errmsg,(u_char*)"region error!!!");
			buf_sz = ngx_http_out_content(r->pool,&errmsg,&out,1);
			goto tail;
		}
		wt = ngx_atoi(value[4].data,value[4].len); //weight
		if(wt == NGX_ERROR) {
			ngx_msg_str(errmsg,(u_char*)"weight error!!!");
			buf_sz = ngx_http_out_content(r->pool,&errmsg,&out,1);
			goto tail;
		}
		//发送给第0位的进程，由此进程处理完毕再广播到其它进程，避免进程锁的使用
		buf_sz = ngx_get_msg(&msg,r->pool,r->uri.data,r->uri.len,up_srv_main_add_msg_handler);
//		_up_srv_main_add_msg_handler(&r->uri);
		ngx_broadcast_processes(msg,buf_sz,r->connection->log,1);
/*
		ngx_str_t *up,*sv;
		ngx_int_t rg,wt,idx;
		ngx_http_upstream_srv_conf_t *us;
		ngx_http_upstream_rr_peer_t *p;
		up = &value[1]; //upstream
		sv = &value[2]; //server
		rg = ngx_atoi(value[3].data,value[3].len); //region
		if(rg < 0) {
			ngx_msg_str(errmsg,(u_char*)"region error!!!");
			buf_sz = ngx_http_out_content(r->pool,&errmsg,&out,1);
			goto tail;
		}
		wt = ngx_atoi(value[4].data,value[4].len); //weight
		if(wt < 0) {
			ngx_msg_str(errmsg,(u_char*)"weight error!!!");
			buf_sz = ngx_http_out_content(r->pool,&errmsg,&out,1);
			goto tail;
		}
		//新增peer
		p = ngx_xfdf_add_upstream_peer(up,sv,wt);
		if( p != NULL) {
			ngx_channel_msg *msg;
			us = ngx_xfdf_get_upstream_srv_conf(up);
			idx = ngx_http_upstream_check_add_check_peer(us, p);
	//		ngx_http_upstream_check_add_peer(cf, us, peer);
			//共享内存shm_peer
			ngx_http_upstream_check_add_shm_peer(idx, rg, wt);
			//
			buf_sz = ngx_get_msg(&msg,r->pool,r->uri.data,r->uri.len,up_srv_add_msg_handler);
			ngx_broadcast_processes(msg,buf_sz,r->connection->log, -1);
			//
			ngx_http_endpoint_item_shm_process_directive((u_char*)shm_process->dus.up_srvs,
					&shm_process->dus.count,
					max_dyn_up_srv,
					max_dyn_up_srv_len,
					&r->uri);
		}*/
		buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
	} else if(resource->nelts == 3 && ngx_str_cmp2(&value[0],"remove") == 0) { //  /remove/[upstream]/[host]
		ngx_channel_msg *msg;
		buf_sz = ngx_get_msg(&msg,r->pool,r->uri.data,r->uri.len,up_srv_main_remove_msg_handler);
		//发送给第0位的进程，由此进程处理完毕再广播到其它进程，避免进程锁的使用
//		_up_srv_main_remove_msg_handler(&r->uri);
		ngx_broadcast_processes(msg,buf_sz,r->connection->log, 1);
		buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
		/*ngx_str_t *up, *sv, dr;
		ngx_channel_msg *msg;
		ngx_int_t	idx;
		up = &value[1]; //upstream
		sv = &value[2]; //server

		//rr_peer xfdf_peer shm_peer check_peer 清除消息
		//rr_peer xfdf_peer check_peer
		idx = remove_up_srv(up, sv);
		if( idx == -2 ) {
			ngx_msg_str(errmsg,(u_char*)"has't such rr peer error!!!");
			buf_sz = ngx_http_out_content(r->pool,&errmsg,&out,1);
		} else if( idx <= 0 ) {
			ngx_msg_str(errmsg,(u_char*)"has't such check peer error!!!");
			buf_sz = ngx_http_out_content(r->pool,&errmsg,&out,1);
		} else {
			//广播到其它进程执行删除任务
			buf_sz = ngx_get_msg(&msg,r->pool,r->uri.data,r->uri.len,up_srv_remove_msg_handler);
			ngx_broadcast_processes(msg,buf_sz,r->connection->log, -1);
			//shm_peer
			ngx_http_upstream_check_remove_shm_peer(idx);
			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
			//
			dr.data = r->uri.data + 7; // strlen("/remote") == 7
			dr.len = r->uri.len - 7;
			//清除消息
			ngx_http_endpoint_item_shm_process_remove_directive((u_char*)shm_process->dus.up_srvs,
								&shm_process->dus.count,
								max_dyn_up_srv,
								max_dyn_up_srv_len,
								&dr, 1);
		}*/
	}
	else if(value[0].len == 5 && ngx_strncasecmp(value[0].data, (u_char *)"limit", 5) == 0) {
		#ifdef NGX_HTTP_REQUEST_CHAIN
    	    ngx_str_t s=ngx_string("$proxy_add_x_forwarded_for , zone=bus_r:1m , rate=2r/s ,burst=1,location=/store/");
    		ngx_http_request_chain_limit_zone(r,&s);
		#endif
//		buf = append_printf(r->pool, &sucs);
    	buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
    }

tail:
//    if( buf !=NULL && ngx_buf_size(buf) == 0) {
    if( buf_sz == 0 ) {
        status = NGX_HTTP_NO_CONTENT;
    } else {
    	status = NGX_HTTP_OK;
//        status = buf ? NGX_HTTP_OK : NGX_HTTP_NOT_FOUND;
    }

    r->headers_out.status = status;

    if (status != NGX_HTTP_OK) {
        r->headers_out.content_length_n = 0;
    } else {
//        r->headers_out.content_length_n = ngx_buf_size(buf);
        r->headers_out.content_length_n = buf_sz;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    if (status != NGX_HTTP_OK) {
        return ngx_http_send_special(r, NGX_HTTP_FLUSH);
    }

//    buf->last_buf = (out.next == NULL);
//    out.buf = buf;
//    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_endpoint_handler(ngx_http_request_t *r)
{
    ngx_array_t  *res;
    res = ngx_parse_path(r->pool, &r->uri);
    return ngx_http_endpoint_do_get(r, res);
}

static char *
ngx_http_endpoint(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_endpoint_handler;

    return NGX_CONF_OK;
}

static char *
ngx_http_var_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    #if (NGX_HTTP_UPSTREAM_CHECK)
    if(cf->args->nelts > 1){
    	ngx_uint_t i ,j;
        ngx_str_t *value = cf->args->elts ,*val ,v_n,v_cf;
    	for(i=1; i<cf->args->nelts; ){
    		val = &value[i];
    		for(j=1;j < val->len-1 ;j++){
    			//has a configure file
    			if(val->data[j] == '='){
    				v_n.data=val->data;
    				v_n.len=j;
    				v_cf.data=&val->data[j+1];
    				v_cf.len=val->len-j-1;
    				v_cf.data = (u_char*)ngx_strcopy(cf->pool,&v_cf);
    				ngx_http_upstream_check_add_variable(cf,&v_n);
    				ngx_preload_var_conf(&v_n,&v_cf);
    				goto next;
    			}
    		}
    		//if has no configure file
    		ngx_http_upstream_check_add_variable(cf,val);
    		next:
				++i;
    	}
    }
    #endif

    return NGX_CONF_OK;
}

/*
 * 返回一个ngx_channel_msg，传递的消息，由一个2个元素的ngx_channel_msg数组，0是消息头描述了1元素的大小(因为1元素最末的data可能会延伸，所以尺寸不是sizeof(ngx_channel_msg) )
 */
static size_t
ngx_get_msg(ngx_channel_msg **msg, ngx_pool_t *pool, void *data, size_t size , msg_handler handler)
{
	size_t mssz = sizeof(ngx_channel_msg);
	size_t ssz = (size < sizeof(char))? mssz : mssz+size-sizeof(char);
	ngx_channel_msg *msg2, *m;
	m = ngx_palloc(pool, mssz+ssz);
	ngx_memzero(m, mssz+ssz);
	m->cmd = CMD_PAYLOAD_SIZE;
	m->fd = -1 ;
	m->size = ssz;
	msg2 = (ngx_channel_msg*)(m+1);
	msg2->cmd = CMD_PROCESS;
	ngx_memcpy(msg2->data,data,size);
	msg2->size = size;
	msg2->handler = handler;

	*msg = m;
	//
	return mssz+ssz;
}

#ifdef NGX_HTTP_REQUEST_LOG
static ngx_int_t request_log_disable_handler(void *msg, ngx_str_t *emsg)
{
	ngx_http_request_log_disable();
	emsg->data = (u_char*)"request_log_disable_handler";
	emsg->len = strlen((char*)emsg->data);
	return NGX_OK;
}

static ngx_int_t request_log_enable_handler(void *msg, ngx_str_t *emsg)
{
	ngx_http_request_log_enable();
	emsg->data = (u_char*)"request_log_enable_handler";
	emsg->len = strlen((char*)emsg->data);
	return NGX_OK;
}

static ngx_int_t request_log_msg_handler(void *msg, ngx_str_t *emsg)
{
	ngx_http_request_t r;
	ngx_connection_t  c;
	ngx_channel_msg *m = msg;
	ngx_str_t f;
	f.data = (u_char*)m->data;
	f.len = m->size;
	make_request_log_filename(&f,ngx_cycle->pool);
	//
	r.connection = &c;
	r.pool = ngx_cycle->pool;
	r.connection->log = ngx_cycle->log;
	r.start_sec = 0;
	ngx_http_request_log_print(&f,&r);
	emsg->data = (u_char*)"request_log_msg_handler";
	emsg->len = strlen((char*)emsg->data);
	return NGX_OK;
}
#endif
static ngx_int_t dn_msg_handler(void *msg, ngx_str_t *emsg)
{
	ngx_channel_msg *m = msg;
	ngx_str_t dn;
	dn.data = (u_char*)m->data;
	dn.len = m->size;
	emsg->data = (u_char*)"dn_msg_handler";
	emsg->len = strlen((char*)emsg->data);
	return ngx_http_endpoint_reslove_dn(ngx_cycle->pool,&dn);
}

static void
parse_up_srv_from_uri(ngx_str_t *s, /*out*/ngx_str_t *up, ngx_str_t *sv, ngx_str_t *swt, ngx_str_t *srg)
{
	ngx_str_sch_idx_trimtoken(s->data, s->len, '/', 1, up);
	ngx_str_sch_idx_trimtoken(s->data, s->len, '/', 2, sv);
	ngx_str_sch_idx_trimtoken(s->data, s->len, '/', 3, srg);
	ngx_str_sch_idx_trimtoken(s->data, s->len, '/', 4, swt);
}

static ngx_int_t add_up_srv(ngx_str_t *up, ngx_str_t *sv, ngx_str_t *swt, ngx_str_t *srg, ngx_int_t idx)
{
	ngx_int_t wt;
	ngx_http_upstream_srv_conf_t *us;
	ngx_http_upstream_rr_peer_t *p;

//	rg = ngx_atoi(srg->data,srg->len); //region
	wt = ngx_atoi(swt->data,swt->len); //weight
	//新增peer
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=1================ %d", ngx_pid);
	p = ngx_xfdf_add_upstream_peer(up, sv, wt, idx);
	if( p != NULL) {
		us = ngx_xfdf_get_upstream_srv_conf(up);
		ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=2================ %d", ngx_pid);
		idx = ngx_http_upstream_check_add_check_peer(us, p, idx);
		ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=3================ %d", ngx_pid);
		ngx_http_upstream_append_peer(up, p);
	}
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=4================ %d", ngx_pid);
	return idx;
}

static ngx_int_t _up_srv_add_msg_handler(ngx_str_t *s)
{
	ngx_str_t up, sv, swt, srg;
	ngx_int_t idx;
	parse_up_srv_from_uri(s, &up, &sv, &swt, &srg);
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-process add start------------------------ %d %V", ngx_pid, &sv);
	idx = add_up_srv(&up, &sv, &swt, &srg, -1);
	if( idx >= 0) {
		ngx_http_upstream_check_add_timers((ngx_cycle_t*)ngx_cycle, idx, idx);
	}
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-process add end------------------------ %d %V", ngx_pid, &sv);
	return idx;
}

static ngx_str_t* get_dyn_up_srv(ngx_str_t *s, ngx_str_t *up, ngx_str_t *sr)
{
	ngx_uint_t i;
	ngx_str_t sup, ssr;
	for( i = 0 ; i < shm_process->dus.count ; i++) {
		s->data = shm_process->dus.up_srvs[i];
		s->len = strlen((char*)shm_process->dus.up_srvs[i]);
		ngx_str_sch_idx_trimtoken(s->data, s->len, '/', 1, &sup);
		ngx_str_sch_idx_trimtoken(s->data, s->len, '/', 2, &ssr);
		if (ngx_str_cmp(&sup, up) == 0 && ngx_str_cmp(&ssr, sr) == 0) {
			return s;
		}
	}
	s->len = 0;
	return s;
}

static void update_dyn_up_srv_arg(ngx_str_t *up, ngx_str_t *sr, ngx_str_t *ar, ngx_int_t pos)
{
	ngx_str_t s;
	get_dyn_up_srv(&s, up, sr);
	if (s.len > 0) {
		ngx_str_replace_pos(s.data, '/', pos, ar->data, ar->len);
	}
}

static void update_dyn_up_srv_wt(ngx_str_t *up, ngx_str_t *sr, ngx_int_t w)
{
	ngx_str_t s;
	s.data = ngx_int_to_str(ngx_cycle->pool, w);
	s.len = ngx_num_bit_count(w);
	update_dyn_up_srv_arg(up, sr, &s, 4);
	ngx_pfree(ngx_cycle->pool, s.data);
//	ngx_str_t s, srg, swt;
//	get_dyn_up_srv(&s, up, sr);
//	if( s.len > 0) {
//		ngx_str_sch_idx_trimtoken(s.data, s.len, '/', 3, &srg);
//		ngx_str_sch_idx_trimtoken(s.data, s.len, '/', 4, &swt);
//		ngx_memzero(swt.data, swt.len);
//		ngx_int_to_str2(swt.data, w);
//	}
}

static void update_dyn_up_srv_rg(ngx_str_t *up, ngx_str_t *sr, ngx_int_t r)
{
	ngx_str_t s;
	s.data = ngx_int_to_str(ngx_cycle->pool, r);
	s.len = ngx_num_bit_count(r);
	update_dyn_up_srv_arg(up, sr, &s, 3);
	ngx_pfree(ngx_cycle->pool, s.data);
//	ngx_str_t s, srg, swt;
//	ngx_int_t wt;
//	u_char *ds;
//	get_dyn_up_srv(&s, up, sr);
//	if( s.len > 0) {
//		ngx_str_sch_idx_trimtoken(s.data, s.len, '/', 3, &srg);
//		ngx_str_sch_idx_trimtoken(s.data, s.len, '/', 4, &swt);
//		wt = ngx_str_to_int(swt.data, swt.len);
//		ngx_memzero(srg.data, srg.len+swt.len+1);
//		ds = srg.data;
//		ngx_int_to_str2(ds, r);
//		ds += ngx_num_bit_count(r);
//		ds = ngx_strcat(ds, (u_char*)"/", 1);
//		ngx_int_to_str2(ds, wt);
//	}
}

void update_dyn_up_srv_dw(ngx_str_t *up, ngx_str_t *sr, ngx_str_t *ar)
{
	update_dyn_up_srv_arg(up, sr, ar, 5); // check_down
}

void update_dyn_up_srv_fdw(ngx_str_t *up, ngx_str_t *sr, ngx_str_t *ar)
{
	update_dyn_up_srv_arg(up, sr, ar, 6); //force_down
}

static ngx_int_t up_srv_add_msg_handler(void *msg, ngx_str_t *emsg)
{
	ngx_channel_msg *m = msg;
	ngx_str_t s;
	ngx_int_t idx;
	s.data = (u_char*)m->data;
	s.len = m->size;
	idx = _up_srv_add_msg_handler(&s);
	emsg->data = (u_char*)"up_srv_add_msg_handler";
	emsg->len = strlen((char*)emsg->data);
	return idx;
}

static ngx_int_t _up_srv_main_add_msg_handler(ngx_str_t *s)
{
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-add start------------------------ %d %V", ngx_pid, s);
	ngx_str_t up, sv, swt, srg;
	ngx_int_t idx, rg, wt ;
	parse_up_srv_from_uri(s, &up, &sv, &swt, &srg);
	if ( (idx = add_up_srv(&up, &sv, &swt, &srg, -1)) >= 0 ) {
		ngx_channel_msg *msg1;
		size_t 	buf_sz = 0;
		u_char	*ch;
		//shm已经被0号进程设置，这里主要是加入定时检测
		rg = ngx_atoi(srg.data,srg.len); //region
		wt = ngx_atoi(swt.data,swt.len); //weight
		ngx_http_upstream_check_add_shm_peer(idx, rg, wt, 0, 0);
		//
		buf_sz = ngx_get_msg(&msg1,ngx_cycle->pool,s->data,s->len,up_srv_add_msg_handler);
		//广播到所有其它进程
//ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "-1b---------------------- %d", ngx_pid);
		ngx_broadcast_processes(msg1,buf_sz,ngx_cycle->log, -1);
		ngx_pfree(ngx_cycle->pool, msg1);

		ch = ngx_http_endpoint_item_shm_process_directive((u_char*)shm_process->dus.up_srvs,
			&shm_process->dus.count,
			max_dyn_up_srv,
			max_dyn_up_srv_len,
			s);
		*ch++ = '/';
		*ch++ = '0'; //check_down
		*ch++ = '/';
		*ch = '0'; //force_down
//		ch++;
//		*((ngx_int_t*)(ch)) = idx; //在shm里的占位
	}
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-add end------------------------ %d %V", ngx_pid, s);
	return NGX_OK;
}

static ngx_int_t up_srv_main_add_msg_handler(void *msg, ngx_str_t *emsg)
{
	ngx_channel_msg *m = msg;
	ngx_str_t s;
	s.data = (u_char*)m->data;
	s.len = m->size;
	emsg->data = (u_char*)"up_srv_main_add_msg_handler";
	emsg->len = strlen((char*)emsg->data);
	return _up_srv_main_add_msg_handler(&s);
}

static ngx_int_t remove_up_srv(ngx_str_t *up, ngx_str_t *sv)
{
	ngx_int_t idx = -2; // -2: has't rr_peer ; -1(NGX_ERROR): hasn't check_peer
	ngx_http_upstream_srv_conf_t *us;
	ngx_http_upstream_rr_peer_t *p;

	//rr_peer xfdf_peer
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=a11================ %d", ngx_pid);
	p = ngx_xfdf_remove_upstream_peer(up, sv);
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=a22================ %d", ngx_pid);
	if( p != NULL) {
		us = ngx_xfdf_get_upstream_srv_conf(up);
		ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=a33================ %d", ngx_pid);
		//check_peer
		idx = ngx_http_upstream_check_remove_check_peer(us, up, p);
		ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=a44================ %d", ngx_pid);
		ngx_http_upstream_release_rr_peer(p);
		ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=a55================ %d", ngx_pid);
	}
	//
	return idx;
}

static ngx_int_t up_srv_remove_msg_handler(void *msg, ngx_str_t *emsg)
{
	ngx_str_t up,sv;
	ngx_int_t idx;
	ngx_channel_msg *m = msg;

	ngx_str_sch_idx_trimtoken((u_char*)m->data, m->size, '/', 1, &up);//upstream
	ngx_str_sch_idx_trimtoken((u_char*)m->data, m->size, '/', 2, &sv);//server

	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-process remove start------------------------ %d %V", ngx_pid, &sv);
	idx = remove_up_srv(&up, &sv);
ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=a66================ %d %d", ngx_pid, idx);
//ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "=33================ %d  %d", ngx_pid, idx);
//	if( idx >= 0) {
//		ngx_http_upstream_check_add_peers_timers(idx);
//	}
ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=a77================ %d %d", ngx_pid, idx);
	emsg->data = (u_char*)"up_srv_remove_msg_handler";
	emsg->len = strlen((char*)emsg->data);
ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=a88================ %d %d", ngx_pid, idx);
ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-process remove end------------------------ %d %V", ngx_pid, &sv);
	return idx;
}

static ngx_int_t _up_srv_main_remove_msg_handler(ngx_str_t *s)
{
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-remove start------------------------ %d %V", ngx_pid, s);
	ngx_str_t up,sv;
	ngx_int_t	idx;
	size_t 	buf_sz = 0;
	//
	ngx_str_sch_idx_trimtoken(s->data, s->len, '/', 1, &up);//upstream
	ngx_str_sch_idx_trimtoken(s->data, s->len, '/', 2, &sv);//server

	//rr_peer xfdf_peer shm_peer check_peer 清除消息
	//rr_peer xfdf_peer check_peer
	if( ngx_xfdf_upstream_peer_is_es(&up, &sv) == 0 ) { //固定的,不是弹性的不能删
		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "peer is not elastic one [%V] [%V]", &up, &sv);
		return -1;
	}
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-2000000000------------------------ %d", ngx_pid);
	ngx_xfdf_down_peer(&up, &sv); //down
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-2100000000------------------------ %d", ngx_pid);
	idx = remove_up_srv(&up, &sv);
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-2------------------------ %d %d", ngx_pid, idx);
	if( idx == -2 ) {
		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no such rr peer error!!! [%V] [%V]", &up, &sv);
	} else if( idx <= 0 ) {
		ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "no such check peer error!!! [%V] [%V]", &up, &sv);
	} else {
		ngx_channel_msg *msg1;
		//shm_peer
		ngx_http_upstream_check_remove_shm_peer(idx);
		//广播到其它进程执行删除任务
		buf_sz = ngx_get_msg(&msg1,ngx_cycle->pool,s->data,s->len,up_srv_remove_msg_handler);
//ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "-2b----------------------- %d %d", ngx_pid, idx);
		ngx_broadcast_processes(msg1,buf_sz,ngx_cycle->log, -1);
		ngx_pfree(ngx_cycle->pool, msg1);
		//
		s->data = s->data + 7; // strlen("/remote") == 7
		s->len = s->len - 7;
		//清除消息
		ngx_http_endpoint_item_shm_process_remove_directive((u_char*)shm_process->dus.up_srvs,
							&shm_process->dus.count,
							max_dyn_up_srv,
							max_dyn_up_srv_len,
							s, 1);
	}
	ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-remove end------------------------ %d %V", ngx_pid, s);
	return idx;
}

static ngx_int_t up_srv_main_remove_msg_handler(void *msg, ngx_str_t *emsg)
{
	ngx_channel_msg *m = msg;
	ngx_str_t s;
	s.data = (u_char*)m->data;
	s.len = m->size;
	emsg->data = (u_char*)"up_srv_main_remove_msg_handler";
	emsg->len = strlen((char*)emsg->data);
	return _up_srv_main_remove_msg_handler(&s);
}

#ifdef NGX_HTTP_WAF_MODULE
static ngx_int_t waf_onoff_msg_handler(void *msg, ngx_str_t *emsg)
{
	ngx_channel_msg *m = msg;
	ngx_http_waf_loc_conf_t *waf_cnf;
	ngx_int_t v;
	waf_data	*wdata = (waf_data*)m->data;
	waf_cnf = wdata->waf_cnf;
	v = *(ngx_int_t*)(&wdata->flag);
	waf_cnf->waf = v;
	emsg->data = (u_char*)"waf_onoff_msg_handler";
	emsg->len = strlen((char*)emsg->data);
	return NGX_OK;
}

static ngx_int_t waf_reload_msg_handler(void *msg, ngx_str_t *emsg)
{
	ngx_channel_msg *m = msg;
	ngx_http_waf_loc_conf_t *waf_cnf;
	waf_data	*wdata = (waf_data*)m->data;
	waf_cnf = wdata->waf_cnf;
	ngx_conf_t cnf;
	cnf.pool = NULL;//ngx_cycle->pool;
	cnf.log = ngx_cycle->log;
	cnf.conf_file = NULL;
	emsg->data = (u_char*)"waf_reload_msg_handler";
	emsg->len = strlen((char*)emsg->data);
	return ngx_http_waf_reload(&cnf,waf_cnf,wdata->flag);
}

static ngx_int_t waf_reload_mode_handler(void *msg, ngx_str_t *emsg)
{
	ngx_channel_msg *m = msg;
	ngx_http_waf_loc_conf_t *waf_cnf;
	waf_data	*wdata = (waf_data*)m->data;
	waf_cnf = wdata->waf_cnf;
	ngx_str_t md;
	md.data = (u_char*)wdata->flag;
	md.len = strlen((char*)wdata->flag);
	emsg->data = (u_char*)"waf_reload_mode_handler";
	emsg->len = strlen((char*)emsg->data);
	return ngx_http_waf_mode_reload(&md,1,waf_cnf);
}
#endif


/* 将消息向所有子进程广播出去
 * pos要发送到哪些指定进程的channel，占位表示法，-1表示所有(除了自身)
 */
ngx_int_t
ngx_broadcast_processes(ngx_channel_msg *data, size_t size, ngx_log_t *log, ngx_int_t pos)
{
	ssize_t             n;
	ngx_err_t           err;
	struct iovec        iov[1];
	struct msghdr       msg;

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)
	union {
		struct cmsghdr  cm;
		char            space[CMSG_SPACE(sizeof(int))];
	} cmsg;

	if (data->fd == -1) {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	} else {
		msg.msg_control = (caddr_t) &cmsg;
		msg.msg_controllen = sizeof(cmsg);
		ngx_memzero(&cmsg, sizeof(cmsg));

		cmsg.cm.cmsg_len = CMSG_LEN(sizeof(int));
		cmsg.cm.cmsg_level = SOL_SOCKET;
		cmsg.cm.cmsg_type = SCM_RIGHTS;

		ngx_memcpy(CMSG_DATA(&cmsg.cm), &data->fd, sizeof(int));
	}

	msg.msg_flags = 0; //1为接收的消息, 0为发送的消息
#else
	if (ch->fd == -1) {
		msg.msg_accrights = NULL;
		msg.msg_accrightslen = 0;
	} else {
		msg.msg_accrights = (caddr_t) &ch->fd;
		msg.msg_accrightslen = sizeof(int);
	}
#endif

	iov[0].iov_base = (char *) data;
	iov[0].iov_len = ngx_max(sizeof(ngx_channel_msg),size);

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	ngx_int_t i, mask = 4294967295 ; //2^32
	if( pos < 0 ){
		for( i = 0; i < ngx_chs->count ; i++) {
			if( i != ngx_args.pos ) {
				n = sendmsg(ngx_chs->chs[i].channel_pair[0], &msg, 0);
				if (n == -1) {
					err = ngx_errno;
					ngx_log_error(NGX_LOG_ALERT, log, err, "ngx_broadcast_processes() failed");
				}
			}
		}
	} else {
		i = 0;
		while( mask & pos ) {
			if( (pos - (pos >> 1 << 1)) > 0 ){ //表示这一位的进程占位为1
				n = sendmsg(ngx_chs->chs[i].channel_pair[0], &msg, 0);
				if (n == -1) {
					err = ngx_errno;
					ngx_log_error(NGX_LOG_ALERT, log, err, "ngx_broadcast_processes() failed");
				}
			}
			pos >>= 1;
			i++;
		}
	}

	return NGX_OK;
}

//epoll_wait唤醒后回调,来接收消息
static void
ngx_endpoint_channel_handler(ngx_event_t *ev)
{
	ngx_channel_msg      *data;
	ngx_connection_t  *c;
	ssize_t			n;
    ngx_err_t           err;
    ngx_int_t			r;
    ngx_str_t			emsg;

	if (ev->timedout) {
		ev->timedout = 0;
		return;
	}

	c = ev->data;

	struct iovec        iov[1];
	struct msghdr       msg;

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)
   union {
	   struct cmsghdr  cm;
	   char            space[CMSG_SPACE(sizeof(int))];
   } cmsg;
#else
   int                 fd;
#endif

   /* 净荷数据的尺寸，因为消息是2个元素的ngx_channel_msg数组，并且1的大小不确定(因为传递应用数据)，用0元素负责表示1元素的大小。
    * 所以第1次设固定尺寸得到0元素，然后根据 0元素的描述得到1元素的尺寸，这样会将一条消息分两次接收
    */
   iov[0].iov_len = (ngx_args.ngx_msg_size > 0) ? ngx_args.ngx_msg_size : sizeof(ngx_channel_msg);
   data = ngx_palloc(ngx_cycle->pool, iov[0].iov_len);
   iov[0].iov_base = (char *)data;

   msg.msg_name = NULL;
   msg.msg_namelen = 0;
   msg.msg_iov = iov;
   msg.msg_iovlen = 1;

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)
   msg.msg_control = (caddr_t) &cmsg;
   msg.msg_controllen = sizeof(cmsg);
#else
   msg.msg_accrights = (caddr_t) &fd;
   msg.msg_accrightslen = sizeof(int);
#endif

	n = recvmsg(c->fd, &msg, 0);
	ngx_args.ngx_msg_size = 0;

	if (n == -1) {
		err = ngx_errno;
		ngx_log_error(NGX_LOG_ERR, ev->log, 0, "ngx_endpoint_channel_handler recvmsg() error : %d ",err);
		goto tail;
	}

	if(data->cmd == CMD_PAYLOAD_SIZE) {//获得消息内容的尺寸
		ngx_args.ngx_msg_size = data->size;
	} else if(data->cmd == CMD_PROCESS ){//处理接收到的消息内容
		if ( (r = data->handler(data, &emsg)) < NGX_OK) {
			ngx_log_error(NGX_LOG_ALERT, ev->log, 0, "ngx_endpoint_channel_handler data->handler():%V error, pid : %l %d",&emsg, ngx_pid, r);
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, ev->log, 0, "ngx_endpoint_channel_handler has no command,pid : %l ",ngx_pid);
	}
tail:
	ngx_pfree(ngx_cycle->pool,data);
}

/** partB */
static ngx_int_t
ngx_http_endpoint_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
	ngx_endpoint_shm_t					*shm_chs;
	size_t							size;
	ngx_shm_zone_t				*oshm_zone;

	oshm_zone = ngx_shared_memory_find((ngx_cycle_t *)ngx_cycle,&shm_endpoint, &ngx_http_endpoint_module);

	if(oshm_zone != NULL) {
//		shm_process = oshm_zone->data;
	} else {
		if(shpool != NULL && shm_process != NULL) {
			ngx_slab_free(shpool,shm_process);
		}

		shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

		size = sizeof(ngx_endpoint_shm_t); //cd->size;
		shm_chs = ngx_slab_alloc(shpool, size);
		if(shm_chs == NULL) {
			ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0, "ngx_http_endpoint_init_shm_zone ngx_slab_alloc error ,size : %l" ,size);
		}
		ngx_memzero(shm_chs, size);
		shm_process = shm_chs; //
		//
		#if (nginx_version >= 1002000)
			if (ngx_shmtx_create(&shm_process->dus.mutex, &shm_process->dus.lock, NULL) != NGX_OK)
		#else
			if (ngx_shmtx_create(&shm_process->dus.mutex, (void *) &shm_process->dus.lock, NULL) != NGX_OK)
		#endif
			{
				return NGX_ERROR;
			}
	}
	shm_process->dus.loaded = 0;
	return NGX_OK;
}

void
ngx_http_endpoint_channel_task_handler(ngx_event_t *event)
{
	ngx_int_t ret;
	ngx_cycle_t *cycle;
	cycle = (ngx_cycle_t*)event->data;

	ngx_log_error(NGX_LOG_ERR, cycle->log, 0, " endpoint make channel error: %l",ngx_pid);

	ret = ngx_add_channel_event(cycle, ngx_chs->chs[ngx_args.pos].channel_pair[1], NGX_READ_EVENT, ngx_endpoint_channel_handler);//监听socket pair为1的套接字
	if(ret == NGX_ERROR){
		ngx_add_timer(event, 5000);
	}
}

static void
ngx_http_endpoint_channel_task(ngx_cycle_t *cycle,ngx_event_t *ev)
{
	ev->handler = ngx_http_endpoint_channel_task_handler;
	ev->log = cycle->log;
	ev->data = cycle;
	ev->timer_set = 0;
	ngx_add_timer(ev, 5000);
}

static ngx_int_t
ngx_http_endpoint_init_process(ngx_cycle_t *cycle)
{
	if (ngx_process == NGX_PROCESS_WORKER) {
		ngx_int_t ret;
		ngx_str_t s;
		ngx_uint_t i;
		//partC
		ngx_args.pos = ngx_worker; //ngx_process_slot%worker_processes;//当前work process的占位，ngx_process_slot是main在fork前给子进程安排的占位
		ret = ngx_add_channel_event(cycle, ngx_chs->chs[ngx_args.pos].channel_pair[1], NGX_READ_EVENT, ngx_endpoint_channel_handler);//监听socket pair为1的套接字
		if(ret == NGX_ERROR){
			ngx_http_endpoint_channel_task(cycle,&ngx_chs->chs[ngx_args.pos].ev);
		}
		//partB
		//只会在 workprocess被kill掉时执行，reload的时候不会执行此部分，因为 shm_process->dns.count 为0, reload时不用shm_process->dns做旧数据还原
		for( i = 0 ; i < shm_process->dns.count ; i++) {
			s.data = shm_process->dns.dns[i];
			s.len = strlen((char*)shm_process->dns.dns[i]);
			ngx_http_endpoint_reslove_dn(cycle->pool,&s);
		}
		//处理动态添加的 upstream中的server
		ngx_str_t up, sv, swt, srg, scdw, sfdw; //, sidx;
		ngx_int_t idx, rg, wt, cdw, fdw;
		ngx_shmtx_lock(&shm_process->dus.mutex);
		for( i = 0 ; i < shm_process->dus.count ; i++) {
			s.data = shm_process->dus.up_srvs[i];
			s.len = strlen((char*)shm_process->dus.up_srvs[i]);
			parse_up_srv_from_uri(&s, &up, &sv, &swt, &srg);
			idx = add_up_srv(&up, &sv, &swt, &srg, -1);
			if( idx >= 0) {
				if(shm_process->dus.loaded == 0) {
					rg = ngx_atoi(srg.data,srg.len); //region
					wt = ngx_atoi(swt.data,swt.len); //weight
					ngx_str_sch_idx_trimtoken(s.data, s.len, '/', 5, &scdw);
					ngx_str_sch_idx_trimtoken(s.data, s.len, '/', 6, &sfdw);
					cdw = ngx_str_to_int(scdw.data, scdw.len);
					fdw = ngx_str_to_int(sfdw.data, sfdw.len);
					ngx_http_upstream_check_add_shm_peer(idx, rg, wt, cdw, fdw);
				} else {
					ngx_http_upstream_check_add_timers((ngx_cycle_t*)ngx_cycle, idx, idx);
				}
			}
//			parse_up_srv_from_uri(&s, &up, &sv, &swt, &srg);
//			ngx_str_sch_idx_trimtoken(s.data, s.len, '/', 5, &sidx);
////			idx = sidx.data[0];
//			idx = *((ngx_int_t*)sidx.data); //得到之前的索引位
//			ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-init add start------------------------ %d %V", ngx_pid, &sv);
//			idx = add_up_srv(&up, &sv, &swt, &srg, idx);
//			ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=5================ %d", ngx_pid);
//			//关联共享内存shm_peer, reload后应该取shm中的region weight
//			//reload后新增的peer，从shm中取rg wt,所以设两个无意义的参数"-1"后面会判断处理
//			ngx_http_upstream_check_add_shm_peer(idx, -1, -1);
//			ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "=6================ %d", ngx_pid);
//			ngx_log_debug_process(NGX_LOG_ERR, ngx_cycle->log, 0, "-init add end------------------------ %d %V", ngx_pid, &sv);
		}
		shm_process->dus.loaded = 1;
		ngx_shmtx_unlock(&shm_process->dus.mutex);
		//重载有变化的waf
#ifdef NGX_HTTP_WAF_MODULE
		if(shm_process->wfs.count > 0) {
			ngx_conf_t cnf;
			cnf.pool = cycle->pool;
			cnf.log = cycle->log;
			cnf.conf_file = NULL;
			ngx_http_waf_loc_conf_t **wcfs = NULL ;
			for(size_t j = 0; j < waf_env_conf.count ; j++) {
				wcfs = waf_env_conf.waf_cf->elts;
				for( i = 0 ; i < shm_process->wfs.count ; i++) {
//					s.data = shm_process->wfs.waf_item[i];
//					s.len = strlen((char*)shm_process->wfs.waf_item[i]);
					ngx_http_waf_reload(&cnf,wcfs[j],shm_process->wfs.waf_item[i]);
				}
			}
		}
		//重载开关waf
		ngx_http_waf_loc_conf_t *wcf = NULL;
		for( i = 0; i < max_waf_item_len; i++) {
			wcf = (ngx_http_waf_loc_conf_t*)shm_process->ws.waf_addrs[i];
			if(wcf != NULL){
				wcf->waf = shm_process->ws.onff[i];
			}else{
				break;
			}
		}
		//
		if(shm_process->wfms.count > 0) {
			ngx_http_waf_loc_conf_t **wcfs = NULL ;
			for(size_t j = 0; j < waf_env_conf.count ; j++) {
				wcfs = waf_env_conf.waf_cf->elts;
				for( i = 0 ; i < shm_process->wfms.count ; i++) {
					s.data = shm_process->wfms.waf_mode[i];
					s.len = strlen((char*)shm_process->wfms.waf_mode[i]);
					ngx_http_waf_mode_reload(&s,1,wcfs[j]);
				}
			}
		}
#endif
	}
	return NGX_OK;
}

static char *
ngx_http_endpoint_init_main_conf(ngx_conf_t *cf, void *conf)
{
	ngx_core_conf_t			*ccf;
	size_t					size;
	ngx_shm_zone_t			*shm_zone;

	ccf = (ngx_core_conf_t *) ngx_get_conf(cf->cycle->conf_ctx, ngx_core_module);
	//partB 共享内存的分配
//	size = sizeof(ngx_processes_cmd_channel) + (ccf->worker_processes - 1) * sizeof(ngx_process_cmd_channel); //预分配的空间大小
//	size = sizeof(ngx_endpoint_shm_t); //预分配的空间大小
	size = ngx_shm_estimate_size(sizeof(ngx_endpoint_shm_t));
//	catch_data.size = size;
	size = ngx_max(size, 1024 * 8); //共享空间最小申请8192
//	shm_zone = ngx_shm_zone_init(cf, &ngx_http_endpoint_module ,&shm_endpoint, size, &catch_data,ngx_http_endpoint_init_shm_zone);
	shm_zone = ngx_shm_zone_init(cf, &ngx_http_endpoint_module ,&shm_endpoint, size, NULL,ngx_http_endpoint_init_shm_zone);
	if(!shm_zone){
		return NGX_CONF_ERROR;
	}

	ngx_memzero(&ngx_args,sizeof(ngx_process_args));
	//partC 为每个work process创建 socket pair
	size = sizeof(ngx_processes_cmd_channel) + (ccf->worker_processes - 1) * sizeof(ngx_process_cmd_channel);
	ngx_chs = ngx_palloc(cf->pool, size);
	ngx_memzero(ngx_chs, size);
	ngx_int_t i;
	for( i = 0 ; i< ccf->worker_processes ; i++) {
		//为每个work process创建socket pair
		if ( ngx_create_socketpair(ngx_chs->chs[i].channel_pair,0,cf->log) != NGX_OK){
			return NGX_CONF_ERROR;
		}
		ngx_chs->count++;
	}

	ngx_pool_create(cf->log);

    return NGX_CONF_OK;
}

/*
static void *
ngx_http_endpoint_create_srv_conf(ngx_conf_t *cf)
{
    return NULL;
}*/

static void
ngx_http_endpoint_exit_process(ngx_cycle_t *cycle)
{
	ngx_uint_t i;
	ngx_event_t *rev = NULL;
	for(i = 0; i < cycle->connection_n; i++) {
		if( cycle->connections[i].fd == ngx_chs->chs[ngx_args.pos].channel_pair[1]) {
			rev = cycle->connections[i].read;
			ngx_del_event(rev, NGX_READ_EVENT, 0);
			break;
		}
	}
}

