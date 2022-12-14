/**
 * 本文件有三大块内容，
 * 1. partA: 是endpoint，由nginx指令访问的入口模块及指令处理
 * 2. partB: 是全局的共享内存shm_process
 * 3. partC: 是所有work processer(简称wp)间通讯的socket注册表ngx_chs, 相关函数ngx_get_msg, ngx_broadcast_processes
 * */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_channel.h>

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

//模块入口
ngx_module_t  ngx_http_endpoint_module = {
    NGX_MODULE_V1,
    &ngx_http_endpoint_module_ctx, /* module context */
    ngx_http_endpoint_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
	ngx_http_endpoint_init_process,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/** partC */
struct ngx_process_cmd_channel_s {
	ngx_socket_t	channel_pair[2];
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
	ngx_int_t				pos; //当前work process在 ngx_chs 取得的值的位置
	size_t				ngx_msg_size ; //当前传递的消息实际内容的长度
} ngx_process_args;
ngx_process_args		ngx_args; //当前 work process 的特有变量

typedef ngx_int_t (*msg_handler)(void *msg); //接收消息后，回调处理信息
static ngx_int_t dn_msg_handler(void *msg); //域名刷新的回调

#define CMD_PAYLOAD_SIZE	1   //消息传递指令，指示本消息是头信息，表现后面的消息体的大小
#define CMD_PROCESS			2   //消息传递指令，指示本消息是要处理的业务
typedef struct {
	ngx_int_t			cmd; 	//命令
	ngx_fd_t    		fd; 		//如果要传输本地描述符,做控制信息传递
	msg_handler		handler;	//因为所有work process的地址是统一的,因此传递回调函数的地址是可以的
	size_t			size; //要传递的消息大小
	char				data[1]; 	//实际传输的数据
} ngx_channel_msg; //传递的消息

ngx_int_t ngx_broadcast_processes(ngx_channel_msg *msg, size_t size, ngx_log_t *log); //对所其它子进程广播消息
static size_t ngx_get_msg(ngx_channel_msg **msg, ngx_pool_t *pool, void *data, size_t size , msg_handler handler); //创建一个ngx_channel_msg用于传递，返回消息体和整个消息的大小

/** partB */
#define	max_dns		10
#define	max_dns_len	100
typedef struct {
	u_char			dns[max_dns][max_dns_len];
	size_t			count;
}domainnames;
typedef struct {
	//TODO 有需要添加的共享内存数据就放到此结构体里
	domainnames		dns;//如果有通过 domain/resovle/ 指令要求重新解析域名的在此做个记录，防止 某 work process被kill后能重新resolve,因为所有子进程重新启动后只是复制主进程的内容
} ngx_endpoint_shm_t;
ngx_endpoint_shm_t *shm_process = NULL; //共享内存的本地变量

static ngx_str_t shm_endpoint = ngx_string("shm_endpoint");//共享内存的名称
typedef struct{
	size_t		size;
	void			*data;
} ngx_endpoint_catch_data;
ngx_endpoint_catch_data catch_data; //创建共享内存时，携带给初始化操作的数据

/** - */
static ngx_str_t sucs = ngx_string("success");
static ngx_str_t fail = ngx_string("failure");

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
		out_native = ngx_palloc(pool, sizeof(ngx_chain_t));
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

//将一个缓存链添加到另一个尾部
static void
ngx_append(ngx_chain_t *p , ngx_chain_t *c)
{
	if(p->next == NULL) {
		p->next = c;
	}else{
		ngx_append(p->next,c);
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
			for( peer = peers->peer ; peer ; peer = peer->next) {
				if(peer->server.len == 0) {
					ngx_str_sch_next_trimtoken(peers->name->data ,peers->name->len ,':',&s_token);//非upstream定义的服务
				}else {
					ngx_str_sch_next_trimtoken(peer->server.data ,peer->server.len ,':',&s_token);//upstream内定义的服务
				}
				if( s_token.len == 0 || ngx_str_cmp(&s_token,dn) != 0 ){
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
					peers->single = (u.naddrs == 1);
					if(u.naddrs <= k) {//如果符合条件的peer数量多于u的addr数量
						p_p->next = peer->next;
						peer = p_p;
						ngx_pfree(pool,peer->sockaddr);
						ngx_pfree(pool,peer);
						peers->number--;
						continue;
					}
//				if( s_token.len > 0 && ngx_str_cmp(&s_token,dn) == 0 ){
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
static ngx_int_t
ngx_http_endpoint_do_get(ngx_http_request_t *r, ngx_array_t *resource)
{
    ngx_int_t                  rc,status;
    ngx_chain_t                out;
    ngx_str_t                  *con;
    ngx_str_t                  *value,val_tmp;
    ngx_str_t                  arg_cf=ngx_string("conf") , ip = ngx_string("ip"), tab = ngx_string("\t");
	u_char 					*s_t;
	size_t					buf_sz = 0;

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
        con = ngx_xfdf_list_upstreams();
//        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "-- %l ---%V----",con->len, con);
        if (con != NULL && con->len >0 ) {
        	buf_sz = ngx_http_out_content(r->pool,con,&out,1);
        }
    } else if(value[0].len == 4 && ngx_strncasecmp(value[0].data, (u_char *)"down", 4) == 0) {
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
    } else if(value[0].len == 2 && ngx_strncasecmp(value[0].data, (u_char *)"up", 2) == 0) {
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
    } else if(value[0].len == 7 && ngx_strncasecmp(value[0].data, (u_char *)"nocheck", 7) == 0) {
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
    } else if(value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"weight", 6) == 0) {
        if( resource->nelts == 4  ){
            ngx_str_t *up = &value[1]; //upstream
            ngx_str_t *sr = &value[2]; //server
            ngx_str_t *wt = &value[3]; //weight
            ngx_uint_t w = ngx_atoi(wt->data, wt->len);
            ngx_xfdf_deal_peer_weight(up,sr,w);
            buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        }
    } else if (value[0].len == 9 && ngx_strncasecmp(value[0].data, (u_char *)"variables", 9) == 0 ) {
    	if( resource->nelts == 2 ){
    		ngx_str_t *varname = &value[1]; //variable name
        	ngx_str_t f;
            ngx_http_get_param_value(r,arg_cf.data , arg_cf.len , &f);
        	if(f.len >0 ){
    			f.data = (u_char*)ngx_strcpy(r->pool,&f);
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
	} else if (value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"region", 6) == 0 ) {
    	if( resource->nelts == 2 ){
    		ngx_str_t *upstream = &value[1]; //upstream name
        	ngx_str_t f;
            ngx_http_get_param_value(r,arg_cf.data , arg_cf.len , &f);
        	if(f.len >0 ){
    			f.data = (u_char*)ngx_strcpy(r->pool,&f);
    			ngx_reload_region_conf(&f,ngx_str_2_hash(upstream));
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        	}
    	}
    } else if (value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"router", 6) == 0 ) {
    	if( resource->nelts == 2 ){
    		ngx_str_t *router_name = &value[1]; //router name
        	ngx_str_t f;
            ngx_http_get_param_value(r,arg_cf.data , arg_cf.len , &f);
        	if(f.len >0 ){
    			f.data = (u_char*)ngx_strcpy(r->pool,&f);
    			ngx_reload_router(r->pool,router_name ,&f);
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
        	}
    	} else if( resource->nelts == 4 ){// /router/[name]/[add|exist|get]/[variable]
    		ngx_str_t *router_name = &value[1]; //router name
    		if( value[2].len == 9 && ngx_strncasecmp(value[2].data, (u_char *)"variables", 9) == 0
    			&& value[3].len == 4 && ngx_strncasecmp(value[3].data, (u_char *)"list", 4) == 0 ){// /router/[name]/variables/list
    			buf_sz = ngx_http_out_content(r->pool,router_name,&out,1);
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
    			ngx_uint_t idx = ngx_atoi(idxt->data, idxt->len);
    			ngx_str_t *k = &value[4];
    			ngx_str_t *v = &value[5];
    			ngx_add_router_item(r->pool ,router_name,idx,k,ngx_atoi(v->data, v->len));
    			buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
    		}
    	}
    } else if (value[0].len == 7 && ngx_strncasecmp(value[0].data, (u_char *)"address", 7) == 0 ) {
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
    } else if(value[0].len == 6 && ngx_strncasecmp(value[0].data, (u_char *)"domain", 6) == 0) {// /domain/resolve/[fx.com|all]
    	if( resource->nelts == 3 ){
			if (value[1].len == 7 && ngx_strncasecmp(value[1].data, (u_char *)"resolve", 7) == 0){
				ngx_str_t *dn = &value[2]; //domain name
				if (dn->len == 3 && ngx_strncasecmp(dn->data, (u_char *)"all", 3) == 0){
					//
				}else {
					ngx_channel_msg *msg;
					buf_sz = ngx_get_msg(&msg,r->connection->pool,dn->data,dn->len,dn_msg_handler);
					ngx_broadcast_processes(msg,buf_sz,r->connection->log);
					if (ngx_http_endpoint_reslove_dn(ngx_cycle->pool,dn) == NGX_OK) {
						buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
					} else {
						buf_sz = ngx_http_out_content(r->pool,&fail,&out,1);
					}
					for(ngx_uint_t i = 0; i < max_dns ; i++) {
						u_char *d = shm_process->dns.dns[i];
						if(d[0] == '\0') {
							ngx_memcpy(d, dn->data, dn->len);
							shm_process->dns.count++;
							break;
						}
						if( dn->len == strlen((char*)d) && ngx_strncmp(dn->data , d, dn->len) == 0){
							break;
						}
					}
				}
			}
    	}
    } else if(value[0].len == 5 && ngx_strncasecmp(value[0].data, (u_char *)"limit", 5) == 0) {
		#ifdef NGX_HTTP_REQUEST_CHAIN
    	    ngx_str_t s=ngx_string("$proxy_add_x_forwarded_for , zone=bus_r:1m , rate=2r/s ,burst=1,location=/store/");
    		ngx_http_request_chain_limit_zone(r,&s);
		#endif
//		buf = append_printf(r->pool, &sucs);
    	buf_sz = ngx_http_out_content(r->pool,&sucs,&out,1);
    }


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
    				v_cf.data = (u_char*)ngx_strcpy(cf->pool,&v_cf);
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

static ngx_int_t dn_msg_handler(void *msg)
{
	ngx_channel_msg *m = msg;
	ngx_str_t dn;
	dn.data = (u_char*)m->data;
	dn.len = m->size;
	return ngx_http_endpoint_reslove_dn(ngx_cycle->pool,&dn);
}

//将消息向所有子进程广播出去
ngx_int_t
ngx_broadcast_processes(ngx_channel_msg *data, size_t size, ngx_log_t *log)
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

	for(ngx_int_t i = 0;i < ngx_chs->count ; i++) {
		if( i != ngx_args.pos ) {
			n = sendmsg(ngx_chs->chs[i].channel_pair[0], &msg, 0);
			if (n == -1) {
				err = ngx_errno;
				ngx_log_error(NGX_LOG_ALERT, log, err, "ngx_broadcast_processes() failed");
			}
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
		if (data->handler(data) == NGX_ERROR) {
			ngx_log_error(NGX_LOG_ERR, ev->log, 0, "ngx_endpoint_channel_handler data->handler() error, pid : %l ",ngx_pid);
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
	ngx_slab_pool_t                     *shpool;
	ngx_endpoint_shm_t					*shm_chs;
	size_t							size;

	ngx_endpoint_catch_data	*cd = (ngx_endpoint_catch_data*)shm_zone->data;

	shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	size = cd->size;
	shm_chs = ngx_slab_alloc(shpool, size);
	if(shm_chs == NULL) {
		ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
		                  "ngx_http_endpoint_init_shm_zone ngx_slab_alloc error ,size : %l" ,size);
	}
	ngx_memzero(shm_chs, size);
	shm_process = shm_chs; //cmd_chs指向共享空间，目前没在使用
	return NGX_OK;
}

static ngx_int_t
ngx_http_endpoint_init_process(ngx_cycle_t *cycle)
{
	if (ngx_process == NGX_PROCESS_WORKER) {
		//partC
		ngx_args.pos = ngx_process_slot;//当前work process的占位，ngx_process_slot是main在fork前给子进程安排的占位
		ngx_add_channel_event(cycle, ngx_chs->chs[ngx_args.pos].channel_pair[1], NGX_READ_EVENT, ngx_endpoint_channel_handler);//监听socket pair为1的套接字
		//partB
		ngx_str_t s;
		//只会在 workprocess被kill掉时执行，reload的时候不会执行此部分，因为 shm_process->dns.count 为0, reload时不所shm_process->dns做旧数据还原
		for(ngx_uint_t i = 0 ; i < shm_process->dns.count ; i++) {
			s.data = shm_process->dns.dns[i];
			s.len = strlen((char*)shm_process->dns.dns[i]);
			ngx_http_endpoint_reslove_dn(cycle->pool,&s);
		}
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
	size = sizeof(ngx_endpoint_shm_t); //预分配的空间大小
	catch_data.size = size;
	size = ngx_max(size, 1024 * 8); //共享空间最小申请8192
	shm_zone = ngx_shm_zone_init(cf, &ngx_http_endpoint_module ,&shm_endpoint, size, &catch_data,ngx_http_endpoint_init_shm_zone);
	if(!shm_zone){
		return NGX_CONF_ERROR;
	}

	ngx_memzero(&ngx_args,sizeof(ngx_process_args));

	//partC 为每个work process创建 socket pair
	size = sizeof(ngx_processes_cmd_channel) + (ccf->worker_processes - 1) * sizeof(ngx_process_cmd_channel);
	ngx_chs = ngx_palloc(cf->pool, size);
	ngx_memzero(ngx_chs, size);
	for(ngx_int_t i =0 ; i< ccf->worker_processes ; i++) {
		//为每个work process创建socket pair
		if ( ngx_create_socketpair(ngx_chs->chs[i].channel_pair,0,cf->log) != NGX_OK){
			return NGX_CONF_ERROR;
		}
		ngx_chs->count++;
	}

    return NGX_CONF_OK;
}

/*
static void *
ngx_http_endpoint_create_srv_conf(ngx_conf_t *cf)
{
    return NULL;
}*/
