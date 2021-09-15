
/*
本模块在upstream中，根据x-forwarded-for的首ip(即用户实际的ip)对各server做负载,这样客户端的负载会更加均匀，同时使用了hash consistent的方式将ip最大限度贴到对应server(不论增减server)。
如果在 ip_hash的情况下使用直连nginx的服务器的ip做key，这样如果有多级代理的情况就做不到负载了，因为不论有多少客户端都只有一个ip地址；另外如果加或减server所有的ip hash会重新计算负载。
如果在 hash 的情况下，可以传入$proxy_add_x_forwarded_for达到使用用户ip负载，但多级代理的情况下ip链过长，增加了计算时间，并且中间路由变化会重新hash就不能贴住客户ip。
使用如下：
upstream store {
        server 192.168.7.105:8082 weight=2 max_fails=3 fail_timeout=5s;
        server 192.168.7.205:8085 weight=2 max_fails=3 fail_timeout=5s;
        xfdf_ip_hash consistent;
    }
xfdf_ip_hash指令只有一个参数：
						consistent：代表使用一致性hash算法
						数字[1,4]：表示不使用一致性hash算法，只是ip hash，hash的强度从1到4，越高散列效果越好，当使用无效的数字则会使用默认3
						rr : 代表负载不是hash算法，而是使用的轮循

//
一致性哈希算法，每个节点虚拟出160个虚拟节点算出哈希值组成环，将ip哈希后负载到对应的虚拟节点上，这样保证负载的均匀，
另外采用就近负载的原则(顺时针)将访问负载到对应节点，来保证增减节点而保证负载不变的情况

*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "../ngx_common/ngx_common_util.h"

#include "ngx_http_upstream_xfdf_ip_hash_module.h"

#if (NGX_HTTP_UPSTREAM_CHECK)
#include "ngx_http_upstream_check_module.h"
#endif

//客户端peer的数据
typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t   rrp; //server数据
    ngx_uint_t                        region; //客户端请求将会负载到的region

    ngx_uint_t                         hash; //根据ip计算的哈希值

    u_char                             addrlen; //ip地址长度
    u_char                            *addr;   /*ip地址,long型，因为inet4的ip的特征是四个数字组成，
                                             *每个数字范围在255之内故使用unsigend char表示一个数字，
                                             *四个数字就是四个unsigned char,所以使用一个long型表示unsigned char*
                                             */
    ngx_str_t							hash_v_val; //hash计算的key

    u_char                             tries;//在给peer分配server的时候，记录已分配的server，为了均匀

    ngx_event_get_peer_pt              get_rr_peer;

} ngx_http_upstream_ip_hash_peer_data_t;

//一致性哈希算法虚拟节点
typedef struct {
    uint32_t                            hash;//节点哈希值
    ngx_str_t                          *server;//真实服务器
    
} ngx_http_upstream_chash_point_t;

//所有虚拟节点
typedef struct {
    ngx_uint_t                          number;//节点数
    ngx_http_upstream_chash_point_t     point[1];//节点链表
} ngx_http_upstream_chash_points_t;

//系统参数
typedef struct {
    u_char				deep;//xfdf_ip_hash指令的数字参数
    ngx_http_upstream_chash_points_t   *points;
    ngx_int_t                          remoteaddr_index;//$remote_addr变量在系统变量表中的位置，取值时使用位置
}ngx_http_upstream_xfdf_ip_hash_create_srv_conf_t;

//一致性哈希算法的情况下peer的数据
typedef struct {
    /* the round robin data must be first */
    ngx_http_upstream_rr_peer_data_t    rrp;
    ngx_uint_t                        region;
    ngx_http_upstream_xfdf_ip_hash_create_srv_conf_t  *conf;
    ngx_str_t                           key;
    ngx_uint_t                          tries;
    ngx_uint_t                          rehash;
    uint32_t                            hash;
    ngx_event_get_peer_pt               get_rr_peer;
} ngx_http_upstream_hash_peer_data_t;

typedef struct {
    ngx_str_t					hash_var;
} ngx_http_upstream_xfdf_ip_hash_create_loc_conf_t;

typedef struct {
	ngx_http_upstream_rr_peer_data_t  rrp;
	ngx_uint_t                    region;
} ngx_http_upstream_rr_ex_peer_data_t ;

static ngx_int_t ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc,
    void *data);
static char *ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upstream_hash_var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_upstream_xfdf_ip_hash_create_srv_conf(ngx_conf_t *cf);
static void *ngx_http_upstream_xfdf_ip_hash_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_xfdf_ip_hash_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_upstream_get_hash_peer(ngx_peer_connection_t *pc, void *data);
static ngx_int_t
ngx_http_upstream_init_chash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static int ngx_libc_cdecl
ngx_http_upstream_chash_cmp_points(const void *one, const void *two);
static ngx_int_t
ngx_http_upstream_get_chash_peer(ngx_peer_connection_t *pc, void *data);

static ngx_int_t ngx_http_upstream_init_rr_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_rr_peer(ngx_peer_connection_t *pc,
    void *data);

void *
ngx_xfdf_deal_server_get_peer(ngx_http_upstream_rr_peer_t **fstp ,ngx_str_t *up , ngx_str_t *sr);

//模块指令
static ngx_command_t  ngx_http_upstream_xfdf_ip_hash_commands[] = {

    { ngx_string("xfdf_ip_hash"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1, //NGX_CONF_NOARGS,
      ngx_http_upstream_ip_hash,
      0,
      0,
      NULL },
	  { ngx_string("set_hash_variable"),
		NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
		ngx_http_upstream_hash_var,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_upstream_xfdf_ip_hash_create_loc_conf_t, hash_var),
		NULL },
      ngx_null_command
};

//模块环境参数
static ngx_http_module_t  ngx_http_upstream_xfdf_ip_hash_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_upstream_xfdf_ip_hash_create_srv_conf,  /* create server configuration */
    NULL,                                  /* merge server configuration */

	ngx_http_upstream_xfdf_ip_hash_create_loc_conf, /* create location configuration */
	ngx_http_upstream_xfdf_ip_hash_merge_loc_conf  /* merge location configuration */
};

//模块入口
ngx_module_t  ngx_http_upstream_xfdf_ip_hash_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_xfdf_ip_hash_module_ctx, /* module context */
    ngx_http_upstream_xfdf_ip_hash_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char ngx_http_upstream_ip_hash_pseudo_addr[3];//空的ip地址
static ngx_str_t strxffd = ngx_string("x-forwarded-for");
static ngx_str_t strremote = ngx_string("remote_addr");

static ngx_http_upstream_xfdf_ups_t *xfdf_ups;
static ngx_str_t str_up=ngx_string("upstream ");
static ngx_str_t str_sr=ngx_string(" server ");
static ngx_str_t str_dn=ngx_string(" down=");
static ngx_str_t str_cd=ngx_string(" check_down=");
static ngx_str_t str_nm=ngx_string(" name=");
static ngx_str_t str_wt=ngx_string(" weight=");
static ngx_str_t str_rg=ngx_string(" region=");
static ngx_str_t str_rt=ngx_string("\n");
static ngx_str_t str_st=ngx_string(" {\n");
static ngx_str_t str_ed=ngx_string(" }\n");

static ngx_str_t hash_var=ngx_string("hashvar");

ngx_http_variable_t *
ngx_http_get_variable_by_name(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_uint_t                  i;
    ngx_http_variable_t        *v;
    ngx_http_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable name \"$\"");
        return NULL;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    v = cmcf->variables.elts;

    if (v != NULL) {
        for (i = 0; i < cmcf->variables.nelts; i++,v++) {
            if (name->len == v->name.len && ngx_strncasecmp(name->data, v->name.data, name->len) == 0) {
                return v;
            }
        }
    }

    return NULL;
}

static u_char*
ngx_http_upstream_ip_get(ngx_http_request_t *r, u_char **theip )
{
    ngx_table_elt_t *header;
    header = r->headers_in.headers.part.elts;
    ngx_str_t lowhd;
    size_t c;
    size_t i;
    c = r->headers_in.headers.part.nelts;//get count of headers
    for(i=0 ; i<c; i++) {
        lowhd.data = header[i].lowcase_key;
        lowhd.len = header[i].key.len;
        if ( ngx_strncmp( strxffd.data , lowhd.data, strxffd.len ) == 0){ //if the head is x-forwarded-for
            u_char *v = header[i].value.data;
            size_t j = 0;
            //get 1st value of the values in header key "x-forwarded-for",it means the original client ip (xxx.xxx.xxx.xxx)
            for ( ; j<header[i].value.len; j++){
                if ( *++v == ',') { //
                	  j++;
                    break;
                }
            }
            if (j > 0){
                in_addr_t naddr = ngx_inet_addr(header[i].value.data, j) ; //make unsinged long value of the client ip
                if (naddr != INADDR_NONE) {
                    *theip = ngx_palloc( r->pool, sizeof(u_char)*4 ); //allocate 4byte space for a in_addr_t(unsigned long)
                    ngx_memcpy(*theip,(u_char*) &naddr,sizeof(in_addr_t));//keey the client ip
                    //
                    /*struct in_addr *h_addr;
                    h_addr = ngx_palloc(r->pool, sizeof(struct in_addr));
                    h_addr->s_addr = naddr;
                    addr = inet_ntoa(*h_addr);
                    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"--%V-------- %s --: \"%V: %V\"",&strxffd, addr,&header[i].key, &header[i].value);*/
                }
            }
            break;
        }
    }
    return *theip;
}

static size_t
ngx_http_upstream_ip_get_str(ngx_http_request_t *r, u_char **theip )
{
    ngx_table_elt_t *header;
    header = r->headers_in.headers.part.elts;
    ngx_str_t lowhd;
    size_t i,c,k=0;
    c = r->headers_in.headers.part.nelts;//get count of headers
    for(i=0 ; i<c; i++) {
        lowhd.data = header[i].lowcase_key;
        lowhd.len = header[i].key.len;
        if ( ngx_strncmp( strxffd.data , lowhd.data, strxffd.len ) == 0){ //if the head is x-forwarded-for
            u_char *v = header[i].value.data;
            size_t j = 0;
            //get 1st value of the values in header key "x-forwarded-for",it means the original client ip (xxx.xxx.xxx.xxx)
            for ( ; j<header[i].value.len; j++){
                if ( *++v == ',') { //
                	  j++;
                    break;
                }
            }
            if (j > 0){
            	  *theip = header[i].value.data;//get the ip with string without '\0'
            	  k = j;
            }
            break;
        }
    }
    return k;//return length of ip
}

static void
ngx_xfdf_init_upstream(ngx_pool_t *pool ,ngx_http_upstream_rr_peers_t* peers)
{
    ngx_http_upstream_xfdf_up_t *xupstream;
    ngx_http_upstream_xfdf_peer_t *xpeer;
    ngx_http_upstream_rr_peer_t *peer;
    size_t p ;
    
    xupstream = ngx_array_push(xfdf_ups->upstreams);
    
    xupstream->peers = ngx_palloc(pool, sizeof(ngx_http_upstream_xfdf_peer_t)*peers->number);
    xupstream->name = peers->name;
    xupstream->num = 0;
    
    xpeer = xupstream->peers;
    for (peer = peers->peer; peer; peer = peer->next) {
        xupstream->peers->peer = peer;
        
        p = ngx_num_bit_count(xupstream->num) ;
        xupstream->peers->name.len = p;
        xupstream->peers->name.data = ngx_palloc(pool, sizeof(u_char)*p);
        ngx_sprintf(xupstream->peers->name.data,"%ui",xupstream->num);
        xupstream->num++;

        xupstream->peers++;
    }
    xupstream->peers = xpeer;
}

ngx_str_t*
ngx_xfdf_list_upstreams()
{
    ngx_str_t *str_ups;
    u_char *buf = NULL , *buf_st ;
    ngx_http_upstream_xfdf_up_t    *ups;
    size_t i ,j,len = 0 ;

    if (xfdf_ups->upstreams == NULL ){
        return NULL;
    }

    str_ups = ngx_palloc(xfdf_ups->pool, sizeof(ngx_str_t));
    str_ups->len = 0;
    str_ups->data = NULL;

    ups = xfdf_ups->upstreams->elts;
    for (i=0; i<xfdf_ups->upstreams->nelts; i++){
        len += str_up.len + ups[i].name->len + str_st.len;
        for (j=0; j < ups[i].num; j++) {
        	char swt[4], srg[4]={'0',0};
            #if (NGX_HTTP_UPSTREAM_CHECK)
			    sprintf(swt,"%lu",ngx_http_upstream_get_peer_weight(ups[i].peers[j].peer));
			    sprintf(srg,"%lu",ngx_http_upstream_get_peer_region(ups[i].peers[j].peer));
		    #else
			    sprintf(swt,"%lu",ups[i].peers[j].peer->weight);
		    #endif
            len += str_sr.len+ ups[i].peers[j].peer->server.len + 
                   str_nm.len+ ups[i].peers[j].name.len +
				   str_wt.len + strlen(swt) +
				   str_rg.len + strlen(srg) +
                   str_dn.len+ 1 +
                   str_cd.len+ 1 +
                   str_rt.len;
        }
        len += str_ed.len;
    }
    if ( len > 0 ) {

        buf_st = buf = ngx_palloc(xfdf_ups->pool, sizeof(u_char)*len );
    
        for (i=0; i<xfdf_ups->upstreams->nelts; i++){
            buf = ngx_strcat(buf ,str_up.data ,str_up.len );
            buf = ngx_strcat(buf ,ups[i].name->data ,ups[i].name->len );
            buf = ngx_strcat(buf ,str_st.data ,str_st.len );
            
            for (j=0; j < ups[i].num; j++) {
                ngx_uint_t wtlen;
                char swt[4] , srg[4]={'0',0} ;
                #if (NGX_HTTP_UPSTREAM_CHECK)
                    sprintf(swt,"%lu",ngx_http_upstream_get_peer_weight(ups[i].peers[j].peer));
    			    sprintf(srg,"%lu",ngx_http_upstream_get_peer_region(ups[i].peers[j].peer));
                #else
                    sprintf(swt,"%lu",ups[i].peers[j].peer->weight);
                #endif
                wtlen=strlen(swt);
                buf = ngx_strcat(buf ,str_sr.data ,str_sr.len );
                buf = ngx_strcat(buf ,ups[i].peers[j].peer->server.data ,ups[i].peers[j].peer->server.len );
                buf = ngx_strcat(buf ,str_nm.data ,str_nm.len );
                buf = ngx_strcat(buf ,ups[i].peers[j].name.data ,ups[i].peers[j].name.len );
                buf = ngx_strcat(buf ,str_wt.data ,str_wt.len );
                ngx_sprintf(buf,"%s", swt );
                buf += wtlen;
                wtlen=strlen(srg);
                buf = ngx_strcat(buf ,str_rg.data ,str_rg.len );
                ngx_sprintf(buf,"%s", srg );
                buf += wtlen;
                buf = ngx_strcat(buf ,str_dn.data ,str_dn.len );
                #if (NGX_HTTP_UPSTREAM_CHECK)
                	ngx_sprintf(buf,"%ui", ngx_http_upstream_check_peer_force_down(ups[i].peers[j].peer));
//                    ngx_sprintf(buf,"%ui", ups[i].peers[j].peer->down ? ups[i].peers[j].peer->down : ngx_http_upstream_check_peer_force_down(ups[i].peers[j].peer) );
                #else
                    ngx_sprintf(buf,"%ui",ups[i].peers[j].peer->down);
                #endif
                buf += 1;
                buf = ngx_strcat(buf ,str_cd.data ,str_cd.len );
                #if (NGX_HTTP_UPSTREAM_CHECK)
                	ngx_sprintf(buf,"%ui", ngx_http_upstream_check_peer_down(ups[i].peers[j].peer));
                #else
                    ngx_sprintf(buf,"%ui",0);
                #endif
                buf += 1;
              //  buf+=(ups[i].peers[j].peer->down/10+1);
                buf = ngx_strcat(buf ,str_rt.data ,str_rt.len );
            }
            buf = ngx_strcat(buf ,str_ed.data ,str_ed.len );
        }

        str_ups->len = len;
        str_ups->data = buf_st;
    }

    return str_ups;

}


void *
ngx_xfdf_deal_server_get_peer(ngx_http_upstream_rr_peer_t **fstp, ngx_str_t *up , ngx_str_t *sr)
{
    ngx_http_upstream_xfdf_up_t    *ups;
    size_t i ,j;

    if (xfdf_ups->upstreams == NULL ){
        return NULL;
    }

    ups = xfdf_ups->upstreams->elts;
    
    for (i=0; i<xfdf_ups->upstreams->nelts; i++){
        if (ups[i].name->len == up->len && ngx_strncasecmp(ups[i].name->data, up->data, up->len) == 0) {
        	if (fstp != NULL){
        		*fstp  = ups[i].peers[0].peer;
        	}
            for (j=0; j < ups[i].num; j++) {
                if (ups[i].peers[j].name.len == sr->len && ngx_strncasecmp(ups[i].peers[j].name.data, sr->data, sr->len) == 0) {
                    return ups[i].peers[j].peer;
                }
            }
        }
    }
    return NULL;
}


void
ngx_xfdf_deal_server(ngx_str_t *up , ngx_str_t *sr ,ngx_int_t dw)
{
	ngx_http_upstream_rr_peer_t *p;

	p = ngx_xfdf_deal_server_get_peer(NULL,up,sr);
    if(p != NULL)
    {
		#if (NGX_HTTP_UPSTREAM_CHECK)
			ngx_http_upstream_check_force_down_peer(p,dw);
		#else
			p->down = dw;
		#endif
    }
}

void
ngx_xfdf_deal_peer_weight(ngx_str_t *up , ngx_str_t *sr ,ngx_int_t w)
{
    #if (NGX_HTTP_UPSTREAM_CHECK)
        ngx_http_upstream_rr_peer_t *p;
        ngx_http_upstream_rr_peer_t *fstp ;
		p = ngx_xfdf_deal_server_get_peer(&fstp,up,sr);
		if(p != NULL)
		{
		    ngx_http_upstream_check_set_peer_weight(fstp,p,w);
		}
    #endif
}

ngx_http_upstream_rr_peer_t*
ngx_upstream_region_peer(ngx_http_upstream_rr_peer_t *peer ,ngx_uint_t region)
{
	ngx_uint_t r = ngx_http_upstream_get_peer_region(peer);
	while(r!=0 && region!=0 && r!= region){
		if(peer->next == NULL) {
			break;
		}
		peer = peer->next;
		r = ngx_http_upstream_get_peer_region(peer);
	}
	return peer;
}

/*  
	ip hash，x-forwarded-for 1st , and then $remote_addr
*/

static ngx_int_t
ngx_http_upstream_init_ip_hash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_rr_peers_t       *peers;
    //
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }
    peers = us->peer.data;

    ngx_xfdf_init_upstream(cf->pool, peers);
    //
    #if (NGX_HTTP_UPSTREAM_CHECK)
        ngx_http_upstream_rr_peer_t        *peer;

        for (peer = peers->peer; peer; peer = peer->next) {
            ngx_http_upstream_check_add_peer(cf, us, peer);
        }
        //backup server
        if ( (peers = peers->next) ) {
            for (peer = peers->peer; peer; peer = peer->next) {
                ngx_http_upstream_check_add_peer(cf, us, peer);
            }
        }
    #endif
    //
    us->peer.init = ngx_http_upstream_init_ip_hash_peer;
    

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_ip_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
	ngx_str_t *hash_v = NULL ;
    struct sockaddr_in                     *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6                    *sin6;
#endif
    ngx_http_upstream_ip_hash_peer_data_t  *iphp;

    iphp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_ip_hash_peer_data_t));
    if (iphp == NULL) {
        return NGX_ERROR;
    }
    
    ngx_http_upstream_xfdf_ip_hash_create_srv_conf_t  *xfdfcf;
    ngx_http_upstream_xfdf_ip_hash_create_loc_conf_t		*xfdflcf;

    xfdfcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_xfdf_ip_hash_module);
    xfdflcf = ngx_http_get_module_loc_conf(r, ngx_http_upstream_xfdf_ip_hash_module);
    r->upstream->peer.data = &iphp->rrp;

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_ip_hash_peer;


	iphp->hash_v_val.len = 0;
    if (xfdflcf->hash_var.len > 0) {
    	hash_v = &xfdflcf->hash_var;
    }else {
    	hash_v = ngx_http_get_variable_head(r,hash_var.data ,hash_var.len);
    }
    if(hash_v != NULL) {
    	get_request_value(r,hash_v, &iphp->hash_v_val);
    }


    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        //default use direct client ip
        iphp->addr = (u_char *) &sin->sin_addr.s_addr;//default is remote_addr
        iphp->addrlen = xfdfcf->deep; //default 3;
        
        iphp->addr=ngx_http_upstream_ip_get(r,&iphp->addr);//get 1st of x-forwarded-for 

        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        iphp->addr = (u_char *) &sin6->sin6_addr.s6_addr;
        iphp->addrlen = 16;
        break;
#endif

    default:
        iphp->addr = ngx_http_upstream_ip_hash_pseudo_addr;
        iphp->addrlen = 3;
    }

    iphp->hash = 89;
    iphp->tries = 0;
    iphp->get_rr_peer = ngx_http_upstream_get_rr_peer;
    iphp->region =	0;
	#if (NGX_HTTP_UPSTREAM_CHECK)
    	iphp->region =	ngx_http_upstream_request_region(r);
	#endif

    return NGX_OK;
}

//负载当前访问到后端服务器
static ngx_int_t
ngx_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_ip_hash_peer_data_t  *iphp = data;

    time_t                        now;
    ngx_int_t                     w;
    uintptr_t                     m;
    ngx_uint_t                    i, n, p, hash;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf --- get ip hash peer, try: %ui", pc->tries);

    /* TODO: cached */

    ngx_http_upstream_rr_peers_wlock(iphp->rrp.peers);

    if (iphp->tries > 20 || iphp->rrp.peers->single) {
        ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
        return iphp->get_rr_peer(pc, iphp);
    }

    now = ngx_time();

    pc->cached = 0;
    pc->connection = NULL;

    hash = iphp->hash; //当前客户端ip初始哈希值,默认值89

    for ( ;; ) {
    	if(iphp->hash_v_val.len > 0) {
    		hash = ngx_str_2_hash_evenly(iphp->hash_v_val.data,iphp->hash_v_val.len);
    	} else {
			//根据xfdf_ip_hash指令的数值参数循环计算散列值，取用89，113，6271三个质数是为了计算结果均匀
			for (i = 0; i < (ngx_uint_t) iphp->addrlen; i++) {
				hash = (hash * 113 + iphp->addr[i]) % 6271;
			}
    	}

        peer = iphp->rrp.peers->peer;//server

        #if (NGX_HTTP_UPSTREAM_CHECK)
        	if(iphp->region == 0) {
        		//no region
        		w = hash % (iphp->rrp.peers->total_weight + ngx_http_upstream_get_v_total_weight(peer));//得到所有服务的权重合并根据散列值取模
        	}else {
        		w = ngx_http_upstream_get_region_total_weight(peer,iphp->region);
        		if(w == 0) {
        			iphp->region = 0;
        			w = (iphp->rrp.peers->total_weight + ngx_http_upstream_get_v_total_weight(peer));
        		}
        		w = hash % w;
        	}
        #else
            w = hash % iphp->rrp.peers->total_weight ;//得到所有服务的权重合并根据散列值取模
        #endif
        p = 0;

		#if (NGX_HTTP_UPSTREAM_CHECK)
        	//请求和负载的server不属于同一个region
        	peer = ngx_upstream_region_peer(peer,iphp->region);
		#endif
        //得到被负载到的server，大权重的机率更高
//        while (w >= peer->weight) {
        ngx_int_t pw=peer->weight;
        #if (NGX_HTTP_UPSTREAM_CHECK)
            pw=ngx_http_upstream_get_peer_weight(peer);
        #endif
        while (w >= pw) {
//            w -= peer->weight;
            w -= pw;
            if(peer->next != NULL) {
				#if (NGX_HTTP_UPSTREAM_CHECK)
				peer = ngx_upstream_region_peer(peer->next,iphp->region);
				#else
				peer = peer->next;
				#endif
            }
            p++;
            pw=peer->weight;
            #if (NGX_HTTP_UPSTREAM_CHECK)
                pw=ngx_http_upstream_get_peer_weight(peer);
            #endif
        }

        /*
         下面的部分是确定被选中的服务器是否已被选过了，如果被选过需要重新选择
         用一组64列的矩阵表示所有server，0为未占用，1为被占用．
         n代表被选中的服务位于哪行，m代表被选中服务位于哪个位上，
         根据rrp.tried中的记录得到服务是否被占用
        */
        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        //rrp.tried[n]表示服务所有行的服务占用情况，m是当前服务所在位置，相与后得到是否已被占用
        if (iphp->rrp.tried[n] & m) {
            goto next;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf - get ip hash peer, hash: %ui %04XL", p, (uint64_t) m);

        #if (NGX_HTTP_UPSTREAM_CHECK)
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf - get hash peer, check peer down ");
        ngx_uint_t nut = ngx_http_upstream_check_peer_force_down(peer);
        if (nut) {
        	if(nut == 2) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0, "xfdf - ip hash peer [%V] is force-down", &peer->server);
        	}
            goto next;
        }
        if (ngx_http_upstream_check_peer_down(peer)) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0, "xfdf - ip hash peer [%V] is check-down", &peer->server);
            goto next;
        }
		#else
        //如果宕机重新选择
        if (peer->down) {
            goto next;
        }

        #endif

        //如果服务错误重新选择
        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            goto next;
        }
        
        //如果超过连接数重新选择
        if (peer->max_conns && peer->conns >= peer->max_conns) {
            goto next;
        }

        break;

    next:

        //如果尝试选择大于20次就重新做一次轮循选择
        if (++iphp->tries > 20) {
            ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);
            return iphp->get_rr_peer(pc, iphp);
        }
    }

    iphp->rrp.current = peer;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    ngx_http_upstream_rr_peers_unlock(iphp->rrp.peers);

    iphp->rrp.tried[n] |= m;
    iphp->hash = hash;

    return NGX_OK;
}

/**-- end --**/

/*
 ip consistent ,x-forwarded-for 1st , if has no value replace with $remote_addr
*/

static ngx_int_t
ngx_http_upstream_init_hash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_hash_peer_data_t  *hp;
    ngx_http_upstream_xfdf_ip_hash_create_srv_conf_t  *xfdfcf;

    hp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_hash_peer_data_t));
    if (hp == NULL) {
        return NGX_ERROR;
    }

    r->upstream->peer.data = &hp->rrp;

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    hp->region =	0;
	#if (NGX_HTTP_UPSTREAM_CHECK)
		hp->region =	ngx_http_upstream_request_region(r);
	#endif

    r->upstream->peer.get = ngx_http_upstream_get_hash_peer;

    xfdfcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_xfdf_ip_hash_module);

	hp->key.data=NULL ;
    hp->key.len = ngx_http_upstream_ip_get_str(r,&hp->key.data);
    //if cannot get x-forwarded-for , then use $remote_addr
    if (hp->key.len == 0){
        ngx_http_variable_value_t *vl = ngx_http_get_indexed_variable(r,xfdfcf->remoteaddr_index);
        hp->key.len=vl->len;
        hp->key.data=vl->data;
        //&r->connection->addr_text//$remote_addr
    }

    //if (ngx_http_complex_value(r, &hcf->key, &hp->key) != NGX_OK) {
    //    return NGX_ERROR;
   // }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "xfdf - upstream hash key:\"%V\"", &hp->key);

    hp->conf = xfdfcf;
    hp->tries = 0;
    hp->rehash = 0;
    hp->hash = 0;
    hp->get_rr_peer = ngx_http_upstream_get_rr_peer;

    return NGX_OK;
}



static ngx_int_t
ngx_http_upstream_get_hash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_hash_peer_data_t  *hp = data;

    time_t                        now;
    u_char                        buf[NGX_INT_T_LEN];
    size_t                        size;
    uint32_t                      hash;
    ngx_int_t                     w;
    uintptr_t                     m;
    ngx_uint_t                    n, p;
    ngx_http_upstream_rr_peer_t  *peer;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf - get hash peer, try: %ui", pc->tries);

    ngx_http_upstream_rr_peers_wlock(hp->rrp.peers);

    if (hp->tries > 20 || hp->rrp.peers->single) {
        ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
        return hp->get_rr_peer(pc, &hp->rrp);
    }

    now = ngx_time();

    pc->cached = 0;
    pc->connection = NULL;

    for ( ;; ) {

        /*
         * Hash expression is compatible with Cache::Memcached:
         * ((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH
         * with REHASH omitted at the first iteration.
         */

        ngx_crc32_init(hash);

        if (hp->rehash > 0) {
            size = ngx_sprintf(buf, "%ui", hp->rehash) - buf;
            ngx_crc32_update(&hash, buf, size);
        }

        ngx_crc32_update(&hash, hp->key.data, hp->key.len);
        ngx_crc32_final(hash);

        hash = (hash >> 16) & 0x7fff;

        hp->hash += hash;
        hp->rehash++;

        peer = hp->rrp.peers->peer;
        #if (NGX_HTTP_UPSTREAM_CHECK)
            w = hp->hash % (hp->rrp.peers->total_weight + ngx_http_upstream_get_v_total_weight(peer));
        #else
            w = hp->hash % hp->rrp.peers->total_weight ;
        #endif

        p = 0;

        ngx_int_t pw=peer->weight;
        #if (NGX_HTTP_UPSTREAM_CHECK)
            pw=ngx_http_upstream_get_peer_weight(peer);
        #endif
        while (w >= pw) {
            w -= pw;
            peer = peer->next;
            p++;
            pw=peer->weight;
            #if (NGX_HTTP_UPSTREAM_CHECK)
                pw=ngx_http_upstream_get_peer_weight(peer);
            #endif
        }

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (hp->rrp.tried[n] & m) {
            goto next;
        }

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf - get hash peer, value:%uD, peer:%ui", hp->hash, p);

        
        #if (NGX_HTTP_UPSTREAM_CHECK)
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf - get hash peer, check peer down ");

        ngx_uint_t nut = ngx_http_upstream_check_peer_force_down(peer);
        if (nut) {
        	if(nut == 2) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0,"xfdf - hash peer [%V] is force-down ", &peer->server);
        	}
            goto next;
        }
        if (ngx_http_upstream_check_peer_down(peer)) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0,"xfdf - hash peer [%V] is check-down ", &peer->server);
            goto next;
        }
		#else
        if (peer->down) {
		   goto next;
	    }
        #endif

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            goto next;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            goto next;
        }

        break;

    next:

        if (++hp->tries > 20) {
            ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
            return hp->get_rr_peer(pc, &hp->rrp);
        }
    }

    hp->rrp.current = peer;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;

    peer->conns++;

    if (now - peer->checked > peer->fail_timeout) {
        peer->checked = now;
    }

    ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);

    hp->rrp.tried[n] |= m;

    return NGX_OK;
}



static ngx_int_t
ngx_http_upstream_init_chash(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    u_char                             *host, *port, c;
    size_t                              host_len, port_len, size;
    uint32_t                            hash, base_hash;
    ngx_str_t                          *server;
    ngx_uint_t                          npoints, i, j;
    ngx_http_upstream_rr_peer_t        *peer;
    ngx_http_upstream_rr_peers_t       *peers;
    ngx_http_upstream_chash_points_t   *points;
    ngx_http_upstream_xfdf_ip_hash_create_srv_conf_t  *xfdfcf;
    
    union {
        uint32_t                        value;
        u_char                          byte[4];
    } prev_hash;

    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_http_upstream_init_chash_peer;

    peers = us->peer.data;
    npoints = peers->total_weight * 160;

    size = sizeof(ngx_http_upstream_chash_points_t)
           + sizeof(ngx_http_upstream_chash_point_t) * (npoints - 1);

    points = ngx_palloc(cf->pool, size);
    if (points == NULL) {
        return NGX_ERROR;
    }

    points->number = 0;

    ngx_xfdf_init_upstream(cf->pool, peers);

    for (peer = peers->peer; peer; peer = peer->next) {
        server = &peer->server;

        #if (NGX_HTTP_UPSTREAM_CHECK)
            ngx_http_upstream_check_add_peer(cf, us, peer);
        #endif

        /*
         * Hash expression is compatible with Cache::Memcached::Fast:
         * crc32(HOST \0 PORT PREV_HASH).
         */

        if (server->len >= 5
            && ngx_strncasecmp(server->data, (u_char *) "unix:", 5) == 0)
        {
            host = server->data + 5;
            host_len = server->len - 5;
            port = NULL;
            port_len = 0;
            goto done;
        }

        for (j = 0; j < server->len; j++) {
            c = server->data[server->len - j - 1];

            if (c == ':') {
                host = server->data;
                host_len = server->len - j - 1;
                port = server->data + server->len - j;
                port_len = j;
                goto done;
            }

            if (c < '0' || c > '9') {
                break;
            }
        }

        host = server->data;
        host_len = server->len;
        port = NULL;
        port_len = 0;

    done:

        ngx_crc32_init(base_hash);
        ngx_crc32_update(&base_hash, host, host_len);
        ngx_crc32_update(&base_hash, (u_char *) "", 1);
        ngx_crc32_update(&base_hash, port, port_len);

        prev_hash.value = 0;
        npoints = peer->weight * 160;
//        #if (NGX_HTTP_UPSTREAM_CHECK)
//        	j = ngx_http_upstream_get_peer_weight(peer) * 160;
//            npoints = (j == 0)? npoints : j ;
//        #endif

        for (j = 0; j < npoints; j++) {
            hash = base_hash;

            ngx_crc32_update(&hash, prev_hash.byte, 4);
            ngx_crc32_final(hash);

            points->point[points->number].hash = hash;
            points->point[points->number].server = server;
            points->number++;

#if (NGX_HAVE_LITTLE_ENDIAN)
            prev_hash.value = hash;
#else
            prev_hash.byte[0] = (u_char) (hash & 0xff);
            prev_hash.byte[1] = (u_char) ((hash >> 8) & 0xff);
            prev_hash.byte[2] = (u_char) ((hash >> 16) & 0xff);
            prev_hash.byte[3] = (u_char) ((hash >> 24) & 0xff);
#endif
        }
    }

    ngx_qsort(points->point,
              points->number,
              sizeof(ngx_http_upstream_chash_point_t),
              ngx_http_upstream_chash_cmp_points);

    for (i = 0, j = 1; j < points->number; j++) {
        if (points->point[i].hash != points->point[j].hash) {
            points->point[++i] = points->point[j];
        }
    }

    points->number = i + 1;

    xfdfcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_xfdf_ip_hash_module);
    xfdfcf->points = points;

    return NGX_OK;
}


static int ngx_libc_cdecl
ngx_http_upstream_chash_cmp_points(const void *one, const void *two)
{
    ngx_http_upstream_chash_point_t *first =
                                       (ngx_http_upstream_chash_point_t *) one;
    ngx_http_upstream_chash_point_t *second =
                                       (ngx_http_upstream_chash_point_t *) two;

    if (first->hash < second->hash) {
        return -1;

    } else if (first->hash > second->hash) {
        return 1;

    } else {
        return 0;
    }
}


static ngx_uint_t
ngx_http_upstream_find_chash_point(ngx_http_upstream_chash_points_t *points,
    uint32_t hash)
{
    ngx_uint_t                        i, j, k;
    ngx_http_upstream_chash_point_t  *point;

    /* find first point >= hash */

    point = &points->point[0];

    i = 0;
    j = points->number;

    while (i < j) {
        k = (i + j) / 2;

        if (hash > point[k].hash) {
            i = k + 1;

        } else if (hash < point[k].hash) {
            j = k;

        } else {
            return k;
        }
    }

    return i;
}


static ngx_int_t
ngx_http_upstream_init_chash_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    uint32_t                             hash;
    ngx_http_upstream_hash_peer_data_t  *hp;
    //ngx_str_t                           *key;
    ngx_http_upstream_xfdf_ip_hash_create_srv_conf_t  *xfdfcf;

    if (ngx_http_upstream_init_hash_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_chash_peer;

    hp = r->upstream->peer.data;
    xfdfcf = ngx_http_conf_upstream_srv_conf(us, ngx_http_upstream_xfdf_ip_hash_module);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "xfdf - the real upstream hash key : \"%V\"",&(hp->key));
    
    hash = ngx_crc32_long(hp->key.data, hp->key.len);

    ngx_http_upstream_rr_peers_rlock(hp->rrp.peers);

    hp->hash = ngx_http_upstream_find_chash_point(xfdfcf->points, hash);

    ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
//    hp->region =	0;
//    #if (NGX_HTTP_UPSTREAM_CHECK)
//       	hp->region =	ngx_http_upstream_request_region(r);
//    #endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_chash_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_hash_peer_data_t  *hp = data;

    time_t                              now;
    intptr_t                            m;
    ngx_str_t                          *server;
    ngx_int_t                           total;
    ngx_uint_t                          i, n, best_i;
    ngx_http_upstream_rr_peer_t        *peer, *best;
    ngx_http_upstream_chash_point_t    *point;
    ngx_http_upstream_chash_points_t   *points;
    ngx_http_upstream_xfdf_ip_hash_create_srv_conf_t  *xfdfcf;
//    ngx_int_t                      need_region =1;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf - get consistent hash peer, try: %ui", pc->tries);

    ngx_http_upstream_rr_peers_wlock(hp->rrp.peers);

    pc->cached = 0;
    pc->connection = NULL;

    now = ngx_time();
    xfdfcf = hp->conf;

    points = xfdfcf->points;
    point = &points->point[0];
    for ( ;; ) {
        server = point[hp->hash % points->number].server;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf - consistent hash peer:%uD, server:\"%V\"", hp->hash, server);

        best = NULL;
        best_i = 0;
        total = 0;

        for (peer = hp->rrp.peers->peer, i = 0;
             peer;
             peer = peer->next, i++)
        {

            n = i / (8 * sizeof(uintptr_t));
            m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

            if (hp->rrp.tried[n] & m) {
                continue;
            }


            if (peer->server.len != server->len
                || ngx_strncmp(peer->server.data, server->data, server->len)
                   != 0)
            {
                continue;
            }

//			#if (NGX_HTTP_UPSTREAM_CHECK)
//        		if (need_region && hp->region!=0 && ngx_http_upstream_get_peer_region(peer)!= hp->region) {
//        			continue;
//        		}
//			#endif

            #if (NGX_HTTP_UPSTREAM_CHECK)
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf - consistent hash peer, check peer down ");
            if (ngx_http_upstream_check_peer_force_down(peer)) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0,"xfdf - consistent peer [%V] is force-down ", &peer->server);
                continue;
            }
            if (ngx_http_upstream_check_peer_down(peer)) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0,"xfdf - consistent peer [%V] is check-down ", &peer->server);
                continue;
            }
			#else
            if (peer->down) {
                continue;
            }
            #endif

            if (peer->max_fails
                && peer->fails >= peer->max_fails
                && now - peer->checked <= peer->fail_timeout)
            {
                continue;
            }

            if (peer->max_conns && peer->conns >= peer->max_conns) {
                continue;
            }

            peer->current_weight += peer->effective_weight;
            total += peer->effective_weight;

            if (peer->effective_weight < peer->weight) {
                peer->effective_weight++;
            }

            if (best == NULL || peer->current_weight > best->current_weight) {
                best = peer;
                best_i = i;
            }
        }

        if (best) {
            best->current_weight -= total;
            goto found;
//        } else if (need_region) {
//        	need_region = 0;
//        	continue;
        }

        hp->hash++;
        hp->tries++;

        if (hp->tries >= points->number) {
            pc->name = hp->rrp.peers->name;
            ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);
            return NGX_BUSY;
        }
    }

found:

    hp->rrp.current = best;

    pc->sockaddr = best->sockaddr;
    pc->socklen = best->socklen;
    pc->name = &best->name;

    best->conns++;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    ngx_http_upstream_rr_peers_unlock(hp->rrp.peers);

    n = best_i / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << best_i % (8 * sizeof(uintptr_t));

    hp->rrp.tried[n] |= m;

    return NGX_OK;
}

/**-- end --**/



/**-- round robin --**/
static ngx_int_t
ngx_http_upstream_init_rr(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_rr_peers_t       *peers;
    //
    if (ngx_http_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }
    peers = us->peer.data;

    ngx_xfdf_init_upstream(cf->pool, peers);
    //
    #if (NGX_HTTP_UPSTREAM_CHECK)
        ngx_http_upstream_rr_peer_t        *peer;

        for (peer = peers->peer; peer; peer = peer->next) {
            ngx_http_upstream_check_add_peer(cf, us, peer);
        }
        //backup server
        if ( (peers = peers->next) ) {
            for (peer = peers->peer; peer; peer = peer->next) {
                ngx_http_upstream_check_add_peer(cf, us, peer);
            }
        }
    #endif
    //
    us->peer.init = ngx_http_upstream_init_rr_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_init_rr_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
	ngx_http_upstream_rr_ex_peer_data_t  *exrrp;

    exrrp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_rr_ex_peer_data_t));
	if (exrrp == NULL) {
		return NGX_ERROR;
	}

    r->upstream->peer.data = &exrrp->rrp;

    if (ngx_http_upstream_init_round_robin_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    r->upstream->peer.get = ngx_http_upstream_get_rr_peer;

	exrrp->region = 0;
	#if (NGX_HTTP_UPSTREAM_CHECK)
		exrrp->region = ngx_http_upstream_request_region(r);
	#endif

    return NGX_OK;
}


static ngx_http_upstream_rr_peer_t *
ngx_http_upstream_get_peer_rr(ngx_peer_connection_t *pc,void *data)
{
	ngx_http_upstream_rr_ex_peer_data_t    *exrrp = data;
	ngx_http_upstream_rr_peer_data_t   *rrp = &exrrp->rrp;
    time_t                        now;
    uintptr_t                     m;
    ngx_int_t                     total,pw;
    ngx_uint_t                    i, n, p;
    ngx_http_upstream_rr_peer_t  *peer, *best;
    ngx_int_t                    need_region = 1;

    now = ngx_time();

    best = NULL;
    total = 0;

#if (NGX_SUPPRESS_WARN)
    p = 0;
#endif

    get_peer:
    for (peer = rrp->peers->peer, i = 0;
         peer;
         peer = peer->next, i++)
    {
		#if (NGX_HTTP_UPSTREAM_CHECK)
    		ngx_uint_t r= ngx_http_upstream_get_peer_region(peer);
    		if(need_region && r!=0 && exrrp->region!=0 && r!= exrrp->region ){
    			continue;
    		}
		#endif
        n = i / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << i % (8 * sizeof(uintptr_t));

        if (rrp->tried[n] & m) {
            continue;
        }

        #if (NGX_HTTP_UPSTREAM_CHECK)
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf - get rr peer, check peer down ");
        ngx_uint_t nut = ngx_http_upstream_check_peer_force_down(peer);
        if (nut) {
        	if(nut == 2) {
                ngx_log_error(NGX_LOG_ERR, pc->log, 0, "xfdf - ip rr peer [%V] is force-down", &peer->server);
        	}
        	continue;
        }
        if (ngx_http_upstream_check_peer_down(peer)) {
            ngx_log_error(NGX_LOG_ERR, pc->log, 0, "xfdf - ip rr peer [%V] is check-down", &peer->server);
            continue;
        }
		#else
        if (peer->down) {
            continue;
        }
        #endif

        if (peer->max_fails
            && peer->fails >= peer->max_fails
            && now - peer->checked <= peer->fail_timeout)
        {
            continue;
        }

        if (peer->max_conns && peer->conns >= peer->max_conns) {
            continue;
        }

        peer->current_weight += peer->effective_weight;
        total += peer->effective_weight;

        pw=peer->weight;
        #if (NGX_HTTP_UPSTREAM_CHECK)
            pw=ngx_http_upstream_get_peer_weight(peer);
        #endif

        if (peer->effective_weight < pw) {
            peer->effective_weight++;
        }else {
        	peer->effective_weight = pw;
        }

        if (best == NULL || peer->current_weight > best->current_weight) {
            best = peer;
            p = i;
        }
    }

    if (best == NULL) {
    	if (need_region){
    		need_region = 0;
    		goto get_peer;
    	}
        return NULL;
    }

    rrp->current = best;

    n = p / (8 * sizeof(uintptr_t));
    m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

    rrp->tried[n] |= m;

    best->current_weight -= total;

    if (now - best->checked > best->fail_timeout) {
        best->checked = now;
    }

    return best;
}


//负载当前访问到后端服务器
static ngx_int_t
ngx_http_upstream_get_rr_peer(ngx_peer_connection_t *pc, void *data)
{
	ngx_http_upstream_rr_ex_peer_data_t    *exrrp = data;
	ngx_http_upstream_rr_peer_data_t  *rrp = &exrrp->rrp;

	ngx_int_t                      rc;
	ngx_uint_t                     i, n;
	ngx_http_upstream_rr_peer_t   *peer;
	ngx_http_upstream_rr_peers_t  *peers;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf --- get rr peer, try: %ui", pc->tries);

	pc->cached = 0;
	pc->connection = NULL;

	peers = rrp->peers;
	ngx_http_upstream_rr_peers_wlock(peers);

	if (peers->single) {
		peer = peers->peer;

		if (peer->down) {
			goto failed;
		}

		if (peer->max_conns && peer->conns >= peer->max_conns) {
			goto failed;
		}

		rrp->current = peer;

	} else {
		peer = ngx_http_upstream_get_peer_rr(pc,exrrp);

		if (peer == NULL) {
			goto failed;
		}

		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,"xfdf --- get rr peer, current: %p %i",peer, peer->current_weight);
	}

	pc->sockaddr = peer->sockaddr;
	pc->socklen = peer->socklen;
	pc->name = &peer->name;

	peer->conns++;

	ngx_http_upstream_rr_peers_unlock(peers);

	return NGX_OK;

failed:

	if (peers->next) {

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "xfdf --- backup servers");

		rrp->peers = peers->next;

		n = (rrp->peers->number + (8 * sizeof(uintptr_t) - 1))
				/ (8 * sizeof(uintptr_t));

		for (i = 0; i < n; i++) {
			rrp->tried[i] = 0;
		}

		ngx_http_upstream_rr_peers_unlock(peers);

		rc = ngx_http_upstream_get_rr_peer(pc, exrrp);

		if (rc != NGX_BUSY) {
			return rc;
		}

		ngx_http_upstream_rr_peers_wlock(peers);
	}

	ngx_http_upstream_rr_peers_unlock(peers);

	pc->name = peers->name;

	return NGX_BUSY;
}

/**-- end --**/
static char *
ngx_http_upstream_hash_var(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_upstream_xfdf_ip_hash_create_loc_conf_t		*xfdflcf = conf;
	ngx_str_t                          *value, *valcnf;
	value = cf->args->elts;
	valcnf = (ngx_str_t *) ((char *) xfdflcf + cmd->offset);
	valcnf->data = value[1].data;
	valcnf->len = value[1].len;
//	xfdflcf->hash_var.data = value[1].data;
//	xfdflcf->hash_var.len = value[1].len;
	return NGX_CONF_OK;
}

static char *
ngx_http_upstream_ip_hash(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf;
    ngx_str_t	*value;
	  u_char deep; 
    ngx_http_upstream_xfdf_ip_hash_create_srv_conf_t  *xfdfcf;

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    if (uscf->peer.init_upstream) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "load balancing method redefined");
    }

    uscf->flags = NGX_HTTP_UPSTREAM_CREATE
                  |NGX_HTTP_UPSTREAM_WEIGHT
                  |NGX_HTTP_UPSTREAM_MAX_CONNS
                  |NGX_HTTP_UPSTREAM_MAX_FAILS
                  |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_HTTP_UPSTREAM_DOWN;

    //
    xfdfcf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_xfdf_ip_hash_module);

    if (xfdfcf == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;
    
    if (ngx_strcmp(value[1].data, "consistent") == 0) { //hash consistent
        uscf->peer.init_upstream = ngx_http_upstream_init_chash;
    } else if (ngx_strcmp(value[1].data, "rr") == 0) { //round_robin
        uscf->peer.init_upstream = ngx_http_upstream_init_rr;
    } else {    //
        deep = (u_char)ngx_atoi(value[1].data, sizeof(u_char) );
        if (deep>0 && deep<5) {
            xfdfcf->deep = deep;
        } else {
            xfdfcf->deep = 3 ;	
        }
        uscf->peer.init_upstream = ngx_http_upstream_init_ip_hash;	
    }

    xfdfcf->remoteaddr_index = ngx_http_get_variable_index(cf, &strremote);

    xfdf_ups = ngx_palloc(cf->pool, sizeof(ngx_http_upstream_xfdf_ups_t));
    xfdf_ups->upstreams = ngx_array_create(cf->pool, 1, sizeof(ngx_http_upstream_xfdf_up_t));
    xfdf_ups->pool = cf->pool;

    return NGX_CONF_OK;

}


static void *
ngx_http_upstream_xfdf_ip_hash_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_xfdf_ip_hash_create_loc_conf_t  *xfdflcf;

    xfdflcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_xfdf_ip_hash_create_loc_conf_t));
    if (xfdflcf == NULL) {
        return NULL;
    }

    xfdflcf->hash_var.len =0;

    return xfdflcf;
}


static char *
ngx_http_upstream_xfdf_ip_hash_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_upstream_xfdf_ip_hash_create_loc_conf_t *prev = parent;
	ngx_http_upstream_xfdf_ip_hash_create_loc_conf_t *conf = child;

    if (conf->hash_var.len == 0) {
        conf->hash_var.data = prev->hash_var.data;
        conf->hash_var.len = prev->hash_var.len;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_upstream_xfdf_ip_hash_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_xfdf_ip_hash_create_srv_conf_t  *xfdfcf;

    xfdfcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_xfdf_ip_hash_create_srv_conf_t));
    if (xfdfcf == NULL) {
        return NULL;
    }

    xfdfcf->deep = 3;

    return xfdfcf;
}
