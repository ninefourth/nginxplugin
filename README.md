##nginx插件##
- ngx_healthcheck_module　检测upstream server
- ngx_xfdf_ip_hash_module upstream使用客户端 x-forwarded-for首ip做hash
- ngx_http_endpoint_module 提供对外端点，用于外部干预nginx 
- ngx_http_waf_module 修改的waf防火墙
- ngx_http_request_chain_module 自定义request filter

./configure --with-cc-opt='-std=gnu99' --with-stream  --with-http_ssl_module --with-http_realip_module --add-module=./plugin/ngx_xfdf_ip_hash_module --add-module=./plugin/ngx_healthcheck_module --add-module=./plugin/ngx_http_endpoint_module --add-module=./plugin/ngx_http_request_log_module --add-module=./plugin/ngx_http_waf_module

./configure --with-ld-opt=-Wl,-rpath,/usr/local/lib --with-stream  --with-http_ssl_module --with-http_realip_module --add-module=./plugin/ngx_xfdf_ip_hash_module --add-module=./plugin/ngx_healthcheck_module --add-module=./plugin/ngx_http_endpoint_module --add-module=./opts/ngx_devel_kit-0.2.19 --add-module=./opts/lua-nginx-module-master