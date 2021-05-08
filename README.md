##nginx插件##
- ngx_healthcheck_module　检测upstream server
- ngx_xfdf_ip_hash_module upstream使用客户端 x-forwarded-for首ip做hash
- ngx_http_endpoint_module 提供对外端点，用于外部干预nginx 

./configure  --with-stream  --with-http_ssl_module --with-http_realip_module --add-module=./plugin/ngx_xfdf_ip_hash_module --add-module=./plugin/ngx_healthcheck_module --add-module=./plugin/ngx_http_endpoint_module