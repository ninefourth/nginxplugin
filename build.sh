# download nginx source and put to this folder
# /usr/local/nginxplugin/nginx.x.x.x
# put all module to folder /usr/local/nginxplugin include me

#nginx version you need, for example 1.14.0
version=1.14.0

cd /usr/local/nginxplugin
cd nginx-$version

make clean
./configure --with-stream  --with-http_ssl_module --with-http_realip_module --add-module=../ngx_xfdf_ip_hash_module --add-module=../ngx_healthcheck_module --add-module=../ngx_http_endpoint_module
#--add-module=../ngx_xfdf_ip_hash_module
#--add-module=../ngx_http_endpoint_module
# --add-module=../ngx_healthcheck_module

make
make install

echo finish!
