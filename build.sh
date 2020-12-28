#nginx version you need
version=1.14.0

cd /usr/local/nginxplugin
cd nginx-$version

make clean
./configure --with-stream  --with-http_ssl_module --with-http_realip_module --add-module=../ngx_xfdf_ip_hash_module --add-module=../ngx_healthcheck_module --add-module=../ngx_http_endpoint_module
#--add-module=../ngx_xfdf_ip_hash_module
#--add-module=../ngx_http_endpoint_module
# --add-module=../ngx_healthcheck_module

make
sudo make install

echo finish!
