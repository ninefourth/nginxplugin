#download
version=1.14.0
echo ============download nginx code.
cd /usr/local/nginxplugin
cd nginx-$version

echo ============apply patch

#git apply ../ngx_healthcheck_module/nginx_healthcheck_for_nginx_1.14+.patch

echo ===========begin build nginx

make clean

#./configure --with-debug --with-stream --add-module=../ngx_healthcheck_module --with-http_ssl_module --with-http_realip_module
#./configure --with-debug --with-stream --with-http_ssl_module --with-http_realip_module  --add-module=../ngx_xfdf_ip_hash_module --add-module=../ngx_healthcheck_module

#./configure --with-stream --with-http_ssl_module --with-http_realip_module  --add-module=../ngx_xfdf_ip_hash_module --add-module=../ngx_healthcheck_module --add-module=../ngx_http_dyups_module
./configure --with-stream  --with-http_ssl_module --with-http_realip_module --add-module=../ngx_xfdf_ip_hash_module --add-module=../ngx_healthcheck_module --add-module=../ngx_http_endpoint_module
#--add-module=../ngx_xfdf_ip_hash_module
#--add-module=../ngx_http_endpoint_module
# --add-module=../ngx_healthcheck_module
 #--add-module=../ngx_http_dyups_module

#./configure --with-debug --with-stream --with-http_ssl_module --with-http_realip_module  --add-module=../ngx_healthcheck_module
#./configure --with-debug --with-stream --with-http_ssl_module --with-http_realip_module  --add-module=../ngx_xfdf_ip_hash_module

make
sudo make install

echo ===========start nginx
echo finish!
