RECIPE=master WITH_IPV6=false /opt/local/etc/unbound/entrypoint.sh > /opt/local/etc/unbound/conf.d/ads.conf
#unbound-control reload
/opt/local/sbin/unbound-control reload
