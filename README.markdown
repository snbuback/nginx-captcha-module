# NGINX Captcha Filter

## Info

This is a nginx module that works like a filter, validating a captcha. The same module renders
a captcha e use memcached to store correct response.

## Requirements

* libmemcached
* nginx (1.0.11)

## build

	curl http://nginx.org/download/nginx-1.0.11.tar.gz | tar -zxv -
	git clone git://github.com/snbuback/nginx-captcha-module.git
	cd nginx-captcha-module
	make configure
	make build
	make start
	open "http://localhost:8080/form.html"
	
