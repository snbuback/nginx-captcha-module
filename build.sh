#!/bin/bash

NGINX_DIR=../nginx-1.0.11
TMPDIR=/tmp/nginx

pushd .
cd $NGINX_DIR
./configure --with-debug --pid-path=$TMPDIR/nginx.pid --error-log-path=$TMPDIR/error.log --http-log-path=$TMPDIR/access.log --http-client-body-temp-path=$TMPDIR/cbt --http-proxy-temp-path=$TMPDIR/proxy --http-fastcgi-temp-path=$TMPDIR/fast --http-uwsgi-temp-path=$TMPDIR/uwsgi --http-scgi-temp-path=$TMPDIR/scgi --add-module=../nginx-captcha-module && \
make -j2
popd


