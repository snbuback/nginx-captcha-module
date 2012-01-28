#ifndef _NGX_CAPTCHA_UTILS_H_INCLUDED_
#define _NGX_CAPTCHA_UTILS_H_INCLUDED_

ngx_int_t write_session_cookie(ngx_http_request_t *r, ngx_str_t *cookie_name, ngx_str_t *cookie_value);
    
#endif

