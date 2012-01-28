#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_captcha_utils.h"

const ngx_str_t SET_COOKIE_HEADER_TEMPLATE = ngx_string("%s=%s; Expires=-1; Path=/; HttpOnly");


/**
 * Write a Set-Cookie header in response.
 */
ngx_int_t write_session_cookie(ngx_http_request_t *r, ngx_str_t *cookie_name, ngx_str_t *cookie_value) {
    ngx_table_elt_t  *set_cookie;
    
    // Validate arguments
    if (!(cookie_name && cookie_name->data && cookie_value && cookie_value->data)) {
        return NGX_ERROR;
    }
    
    // allocate memory for cookie header
    ngx_str_t cookie_header = ngx_null_string;
    cookie_header.data = ngx_palloc(r->pool, sizeof(u_char)*(SET_COOKIE_HEADER_TEMPLATE.len + cookie_name->len + cookie_value->len + 1));
    
    cookie_header.len = sprintf((char*) cookie_header.data, (char*) SET_COOKIE_HEADER_TEMPLATE.data, cookie_name->data, cookie_value->data);
    
    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "erro writing cookie '%s'='%s'", cookie_name->data, cookie_value->data);
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value = cookie_header;

    return NGX_OK;
}

/**
 * Write a custom header in response
 */
ngx_int_t write_custom_header(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *value) {
    ngx_table_elt_t  *set_custom_header;
    
    // Validate arguments
    if (!(name && name->data && value && value->data)) {
        return NGX_ERROR;
    }
    
    set_custom_header = ngx_list_push(&r->headers_out.headers);
    if (set_custom_header == NULL) {
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "erro writing custom header '%s: %s'", name->data, value->data);
        return NGX_ERROR;
    }

    set_custom_header->hash = 1;
    ngx_str_set(&set_custom_header->key, name->data);
    ngx_str_set(&set_custom_header->value, value->data);

    return NGX_OK;
}


