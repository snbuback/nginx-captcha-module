#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_captcha_utils.h"

const ngx_str_t SET_COOKIE_HEADER_TEMPLATE = ngx_string("%s=%s; Expires=-1; Path=/; HttpOnly");
const ngx_str_t SET_COOKIE_HEADER = ngx_string("Set-Cookie");

/**
 * Write a Set-Cookie header in response.
 */
ngx_int_t write_session_cookie(ngx_http_request_t *r, const ngx_str_t *cookie_name, const ngx_str_t *cookie_value) {
    
    // Validate arguments
    if (!(cookie_name && cookie_name->data && cookie_value && cookie_value->data)) {
        return NGX_ERROR;
    }
    
    // allocate memory for cookie header
    ngx_str_t *cookie_header = ngx_palloc(r->pool, sizeof(ngx_str_t));
    cookie_header->data = ngx_palloc(r->pool, sizeof(u_char)*(SET_COOKIE_HEADER_TEMPLATE.len + cookie_name->len + cookie_value->len + 1));
    
    cookie_header->len = sprintf((char*) cookie_header->data, (char*) SET_COOKIE_HEADER_TEMPLATE.data, cookie_name->data, cookie_value->data);
    
    return write_custom_header(r, &SET_COOKIE_HEADER, cookie_header);
}

/**
 * Write a custom header in response
 */
ngx_int_t write_custom_header(ngx_http_request_t *r, const ngx_str_t *name, const ngx_str_t *value) {
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
    set_custom_header->key.len = name->len;
    set_custom_header->key.data = name->data;
    set_custom_header->value.len = value->len;
    set_custom_header->value.data = value->data;

    return NGX_OK;
}


