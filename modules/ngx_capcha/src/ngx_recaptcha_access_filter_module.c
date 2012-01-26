#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>


#include "ngx_recaptcha_access_filter_module.h"

/****** CAPTCHA */
static char * ngx_http_captcha_generate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);




static ngx_int_t ngx_recaptcha_access_filter_install(ngx_conf_t *cf);

static void *
ngx_recaptcha_access_filter_create_conf( ngx_conf_t *cf );

static char *
ngx_recaptcha_access_filter_merge_loc_conf( ngx_conf_t *cf, void *parent, void *child );


static u_char *
ngx_recaptcha_get_request_body( ngx_http_request_t *r );

static void ngx_http_form_input_post_read(ngx_http_request_t *r);

static ngx_int_t
ngx_recaptcha_get_request_parameter_value( ngx_http_request_t *r, u_char *buffer, ngx_str_t *name, ngx_str_t *value );

static ngx_int_t
ngx_recaptcha_get_ip_str( ngx_http_request_t *r, ngx_str_t *addr );


static ngx_int_t
ngx_recaptcha_url_encode( ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst );



static void *chunk_realloc( void *ptr, size_t size ) {
    if ( ptr ) return realloc(ptr, size);
    else return malloc( size );
}



static size_t
write_memory_callback( void *ptr, size_t size, size_t nmemb, void *data ) {
    size_t realsize = size * nmemb;
    ngx_str_t *mem = (ngx_str_t *)data;
 
    mem->data = chunk_realloc(mem->data, mem->len + realsize + 1);
    if ( mem->data ) {
            memcpy(&(mem->data[mem->len]), ptr, realsize);
            mem->len += realsize;
            mem->data[mem->len] = 0;
    }
    return realsize;
}


static ngx_int_t 
ngx_recaptcha_verify_response( ngx_http_request_t *r, ngx_str_t *challenge, ngx_str_t *response ) {
    ngx_int_t   rc;

    u_char      *last = NULL;

    ngx_str_t chunk = ngx_null_string;

    ngx_recaptcha_access_filter_loc_conf_t  *lcf    = NULL;

    ngx_str_t    response_enc   = ngx_null_string;
    ngx_str_t    challenge_enc  = ngx_null_string;
    ngx_str_t    remote_addr    = ngx_null_string;
    ngx_str_t    post_data      = ngx_null_string;


    ngx_str_t   privatekey_key  = ngx_string("privatekey");
    ngx_str_t   challenge_key   = ngx_string("challenge");
    ngx_str_t   response_key    = ngx_string("response");
    ngx_str_t   remoteip_key    = ngx_string("remoteip");


    CURL        *curl           = NULL;
    CURLcode     res;

    
    rc = ngx_recaptcha_get_ip_str( r, &remote_addr );
    if ( rc != NGX_OK ) {       
        ngx_log_error( NGX_LOG_ERR, r->connection->log, 0, "while retrieving remote address" );
        return NGX_ERROR;
    }

    ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "remote address: %s", remote_addr.data );

    rc = ngx_recaptcha_url_encode( r->pool, challenge, &challenge_enc );
    if ( rc != NGX_OK ) {
        ngx_log_error( NGX_LOG_ERR , r->connection->log, 0, "while url encoding %s", challenge->data );
        return NGX_ERROR;
    }

    rc = ngx_recaptcha_url_encode( r->pool, response, &response_enc );
    if ( rc != NGX_OK ) {
        ngx_log_error( NGX_LOG_ERR , r->connection->log, 0, "while url encoding %s", response->data );
        return NGX_ERROR;
    }


    lcf = ngx_http_get_module_loc_conf( r, ngx_recaptcha_access_filter_module );

    post_data.len =  (privatekey_key.len   + 1);    // privatekey=
    post_data.len += (lcf->private_key.len + 1);    // XXXXX&
    post_data.len += (challenge_key.len    + 1);    // challenge=
    post_data.len += (challenge_enc.len    + 1);    // YYYYY&
    post_data.len += (response_key.len     + 1);    // response=
    post_data.len += (response_enc.len     + 1);    // ZZZZZ&
    post_data.len += (remoteip_key.len     + 1);    // remoteip=
    post_data.len += (remote_addr.len      + 1);    // WWWWW&

    post_data.data = ngx_pcalloc( r->pool, post_data.len + 1 );
    if ( post_data.data == NULL ) {
        ngx_log_error( NGX_LOG_ERR , r->connection->log, 0, "while allocating memory for <post_data>" );
        return NGX_ERROR;   
    }
    last = ngx_copy( post_data.data, privatekey_key.data, privatekey_key.len );
    last = ngx_copy( last, "=", 1 );
    last = ngx_copy( last, lcf->private_key.data, lcf->private_key.len );

    last = ngx_copy( last, "&", 1 );

    last = ngx_copy( last, challenge_key.data, challenge_key.len );
    last = ngx_copy( last, "=", 1 );
    last = ngx_copy( last, challenge_enc.data, challenge_enc.len );

    last = ngx_copy( last, "&", 1 );

    last = ngx_copy( last, response_key.data, response_key.len );
    last = ngx_copy( last, "=", 1 );
    last = ngx_copy( last, response_enc.data, response_enc.len );

    last = ngx_copy( last, "&", 1 );

    last = ngx_copy( last, remoteip_key.data, remoteip_key.len );
    last = ngx_copy( last, "=", 1 );
    last = ngx_copy( last, remote_addr.data, remote_addr.len );

    *last = (u_char)'\0';
    
    ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "post_data = <%s>", post_data.data );
    
    curl_global_init( CURL_GLOBAL_ALL );

    curl = curl_easy_init();
    // Should I use CURLOPT_TIMEOUT option ?
    curl_easy_setopt( curl, CURLOPT_VERBOSE, 1 );
    curl_easy_setopt( curl, CURLOPT_USERAGENT, r->headers_in.user_agent->value.data );
    curl_easy_setopt( curl, CURLOPT_FOLLOWLOCATION, 1 );

    curl_easy_setopt( curl, CURLOPT_URL, lcf->verify_url.data );
    curl_easy_setopt( curl, CURLOPT_WRITEFUNCTION, write_memory_callback );
    curl_easy_setopt( curl, CURLOPT_WRITEDATA, (void *)&chunk );
    curl_easy_setopt( curl, CURLOPT_POSTFIELDS, (void*)post_data.data );
    curl_easy_setopt( curl, CURLOPT_POSTFIELDSIZE, post_data.len ); 

    res = curl_easy_perform(curl);
    if ( res != CURLE_OK ) {
        ngx_log_error( NGX_LOG_ERR , r->connection->log, 0, "curl_easy_perform failed: %s", curl_easy_strerror(res) );
        curl_easy_cleanup(curl);
        return NGX_ERROR;
    }

    curl_easy_cleanup( curl );

    rc = NGX_ERROR;
    if ( chunk.data ) {     
        char *p = (char*)strtok( (char*)chunk.data, "\n");
        if( p == NULL ) {
            ngx_log_error( NGX_LOG_WARN, r->connection->log, 0, "while parsing Google response" );
            return NGX_ERROR;
        }

        if ( strcmp(p, "true") == 0 ) {
            rc = NGX_OK;        
        } else {
            rc = NGX_ERROR;
            p = (char*)strtok( (char*)NULL, "\n" );
            if(  p != NULL ) {
                ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "not verified because: %s", p );
            }
        }
        ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Google response: %s", chunk.data );
    }

    return rc;
}



/* Module's directives  */
static ngx_command_t  ngx_recaptcha_access_filter_commands[] = 
{
    {   ngx_string("recaptcha"),                    
        NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_FLAG,  
        ngx_conf_set_flag_slot,                             
        NGX_HTTP_LOC_CONF_OFFSET,                           
        offsetof(ngx_recaptcha_access_filter_loc_conf_t, enable),   
        NULL },

    {   ngx_string("recaptcha_private_key"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_recaptcha_access_filter_loc_conf_t, private_key),
        NULL },

    {   ngx_string("recaptcha_verify_url"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_recaptcha_access_filter_loc_conf_t, verify_url),
        NULL },

    {   ngx_string("captcha_generate"),                    
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,  
        ngx_http_captcha_generate,                             
        0,                           
        0,   
        NULL },

        ngx_null_command
};


/* The Module Context */
static ngx_http_module_t  ngx_recaptcha_access_filter_module_ctx = {
    NULL,                               /* preconfiguration */
    ngx_recaptcha_access_filter_install,    /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_recaptcha_access_filter_create_conf,        /* create location configuration */
    ngx_recaptcha_access_filter_merge_loc_conf  /* merge location configuration */
};


/* Module Definition */
ngx_module_t  ngx_recaptcha_access_filter_module = {
    NGX_MODULE_V1,
    &ngx_recaptcha_access_filter_module_ctx,       /* module context */
    ngx_recaptcha_access_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};



static ngx_int_t
ngx_recaptcha_access_filter_handler(ngx_http_request_t *r) {
    ngx_int_t   rc;

    ngx_recaptcha_access_filter_ctx_t       *ctx    = NULL;
    ngx_recaptcha_access_filter_loc_conf_t  *lcf    = NULL;
    
    ngx_str_t   challenge_key   = ngx_string("recaptcha_challenge_field");
    ngx_str_t   challenge_val   = ngx_null_string;

    ngx_str_t   response_key    = ngx_string("recaptcha_response_field");
    ngx_str_t   response_val    = ngx_null_string;

    u_char      *buffer     = NULL;


    lcf = ngx_http_get_module_loc_conf(r, ngx_recaptcha_access_filter_module);
    if (!lcf->enable ) {
        return NGX_OK;
    }


    /* Create a new context */
    ctx = ngx_pcalloc(r->pool, sizeof(ngx_recaptcha_access_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_recaptcha_access_filter_module);
    
    ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "client request body successfully read" );

    /* Begin to read POST data */
    rc = ngx_http_read_client_request_body(r, ngx_http_form_input_post_read);
    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    if (rc == NGX_AGAIN) {
        ctx->waiting_more_body = 1;
        return NGX_AGAIN;
    }

    /* Now we have post data */
    ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "client request body successfully read" );
    
    /* Retrieve username and pasword */
    buffer = ngx_recaptcha_get_request_body( r );   
    if ( buffer == NULL ) {
        return NGX_HTTP_FORBIDDEN;
    }

    rc = ngx_recaptcha_get_request_parameter_value( r, buffer, &challenge_key, &challenge_val );
    if ( rc != NGX_OK ) {
        ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request parameter %s not found", challenge_key.data );
        return NGX_HTTP_FORBIDDEN;
    }   

    ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s value is %s", challenge_key.data, challenge_val.data );

    rc = ngx_recaptcha_get_request_parameter_value( r, buffer, &response_key, &response_val );
    if ( rc != NGX_OK ) {
        ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request parameter %s not found", response_key.data );
        return NGX_HTTP_FORBIDDEN;
    }   

    ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s value is %s", response_key.data, response_val.data );

    rc = ngx_recaptcha_verify_response( r, &challenge_val, &response_val );
    if ( rc != NGX_OK ) {
        ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "captcha not verified" );
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}




static ngx_int_t
ngx_recaptcha_access_filter_install(ngx_conf_t *cf) {

    ngx_http_handler_pt        *h = NULL;
    ngx_http_core_main_conf_t  *cmcf = NULL;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_recaptcha_access_filter_handler;

    return NGX_OK;
}


static void *
ngx_recaptcha_access_filter_create_conf(ngx_conf_t *cf) {

    ngx_recaptcha_access_filter_loc_conf_t *conf;


    conf = ngx_pcalloc(cf->pool, sizeof(ngx_recaptcha_access_filter_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->enable                = NGX_CONF_UNSET;

    conf->private_key.data  = NULL;
    conf->private_key.len   = 0;

    conf->verify_url.data   = NULL;
    conf->verify_url.len    = 0;

    return conf;
}


static char *
ngx_recaptcha_access_filter_merge_loc_conf( ngx_conf_t *cf, void *parent, void *child ) {

    ngx_recaptcha_access_filter_loc_conf_t *prev = parent;
    ngx_recaptcha_access_filter_loc_conf_t *conf = child;

    ngx_conf_merge_str_value( conf->private_key, prev->private_key, "null" );
    ngx_conf_merge_str_value( conf->verify_url, prev->verify_url, "http://www.google.com/recaptcha/api/verify" );
    ngx_conf_merge_value( conf->enable, prev->enable, 0 );

    return NGX_CONF_OK;
}


static u_char *
ngx_recaptcha_get_request_body( ngx_http_request_t *r ) {
    u_char          *buffer = NULL;
    u_char          *p  = NULL, *last = NULL;
    ngx_chain_t     *cl = NULL;
    ngx_int_t       len = 0;


    /* we read data from r->request_body->bufs */
    if ( r->request_body == NULL) {
        return NULL;
    }
    
    if (r->request_body->bufs == NULL) {
        return NULL;
    }

    /* calculate the length of the post data */
    len = 0;
    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        len += (ngx_int_t)(cl->buf->last - cl->buf->pos);
    }

    //ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "content length = %d", len );
    
    //if ( (len == 0) || (len > NGX_FASTSSO_LOGIN_MAX_CONTENT_LEN) ) {
    //    return NULL;
    //}

    buffer = ngx_palloc( r->pool, len + 1);
    if (buffer == NULL) {
        return NULL;
    }

    for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
        p = ngx_copy(buffer, cl->buf->pos, (cl->buf->last - cl->buf->pos));
    }

    p = buffer;
    last = p + len;
    *last = '\0';

            
    return buffer;
}



static ngx_int_t
ngx_recaptcha_get_request_parameter_value( ngx_http_request_t *r, u_char *buffer, ngx_str_t *name, ngx_str_t *value ) {
    
    u_char              *p      = NULL;
    u_char              *v      = NULL; 
    u_char              *last   = NULL;
 
    value->data = NULL;
    value->len = 0;

    if ( buffer == NULL ) {
        return NGX_ERROR;
    }

    ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "searching for %s (%d)", name->data, name->len );

    last = buffer + ngx_strlen( buffer ) ;
    
    for ( p = buffer; p < last; p++ ) {
        // we need '=' after name, so drop one char from last 
        p = ngx_strlcasestrn(p, last - 1, name->data, name->len - 1);
        if ( p == NULL ) {
            return NGX_ERROR;
        }

        if ((p == buffer || *(p - 1) == '&') && *(p + name->len) == '=') {
            size_t val_len = 0; 
            size_t dst_len = 0;

            v = p + name->len + 1;
            
            p = ngx_strlchr(p, last, '&');
            if (p == NULL) {
                p = last;
            }
            
            val_len = (p-v);
            
            /* Allocate buffer for request parameter value */
            value->data = ngx_pcalloc(r->pool, val_len + 1);
            if ( value->data == NULL ) {
                ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "--->> BOOOM" );
                return NGX_ERROR;
            }
            /* Unescape parameter value */
            dst_len = (size_t)value->data;
            ngx_unescape_uri(&value->data, &v, val_len, NGX_UNESCAPE_URI);
            dst_len = (size_t) value->data - dst_len;
            *(value->data) = '\0';
            value->data -= dst_len;            
            value->len = dst_len;

            return NGX_OK;
        }
    }

    return ( (value->data == NULL) ? NGX_ERROR: NGX_OK );
}


static void ngx_http_form_input_post_read(ngx_http_request_t *r)
{
    ngx_recaptcha_access_filter_ctx_t     *ctx = NULL;

    r->read_event_handler = ngx_http_request_empty_handler;

    ctx = ngx_http_get_module_ctx(r, ngx_recaptcha_access_filter_module);
    ctx->done = 1;

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif

    /* waiting_more_body my rewrite phase handler */
    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;
        ngx_http_core_run_phases(r);
    }
}


static ngx_int_t
ngx_recaptcha_get_ip_str( ngx_http_request_t *r, ngx_str_t *addr ) {
    u_char *last = NULL;

    struct sockaddr *sa = r->connection->sockaddr;

    switch ( sa->sa_family ) {
        case AF_INET:
            addr->len = INET_ADDRSTRLEN;
            break;

        case AF_INET6:
            addr->len = INET6_ADDRSTRLEN;
            break;

        default:
            addr->len = strlen("unknown-AF") + 1;
    }

    addr->data = ngx_pcalloc( r->pool, addr->len );
    if ( addr->data == NULL ) {
        addr->len = 0;
        return NGX_ERROR;           
    }

    switch( sa->sa_family ) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), (char *)addr->data, INET_ADDRSTRLEN);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), (char *)addr->data, INET6_ADDRSTRLEN);
            break;

        default:
            last = ngx_copy( addr->data, "unknown-AF", addr->len );
            *last = (u_char)'\0';
    }

    return NGX_OK;
}


static ngx_int_t
ngx_recaptcha_url_encode( ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst ) {
    dst->len  = src->len + 2 * ngx_escape_uri(NULL, src->data, src->len, NGX_ESCAPE_URI );  
    dst->data = ngx_pcalloc( pool, dst->len + 1 );
    if ( !dst->data ) {
        return NGX_ERROR;
    }
    
    ngx_escape_uri( dst->data, src->data, src->len, NGX_ESCAPE_URI );

    return NGX_OK;  
}

/********** GERACAO DO CAPTCHA ********/

static u_char ngx_hello_string[] = "Hello, world!";

static ngx_int_t
ngx_http_captcha_generate_handler(ngx_http_request_t *r)
{
    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;
 
    /* we response to 'GET' and 'HEAD' requests only */
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }
 
    /* discard request body, since we don't need it here */
    rc = ngx_http_discard_request_body(r);
 
    if (rc != NGX_OK) {
        return rc;
    }
 
    /* set the 'Content-type' header */
    r->headers_out.content_type_len = sizeof("text/html") - 1;
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
 
    /* send the header only, if the request type is http 'HEAD' */
    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = sizeof(ngx_hello_string) - 1;
 
        return ngx_http_send_header(r);
    }
 
    /* allocate a buffer for your response body */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
 
    /* attach this buffer to the buffer chain */
    out.buf = b;
    out.next = NULL;
 
    /* adjust the pointers of the buffer */
    b->pos = ngx_hello_string;
    b->last = ngx_hello_string + sizeof(ngx_hello_string) - 1;
    b->memory = 1;    /* this buffer is in memory */
    b->last_buf = 1;  /* this is the last buffer in the buffer chain */
 
    /* set the status line */
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = sizeof(ngx_hello_string) - 1;
 
    /* send the headers of your response */
    rc = ngx_http_send_header(r);
 
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
 
    /* send the buffer chain of your response */
    return ngx_http_output_filter(r, &out);
}


static char *
ngx_http_captcha_generate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
 
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_captcha_generate_handler; /* handler to process the 'hello' directive */
 
    return NGX_CONF_OK;
}








