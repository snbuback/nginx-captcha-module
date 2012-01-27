#include <string.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>


#include "ngx_recaptcha_access_filter_module.h"
#include "ngx_http_libcaptcha.h"

/****** CAPTCHA */
static char * ngx_http_captcha_generate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
int escreve_cookie_sessao(ngx_http_request_t *r, ngx_str_t *cookie_name, ngx_str_t *cookie_value);
ngx_int_t verifica_captcha(ngx_http_request_t *r, ngx_str_t resposta, ngx_str_t chave);


/** MEMCACHED */
typedef int bool;
#include <libmemcached/memcached.h>

// const char *config_string= "--SERVER=localhost:11211 --BINARY-PROTOCOL --CONNECT-TIMEOUT=1000 --TCP-NODELAY --TCP-KEEPALIVE --SND-TIMEOUT=1000 --RCV-TIMEOUT=1000";
const char *config_string= "--SERVER=localhost:11211";
static memcached_st * memc = NULL;



/** END MEMCACHED */

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

    //rc = ngx_recaptcha_get_request_parameter_value( r, buffer, &challenge_key, &challenge_val );
    //if ( rc != NGX_OK ) {
    //    ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request parameter %s not found", challenge_key.data );
    //    return NGX_HTTP_FORBIDDEN;
    //}   

    //ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s value is %s", challenge_key.data, challenge_val.data );

    rc = ngx_recaptcha_get_request_parameter_value( r, buffer, &response_key, &response_val );
    if ( rc != NGX_OK ) {
        ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request parameter %s not found", response_key.data );
        return NGX_HTTP_FORBIDDEN;
    }   

    ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s value is %s", response_key.data, response_val.data );

    rc = verifica_captcha( r, response_val, response_val );
    if ( rc != NGX_OK ) {
        ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "captcha not verified" );
        return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}


ngx_int_t verifica_captcha(ngx_http_request_t *r, ngx_str_t resposta, ngx_str_t chave) {
    
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
    
    // Configura o memcached
    memc = memcached(config_string, strlen(config_string));
    
    // FIXME Incluir código para liberar conexao do memcached
    //memcached_free(memc);
    

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

/********** GERACAO DO CAPTCHA ********/


/**
 * Dada uma sequencia de opções de tamanho max_opcoes, gera uma string no buffer de tamanho
 * max_tam com caracteres aleatórios de opcoes.
 */
static void generate_random_string(ngx_str_t* buffer, const ngx_str_t* options) {
    
    u_int i;
    for (i=0; i<buffer->len; i++) {
        buffer->data[i] = options->data[ngx_random() % options->len];
    }
}

static ngx_int_t
ngx_http_captcha_generate_handler(ngx_http_request_t *r)
{
    ngx_int_t    rc;
    ngx_buf_t   *b;
    ngx_chain_t  out;

    ngx_recaptcha_access_filter_ctx_t       *ctx    = NULL;

    ngx_str_t   response_key    = ngx_string("valor_captcha");
    ngx_str_t   response_val    = ngx_null_string;

    u_char      *buffer     = NULL;

    /* we response to 'GET' and 'HEAD' requests only */
   if (r->method & (NGX_HTTP_POST)) {
        /* Create a new context */
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_recaptcha_access_filter_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_recaptcha_access_filter_module);
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
        rc = ngx_recaptcha_get_request_parameter_value( r, buffer, &response_key, &response_val );
        if ( rc != NGX_OK ) {
            ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "request parameter %s not found", response_key.data );
            return NGX_HTTP_FORBIDDEN;
        } 
        
        
        rc = verifica_captcha( r, response_val, response_val );
        if ( rc != NGX_OK ) {
            ngx_log_debug( NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "\n\n\n\n\ncaptcha not verified\n\n\n\n\n" );
            return NGX_HTTP_FORBIDDEN;
        }
        
    }

    if (!(r->method & (NGX_HTTP_GET))) {
        return NGX_HTTP_NOT_ALLOWED;
    }
 
    /* discard request body, since we don't need it here */
    rc = ngx_http_discard_request_body(r);
 
    if (rc != NGX_OK) {
        return rc;
    }
 
    /* set the 'Content-type' header */
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_type.len = sizeof("image/gif") - 1;
    r->headers_out.content_type.data = (u_char *) "image/gif";
//    r->headers_out.content_length_n = 100;
    
    /* allocate a buffer for your response body */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
 
    /* attach this buffer to the buffer chain */
    out.buf = b;
    out.next = NULL;
    
    // Gera a imagem
    u_char imagem[70*200];
    u_char resposta[7];
    u_char gif[gifsize];
    
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "Teste numeros aleatorias: %ld\n", ngx_random());

    resposta[6] = 0; // string em C precisam de um \0
    char chave[10];
    
    ngx_str_t ngx_chave = ngx_string(chave);
    ngx_str_t COMBINACOES = ngx_string("0123456789abcdefgihjk");
    
    generate_random_string(&ngx_chave, &COMBINACOES);
    
    captcha(imagem, resposta);
    makegif(imagem, gif);
    
    ngx_str_t cookie_name = ngx_string("CAPTCHA");
    ngx_str_t cookie_value = ngx_chave;
    
    escreve_cookie_sessao(r, &cookie_name, &cookie_value);
    

    // TODO Permitir configurar o tempo de expiração
    memcached_return_t mc_rc = memcached_set(memc, (char*) ngx_chave.data, ngx_chave.len, (char*)resposta, strlen((char*)resposta), (time_t) 10000, (uint32_t)0);
    if (mc_rc != MEMCACHED_SUCCESS) {
        ngx_log_error(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "Problemas ao escrever no memcached");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

 
    /* adjust the pointers of the buffer */
    b->pos = gif;
    b->last = gif + gifsize - 1;
    b->memory = 1;    /* this buffer is in memory */
    b->last_buf = 1;  /* this is the last buffer in the buffer chain */
 
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


int escreve_cookie_sessao(ngx_http_request_t *r, ngx_str_t *cookie_name, ngx_str_t *cookie_value) {
    ngx_table_elt_t  *set_cookie;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "\n\n\nChamado código escreve_cookie_sessao\n\n\n");
    
    //Set-Cookie: lu=Rg3vHJZnehYLjVg7qi3bZjzg; Expires=Tue, 15 Jan 2013 21:47:38 GMT; Path=/; Domain=.foo.com; HttpOnly    
    char COOKIE_TEMPLATE[] = "%s=%s; Expires=-1; Path=/; HttpOnly";
    
    // FIXME
    char* cookie_header = (char*) malloc(100);
    sprintf(cookie_header, COOKIE_TEMPLATE, cookie_name->data, cookie_value->data/*, "localhost"*/);
    
    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }

    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = strlen(cookie_header);
    set_cookie->value.data = (u_char*) cookie_header;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%V\"", &set_cookie->value);

    return NGX_OK;
}





