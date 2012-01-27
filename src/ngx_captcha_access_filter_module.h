#ifndef _NGX_CAPTCHA_ACCESS_FILTER_H_INCLUDED_
#define _NGX_CAPTCHA_ACCESS_FILTER_H_INCLUDED_



typedef struct {
	ngx_flag_t	 enable;
	ngx_str_t  	 private_key;
	ngx_str_t  	 verify_url;
	
} ngx_captcha_access_filter_loc_conf_t;



/*
 *	Post data reader callback struct
 */
typedef struct {
    ngx_flag_t          done:1;
    ngx_flag_t          waiting_more_body:1;

} ngx_captcha_access_filter_ctx_t;



extern ngx_module_t  ngx_captcha_access_filter_module;

#endif 

