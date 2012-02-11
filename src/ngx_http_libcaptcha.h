
#define CAPTCHA_BUFFER 17646 // gif size

#define NDOTS 100

// captcha image size
#define CAPTCHA_WIDTH   200
#define CAPTCHA_HEIGHT  70

extern char *lt[];

//void captcha(unsigned char im[70*200], unsigned char l[6]);
//void makegif(unsigned char im[70*200], unsigned char gif[CAPTCHA_BUFFER]);


/**
 * Generate a captcha for specified text.
 */
void simple_captcha_generate(u_char *gif, const ngx_str_t *captcha_text);


