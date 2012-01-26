#ifndef _CAPTCHA

extern int gifsize;
extern char *lt[];

char gen_captcha();
char captcha_challenge();
void captcha(unsigned char im[70*200], unsigned char l[6]);
void makegif(unsigned char im[70*200], unsigned char gif[gifsize]);

#endif
