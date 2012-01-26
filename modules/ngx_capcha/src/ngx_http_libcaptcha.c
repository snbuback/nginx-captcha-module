#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include "ngx_http_libcaptcha.h"

//const int gifsize;
//static char *lt[];
int gifsize=17646;

void captcha(unsigned char im[70*200], unsigned char l[6]);
void makegif(unsigned char im[70*200], unsigned char gif[gifsize]);


void makegif(unsigned char im[70*200], unsigned char gif[gifsize])
{
 	// tag ; widthxheight ; GCT:0:0:7 ; bgcolor + aspect // GCT
 	// Image Separator // left x top // widthxheight // Flags
	// LZW code size
	memcpy(gif,"GIF89a" "\xc8\0\x46\0" "\x83" "\0\0"
		"\x00\x00\x00"
		"\x10\x10\x10"
		"\x20\x20\x20"
		"\x30\x30\x30"
		"\x40\x40\x40"
		"\x50\x50\x50"
		"\x60\x60\x60"
		"\x70\x70\x70"
		"\x80\x80\x80"
		"\x90\x90\x90"
		"\xa0\xa0\xa0"
		"\xb0\xb0\xb0"
		"\xc0\xc0\xc0"
		"\xd0\xd0\xd0"
		"\xe0\xe0\xe0"
		"\xff\xff\xff"
		"," "\0\0\0\0" "\xc8\0\x46\0" "\0" "\x04",13+48+10+1);

	int x,y;
	unsigned char *i=im;
	unsigned char *p=gif+13+48+10+1;
	for(y=0;y<70;y++)
	{
		*p++=250; // Data length 5*50=250
		for(x=0;x<50;x++)
		{
			unsigned char a=i[0]>>4,b=i[1]>>4,c=i[2]>>4,d=i[3]>>4;

			p[0]=16|(a<<5);			// bbb10000
			p[1]=(a>>3)|64|(b<<7);	// b10000xb
			p[2]=b>>1;			// 0000xbbb
			p[3]=1|(c<<1);		// 00xbbbb1
			p[4]=4|(d<<3);		// xbbbb100
			i+=4;
			p+=5;
		}
	}

 	// Data length // End of LZW (b10001) // Terminator // GIF End
	memcpy(gif+gifsize-4,"\x01" "\x11" "\x00" ";",4);
	return;
}

static const char sw[200]={0, 4, 8, 12, 16, 20, 23, 27, 31, 35, 39, 43, 47, 50, 54, 58, 61, 65, 68, 71, 75, 78, 81, 84, 87, 90, 93, 96, 98, 101, 103, 105, 108, 110, 112, 114, 115, 117, 119, 120, 121, 122, 123, 124, 125, 126, 126, 127, 127, 127, 127, 127, 127, 127, 126, 126, 125, 124, 123, 122, 121, 120, 119, 117, 115, 114, 112, 110, 108, 105, 103, 101, 98, 96, 93, 90, 87, 84, 81, 78, 75, 71, 68, 65, 61, 58, 54, 50, 47, 43, 39, 35, 31, 27, 23, 20, 16, 12, 8, 4, 0, -4, -8, -12, -16, -20, -23, -27, -31, -35, -39, -43, -47, -50, -54, -58, -61, -65, -68, -71, -75, -78, -81, -84, -87, -90, -93, -96, -98, -101, -103, -105, -108, -110, -112, -114, -115, -117, -119, -120, -121, -122, -123, -124, -125, -126, -126, -127, -127, -127, -127, -127, -127, -127, -126, -126, -125, -124, -123, -122, -121, -120, -119, -117, -115, -114, -112, -110, -108, -105, -103, -101, -98, -96, -93, -90, -87, -84, -81, -78, -75, -71, -68, -65, -61, -58, -54, -50, -47, -43, -39, -35, -31, -27, -23, -20, -16, -12, -8, -4};


#define MAX(x,y) ((x>y)?(x):(y))

static int letter(int n, int pos, unsigned char im[70*200], unsigned char swr[200], uint8_t s1, uint8_t s2)
{
	char *p=lt[n];
	unsigned char *r=im+200*16+pos;
	unsigned char *i=r;
	int sk1=s1+pos;
	int sk2=s2+pos;
	int mpos=pos;
	int row=0;
	for(;*p!=-101;p++)
	{
		if(*p<0)
		{
			if(*p==-100) { r+=200; i=r; sk1=s1+pos; row++; continue; }
			i+=-*p;
			continue;
		}

		if(sk1>=200) sk1=sk1%200;
		int skew=sw[sk1]/16;
		sk1+=(swr[pos+i-r]&0x1)+1;

		if(sk2>=200) sk2=sk2%200;
		int skewh=sw[sk2]/70;
		sk2+=(swr[row]&0x1);

		unsigned char *x=i+skew*200+skewh;
		mpos=MAX(mpos,pos+i-r);
		
		if((x-im)<70*200) *x=(*p)<<4;
		i++;
	}
	return mpos-1;
}

#define NDOTS 100

uint32_t dr[NDOTS];

static void line(unsigned char im[70*200], unsigned char swr[200], uint8_t s1) 
{
	int x;
	int sk1=s1;
	for(x=0;x<199;x++) 
	{
		if(sk1>=200) sk1=sk1%200;
		int skew=sw[sk1]/16;
		sk1+=(swr[x]&0x3)+1;
		unsigned char *i= im+(200*(45+skew)+x);
		i[0]=0; i[1]=0; i[200]=0; i[201]=0;
	}
	return;
}

static void dots(unsigned char im[70*200]) 
{
	int n;
	for(n=0;n<NDOTS;n++) 
	{
		uint32_t v=dr[n];
		unsigned char *i=im+v%(200*67);
		
		i[0]=0xff;
		i[1]=0xff;
		i[2]=0xff;
		i[200]=0xff;
		i[201]=0xff;
		i[202]=0xff;
	}
	return;
}
static void blur(unsigned char im[70*200])
{
	unsigned char *i=im;
	int x,y;
	for(y=0;y<68;y++) 
	{
        for(x=0;x<198;x++) 
        {
		    unsigned int c11=*i,c12=i[1],c21=i[200],c22=i[201];
			*i++ = ((c11+c12+c21+c22)/4);
        }
	}
	return;
}

static const char *letters="abcdefahijklmnopqrstuvwxyz";

void captcha(unsigned char im[70*200], unsigned char l[6])
{
	unsigned char swr[200];
	uint8_t s1,s2;

	int f=open("/dev/urandom",O_RDONLY);
	read(f,l,5); read(f,swr,200); read(f,dr,sizeof(dr)); read(f,&s1,1); read(f,&s2,1);
	close(f);

	memset(im,0xff,200*70); s1=s1&0x7f; s2=s2&0x3f; l[0]%=25; l[1]%=25; l[2]%=25; l[3]%=25; l[4]%=25; l[5]=0;
	int p=30; p=letter(l[0],p,im,swr,s1,s2); p=letter(l[1],p,im,swr,s1,s2); p=letter(l[2],p,im,swr,s1,s2); p=letter(l[3],p,im,swr,s1,s2); letter(l[4],p,im,swr,s1,s2);
	line(im,swr,s1); dots(im); blur(im);
	l[0]=letters[l[0]]; l[1]=letters[l[1]]; l[2]=letters[l[2]]; l[3]=letters[l[3]]; l[4]=letters[l[4]];
	return;
}

#ifdef CAPTCHA

char gen_captcha()
{
	char l[20];
    char ch;
    int index=0;
	unsigned char im[70*200];
	unsigned char gif[gifsize];
	

    /* Gen CAPTCHA */
	captcha(im,l);
	makegif(im,gif);
    l[6] = 0;

    /* Writing captcha image to file. */
    FILE *img_fp;
    img_fp = fopen(strcat(l, ".gif"), "w");
    if(img_fp == NULL)
        return NULL; //fail

    while(1)
    {
        ch = gif[index];
        if(index >= gifsize)
            break;
        else
            fputc(ch, img_fp);
        index ++;
    }
    fclose(img_fp);

	//write(1, gif, gifsize);
	//write(2, l, 5);
	//Usage: captcha > captcha.gif 2> letters.txt

	return l; //happy
}

int main(int argc, char** argv) {
    gen_captcha();
    return 0;
}

char captcha_challenge()
{
    char captcha_code = gen_captcha();
    if(captcha_code)
        return captcha_code;
    else
        return NULL;
}

#endif

char lt0[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-4,11,7,5,3,1,0,0,0,1,3,7,13,-100,-2,11,3,0,0,0,0,0,0,0,0,0,0,0,0,9,-100,-1,7,0,0,0,0,0,0,3,9,11,9,3,0,0,0,0,13,-100,9,0,0,0,0,0,0,3,-5,3,0,0,0,7,-100,5,0,0,0,0,0,1,13,-5,9,0,0,0,1,-100,7,0,0,0,0,1,13,-6,13,0,0,0,0,-100,-1,9,1,0,5,13,-8,0,0,0,0,13,-100,-14,0,0,0,0,11,-100,-14,0,0,0,0,11,-100,-14,0,0,0,0,11,-100,-12,13,5,0,0,0,0,11,-100,-8,13,9,5,1,0,0,0,0,0,0,11,-100,-4,13,7,3,1,0,0,0,0,1,1,0,0,0,0,11,-100,-2,13,5,0,0,0,0,0,5,9,13,-2,0,0,0,0,11,-100,-1,13,1,0,0,0,0,7,-6,0,0,0,0,11,-100,13,1,0,0,0,0,13,-7,0,0,0,0,11,-100,5,0,0,0,0,5,-8,0,0,0,0,11,-100,0,0,0,0,0,11,-8,0,0,0,0,11,-100,0,0,0,0,0,13,-7,13,0,0,0,0,11,-100,1,0,0,0,0,-7,9,0,0,0,0,0,9,-3,9,-100,5,0,0,0,0,3,13,-3,11,3,0,0,0,0,0,0,0,9,13,3,5,-100,13,0,0,0,0,0,0,1,1,0,0,0,1,11,9,0,0,0,0,0,0,1,13,-100,-1,11,1,0,0,0,0,0,0,0,0,5,-3,9,0,0,0,0,0,11,-100,-2,13,7,3,0,0,0,3,7,13,-5,9,0,1,3,9,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt1[]={-100,-100,-4,13,5,0,3,-100,-3,11,1,0,0,0,7,-100,-2,7,0,0,0,0,0,3,-100,13,3,0,0,0,0,0,0,5,-100,1,0,0,0,0,0,0,0,9,-100,1,0,0,0,0,0,0,0,13,-100,13,3,0,0,0,0,0,1,-100,-2,5,0,0,0,0,5,-100,-3,0,0,0,0,9,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,9,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,3,13,9,5,3,1,0,0,1,3,5,9,-100,-3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,13,-100,-3,0,0,0,0,0,5,13,-2,13,11,9,5,0,0,0,0,1,13,-100,-3,0,0,0,0,1,-8,13,1,0,0,0,5,-100,-3,3,0,0,0,5,-9,13,0,0,0,0,11,-100,-3,0,0,0,0,9,-10,7,0,0,0,5,-100,-3,1,0,0,0,11,-10,13,0,0,0,0,-100,-3,3,0,0,0,11,-11,3,0,0,0,11,-100,-3,1,0,0,0,11,-11,7,0,0,0,7,-100,-3,0,0,0,0,11,-11,9,0,0,0,3,-100,-3,0,0,0,0,11,-11,11,0,0,0,1,-100,-3,0,0,0,0,11,-11,11,0,0,0,1,-100,-3,0,0,0,0,11,-11,11,0,0,0,0,-100,-3,0,0,0,0,11,-11,9,0,0,0,0,-100,-3,0,0,0,0,11,-11,7,0,0,0,3,-100,-3,0,0,0,0,11,-11,3,0,0,0,7,-100,-3,0,0,0,0,11,-11,0,0,0,0,11,-100,-3,0,0,0,0,11,-10,9,0,0,0,3,-100,-3,0,0,0,0,9,-10,3,0,0,0,11,-100,-3,0,0,0,0,3,-9,11,0,0,0,5,-100,-2,13,0,0,0,0,0,9,-7,11,1,0,0,3,-100,-2,7,0,0,0,0,0,0,7,13,-2,13,9,3,0,0,0,3,13,-100,-2,13,0,0,5,13,11,1,0,0,0,0,0,0,0,0,0,7,-100,-3,9,11,-4,7,3,1,0,0,1,5,9,13,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt2[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-6,13,7,3,1,0,0,1,3,7,13,-100,-5,9,0,0,0,0,0,0,0,0,0,0,5,13,-100,-3,13,3,0,0,0,5,13,13,7,0,0,0,0,0,1,13,-100,-2,13,1,0,0,0,9,-4,7,0,0,0,0,0,1,-100,-1,13,1,0,0,0,9,-6,5,0,0,0,0,0,13,-100,-1,5,0,0,0,3,-8,1,0,0,0,3,-100,13,0,0,0,0,11,-8,13,3,0,3,-100,7,0,0,0,1,-100,5,0,0,0,5,-100,3,0,0,0,9,-100,1,0,0,0,11,-100,0,0,0,0,11,-100,0,0,0,0,11,-100,0,0,0,0,11,-100,0,0,0,0,9,-100,1,0,0,0,5,-100,5,0,0,0,0,13,-100,11,0,0,0,0,7,-100,-1,3,0,0,0,0,13,-100,-1,11,0,0,0,0,3,-12,9,-100,-2,7,0,0,0,0,3,13,-8,9,1,3,-100,-3,5,0,0,0,0,1,9,-5,9,3,0,0,11,-100,-4,5,0,0,0,0,0,0,1,1,1,0,0,0,0,11,-100,-5,9,1,0,0,0,0,0,0,0,0,0,3,13,-100,-7,11,7,3,1,0,1,3,7,11,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt3[]={-100,-100,-100,-100,-18,11,3,0,-100,-16,13,3,0,0,0,-100,-14,9,3,0,0,0,0,0,-100,-13,3,0,0,0,0,0,0,0,-100,-13,0,0,0,0,0,0,0,0,-100,-13,9,1,0,0,0,0,0,0,-100,-15,13,5,0,0,0,0,-100,-17,1,0,0,0,-100,-17,3,0,0,0,-100,-17,1,0,0,0,-100,-17,0,0,0,0,-100,-16,13,0,0,0,0,-100,-16,13,0,0,0,0,-100,-6,11,5,3,1,0,0,1,5,9,13,13,0,0,0,0,-100,-4,13,3,0,0,0,0,0,0,0,0,0,0,3,0,0,0,0,-100,-3,13,1,0,0,0,0,5,11,-1,13,11,3,0,0,0,0,0,0,-100,-2,13,1,0,0,0,0,7,-6,11,0,0,0,0,0,-100,-2,3,0,0,0,0,9,-8,11,0,0,0,0,-100,-1,9,0,0,0,0,7,-9,11,0,0,0,0,-100,-1,1,0,0,0,0,13,-9,11,0,0,0,0,-100,11,0,0,0,0,3,-10,11,0,0,0,0,-100,5,0,0,0,0,13,-10,11,0,0,0,0,-100,3,0,0,0,3,-11,11,0,0,0,0,-100,0,0,0,0,7,-11,11,0,0,0,0,-100,0,0,0,0,11,-11,11,0,0,0,0,-100,0,0,0,0,11,-11,11,0,0,0,0,-100,0,0,0,0,11,-11,11,0,0,0,0,-100,1,0,0,0,9,-11,11,0,0,0,0,-100,3,0,0,0,7,-11,11,0,0,0,0,-100,7,0,0,0,3,-11,11,0,0,0,0,-100,13,0,0,0,0,13,-10,13,0,0,0,0,-100,-1,3,0,0,0,5,-11,0,0,0,0,-100,-1,13,0,0,0,0,11,-10,0,0,0,0,-100,-2,7,0,0,0,1,13,-8,13,0,0,0,0,13,-100,-3,5,0,0,0,1,11,-7,5,0,0,0,0,9,-100,-4,5,0,0,0,0,3,9,13,-1,13,11,1,0,0,0,0,0,0,0,5,-100,-5,9,1,0,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0,1,13,-100,-7,9,3,1,0,0,3,7,13,-1,11,1,0,1,5,7,11,-100,-18,13,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt4[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-7,13,5,1,1,0,1,3,9,13,-100,-6,5,0,0,0,0,0,0,0,0,0,9,-100,-4,11,1,0,0,3,11,-1,13,7,1,0,0,0,9,-100,-3,9,0,0,0,1,13,-5,3,0,0,1,-100,-2,9,0,0,0,0,13,-6,11,0,0,0,9,-100,-1,13,0,0,0,0,9,-8,0,0,0,1,-100,-1,5,0,0,0,0,13,-8,3,0,0,0,11,-100,-1,0,0,0,0,0,-8,13,1,0,0,0,5,-100,9,0,0,0,0,0,3,11,-4,13,11,1,0,0,0,0,1,-100,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,-100,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,3,-100,1,0,0,0,1,13,-100,0,0,0,0,11,-100,0,0,0,0,11,-100,1,0,0,0,9,-100,3,0,0,0,7,-100,7,0,0,0,5,-100,13,0,0,0,0,11,-100,-1,5,0,0,0,1,13,-100,-1,13,1,0,0,0,1,13,-10,13,11,-100,-2,11,0,0,0,0,1,13,-8,13,1,1,-100,-3,11,0,0,0,0,0,7,13,-4,11,7,0,0,9,-100,-4,11,1,0,0,0,0,0,1,1,1,0,0,0,0,7,-100,-5,13,5,0,0,0,0,0,0,0,0,0,1,9,-100,-7,13,7,3,0,0,0,1,5,9,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt5[]={-100,-100,-100,-100,-9,13,9,3,1,0,1,5,13,-100,-8,7,0,0,0,0,0,0,0,3,-100,-7,3,0,0,0,0,0,0,0,0,1,-100,-6,5,0,0,0,0,0,0,0,0,0,3,-100,-5,13,0,0,3,13,9,1,0,0,0,0,11,-100,-5,9,0,0,13,-2,13,5,0,1,9,-100,-5,5,0,0,-100,-5,1,0,1,-100,-5,1,0,0,-100,-5,0,0,0,-100,-5,0,0,0,13,-100,-5,0,0,0,9,-100,-5,0,0,0,7,-100,-5,0,0,0,5,-100,-3,13,7,0,0,0,0,9,-1,13,11,13,-100,3,0,0,0,0,0,0,0,0,0,0,0,0,0,9,-100,3,0,0,0,0,0,0,0,0,0,0,0,0,0,9,-100,-1,11,13,-1,7,0,0,0,0,5,-1,13,11,13,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,11,-100,-5,0,0,0,0,7,-100,-3,13,5,0,0,0,0,0,7,13,-100,-1,5,0,0,0,0,0,0,0,0,0,0,0,1,11,-100,-1,7,1,0,0,0,0,0,0,0,0,1,3,7,13,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt6[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-7,11,7,3,1,0,0,1,3,7,13,-4,13,7,5,7,11,-100,-5,11,3,0,0,0,0,0,0,0,0,0,0,5,13,13,5,0,0,0,0,0,-100,-4,9,0,0,0,5,13,-1,13,9,3,0,0,0,0,0,0,0,0,0,0,0,1,-100,-3,11,0,0,0,5,-6,5,0,0,0,0,0,11,13,9,3,0,9,-100,-2,13,0,0,0,0,13,-7,1,0,0,0,0,13,-100,-2,1,0,0,0,7,-8,7,0,0,0,0,7,-100,-2,0,0,0,0,9,-8,11,0,0,0,0,3,-100,-2,0,0,0,0,11,-9,0,0,0,0,1,-100,-2,0,0,0,0,11,-9,0,0,0,0,0,-100,-2,0,0,0,0,9,-8,13,0,0,0,0,1,-100,-2,3,0,0,0,5,-8,9,0,0,0,0,7,-100,-2,13,1,0,0,0,13,-7,5,0,0,0,0,13,-100,-3,11,0,0,0,3,13,-5,7,0,0,0,0,11,-100,-4,7,0,0,0,1,9,13,-1,13,7,0,0,0,1,11,-100,-4,13,0,0,0,0,0,0,0,0,0,0,0,5,13,-100,-4,13,0,0,0,0,0,0,1,3,5,9,-100,-2,13,5,0,11,-100,-1,13,1,0,0,-100,-1,3,0,0,0,1,7,13,-100,-1,0,0,0,0,0,0,0,1,3,7,9,11,13,-100,-1,5,0,0,0,0,0,0,0,0,0,0,0,0,0,1,3,5,11,-100,-2,11,7,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,11,-100,-4,13,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,9,-100,-3,9,1,0,3,9,13,13,11,7,3,0,0,0,0,0,0,0,0,0,13,-100,-1,7,1,0,0,9,-8,11,7,3,0,0,0,0,0,5,-100,9,0,0,0,3,-13,11,1,0,0,1,-100,1,0,0,0,9,-15,0,0,0,-100,0,0,0,0,9,-14,13,0,0,1,-100,3,0,0,0,1,-14,7,0,0,5,-100,11,0,0,0,0,5,-12,11,0,0,0,13,-100,-1,11,1,0,0,0,1,7,11,13,-1,13,13,11,9,5,3,1,0,0,3,13,-100,-3,9,3,0,0,0,0,0,0,0,0,0,0,0,0,0,1,9,-100,-6,9,7,3,1,1,0,0,1,1,3,7,11,-100,-101};
char lt7[]={-100,-100,-100,-100,-4,13,7,1,9,-100,-2,13,7,0,0,0,3,-100,-1,7,0,0,0,0,0,5,-100,1,0,0,0,0,0,0,7,-100,3,0,0,0,0,0,0,7,-100,13,7,0,0,0,0,0,9,-100,-2,5,0,0,0,0,9,-100,-2,11,0,0,0,0,9,-100,-3,0,0,0,0,9,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-5,11,5,1,0,1,7,-100,-3,0,0,0,0,11,-3,13,3,0,0,0,0,0,0,3,-100,-3,0,0,0,0,11,-2,7,0,0,0,0,0,0,0,0,0,9,-100,-3,0,0,0,0,11,11,3,0,5,11,-1,13,9,1,0,0,0,3,-100,-3,0,0,0,0,3,0,1,11,-6,1,0,0,0,13,-100,-3,0,0,0,0,0,5,-8,11,0,0,0,11,-100,-3,0,0,0,0,11,-10,0,0,0,7,-100,-3,0,0,0,0,13,-10,0,0,0,7,-100,-3,0,0,0,0,11,-10,0,0,0,7,-100,-3,0,0,0,0,11,-10,0,0,0,7,-100,-3,0,0,0,0,13,-10,0,0,0,9,-100,-3,0,0,0,0,13,-10,0,0,0,9,-100,-3,0,0,0,0,-11,0,0,0,11,-100,-3,0,0,0,1,-11,0,0,0,13,-100,-3,0,0,0,1,-11,0,0,0,13,-100,-3,0,0,0,3,-11,0,0,0,-100,-3,0,0,0,3,-11,0,0,0,-100,-3,0,0,0,3,-11,0,0,0,-100,-3,0,0,0,3,-10,13,0,0,0,13,-100,-3,0,0,0,1,-10,13,0,0,0,11,-100,-2,9,0,0,0,0,-10,11,0,0,0,5,-100,-1,7,0,0,0,0,0,5,13,-7,13,3,0,0,0,0,7,-100,5,0,0,0,0,0,0,0,0,3,-5,1,0,0,0,0,0,0,1,3,11,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt8[]={-100,-100,-100,-100,-3,5,1,0,3,11,-100,-2,7,0,0,0,0,0,11,-100,-2,1,0,0,0,0,0,5,-100,-2,0,0,0,0,0,0,5,-100,-2,5,0,0,0,0,0,11,-100,-3,7,0,0,3,9,-100,-4,13,-100,-100,-100,-100,-100,-100,-100,-4,11,3,0,9,-100,-2,9,3,0,0,0,9,-100,11,1,0,0,0,0,0,7,-100,1,0,0,0,0,0,0,7,-100,1,0,0,0,0,0,0,9,-100,-1,11,0,0,0,0,0,9,-100,-2,7,0,0,0,0,11,-100,-3,0,0,0,0,13,-100,-3,1,0,0,0,-100,-3,1,0,0,0,13,-100,-3,1,0,0,0,13,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-2,13,0,0,0,0,7,-100,-2,13,0,0,0,0,1,-100,-2,7,0,0,0,0,0,9,-100,7,0,0,0,0,0,0,0,0,3,-100,9,5,1,1,0,0,1,1,3,5,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt9[]={-100,-100,-100,-100,-6,5,0,1,5,13,-100,-5,5,0,0,0,0,1,-100,-5,1,0,0,0,0,0,13,-100,-5,0,0,0,0,0,0,-100,-5,5,0,0,0,0,3,-100,-6,7,1,0,5,13,-100,-100,-100,-100,-100,-100,-100,-100,-6,13,7,3,0,13,-100,-5,7,0,0,0,0,11,-100,-3,7,1,0,0,0,0,0,11,-100,-2,13,0,0,0,0,0,0,0,11,-100,-3,11,3,0,0,0,0,0,11,-100,-5,9,0,0,0,0,11,-100,-6,1,0,0,0,11,-100,-6,3,0,0,0,11,-100,-6,5,0,0,0,11,-100,-6,5,0,0,0,11,-100,-6,5,0,0,0,11,-100,-6,5,0,0,0,11,-100,-6,3,0,0,0,11,-100,-6,3,0,0,0,11,-100,-6,1,0,0,0,11,-100,-6,1,0,0,0,13,-100,-6,1,0,0,0,13,-100,-6,1,0,0,0,13,-100,-6,1,0,0,0,13,-100,-6,1,0,0,0,13,-100,-6,1,0,0,0,-100,-6,1,0,0,0,-100,-6,1,0,0,1,-100,-6,1,0,0,3,-100,-6,0,0,0,5,-100,-6,0,0,0,7,-100,-6,0,0,0,11,-100,11,0,0,0,5,5,0,0,5,-100,3,0,0,0,0,0,0,3,-100,0,0,0,0,0,0,0,13,-100,1,0,0,0,0,0,11,-100,13,3,0,0,3,11,-100,-100,-101};
char lt10[]={-100,-100,-100,-100,-6,9,1,13,-100,-3,13,5,0,0,0,11,-100,-1,13,5,0,0,0,0,0,11,-100,13,1,0,0,0,0,0,0,11,-100,3,0,0,0,0,0,0,0,11,-100,11,3,0,0,0,0,0,0,11,-100,-2,13,0,0,0,0,0,11,-100,-3,9,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-7,3,0,0,0,0,0,0,0,0,0,3,-100,-4,0,0,0,0,11,-7,5,0,0,0,0,0,0,0,1,7,13,-100,-4,0,0,0,0,11,-8,9,0,0,0,1,9,-100,-4,0,0,0,0,11,-7,13,1,0,0,7,-100,-4,0,0,0,0,11,-7,5,0,3,13,-100,-4,0,0,0,0,11,-6,5,0,5,-100,-4,0,0,0,0,11,-5,5,1,11,-100,-4,0,0,0,0,11,-3,11,3,1,-100,-4,0,0,0,0,11,-1,11,3,0,0,1,-100,-4,0,0,0,0,11,9,0,0,0,0,0,11,-100,-4,0,0,0,0,0,0,1,0,0,0,0,3,-100,-4,0,0,0,0,0,9,-1,11,1,0,0,0,9,-100,-4,0,0,0,0,5,-4,3,0,0,0,11,-100,-4,0,0,0,0,11,-4,13,1,0,0,0,13,-100,-4,0,0,0,0,11,-5,11,0,0,0,1,13,-100,-4,0,0,0,0,11,-6,3,0,0,0,3,-100,-4,0,0,0,0,11,-6,11,0,0,0,0,7,-100,-4,0,0,0,0,11,-7,3,0,0,0,0,7,-100,-3,13,0,0,0,0,11,-7,13,0,0,0,0,0,7,-100,-2,13,3,0,0,0,0,7,-7,9,0,0,0,0,0,0,3,11,-100,-1,1,0,0,0,0,0,0,0,0,1,3,-4,0,0,0,0,0,0,0,0,0,0,3,-100,-1,7,1,0,0,0,0,0,0,0,0,7,-4,3,0,0,0,0,0,0,1,1,5,9,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt11[]={-100,-100,-100,-6,11,7,11,-100,-4,11,3,0,0,5,-100,-3,5,0,0,0,0,5,-100,-1,11,1,0,0,0,0,0,7,-100,7,0,0,0,0,0,0,0,7,-100,0,0,0,0,0,0,0,0,9,-100,7,0,0,0,0,0,0,0,9,-100,-2,9,1,0,0,0,0,9,-100,-3,11,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,7,-100,-3,5,0,0,0,0,0,13,-100,-1,9,1,0,0,0,0,0,0,0,1,9,-100,-1,5,1,0,0,0,0,0,0,0,1,11,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt12[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-5,11,5,0,-21,7,1,0,3,9,-100,-4,7,0,0,0,13,-4,11,5,1,1,0,1,7,-7,11,3,0,0,0,0,0,5,-100,-2,11,1,0,0,0,0,11,-2,9,1,0,0,0,0,0,0,0,9,-4,13,5,0,0,0,0,0,0,0,0,7,-100,13,3,0,0,0,0,0,0,7,13,3,0,0,0,1,0,0,0,0,0,0,7,-1,13,7,0,0,0,0,0,0,0,0,0,0,0,11,-100,3,0,0,0,0,0,0,0,1,0,0,5,11,-3,11,0,0,0,0,0,0,0,3,9,13,13,-3,7,0,0,0,0,5,-100,13,3,0,0,0,0,0,0,0,7,13,-6,3,0,0,0,0,0,9,-8,5,0,0,0,1,-100,-2,11,0,0,0,0,0,3,-8,9,0,0,0,0,7,-9,11,0,0,0,0,-100,-3,3,0,0,0,0,7,-8,13,0,0,0,0,-10,11,0,0,0,0,-100,-3,7,0,0,0,0,11,-9,0,0,0,0,-10,11,0,0,0,1,-100,-3,11,0,0,0,0,11,-9,0,0,0,0,-10,11,0,0,0,3,-100,-3,13,0,0,0,0,11,-8,13,0,0,0,0,-10,11,0,0,0,5,-100,-3,13,0,0,0,0,11,-8,11,0,0,0,0,-10,11,0,0,0,5,-100,-4,0,0,0,0,13,-8,9,0,0,0,0,-10,11,0,0,0,5,-100,-4,0,0,0,0,13,-8,11,0,0,0,0,-10,11,0,0,0,3,-100,-4,0,0,0,0,13,-8,11,0,0,0,0,-10,11,0,0,0,0,-100,-3,13,0,0,0,1,-9,13,0,0,0,0,-10,11,0,0,0,0,-100,-3,11,0,0,0,13,-10,0,0,0,0,-10,11,0,0,0,0,-100,-4,0,0,0,11,-10,0,0,0,0,-10,11,0,0,0,0,-100,-3,13,0,0,0,3,-9,13,0,0,0,0,13,-9,9,0,0,0,0,-100,-3,7,0,0,0,0,13,-8,11,0,0,0,0,11,-9,7,0,0,0,0,13,-100,-3,3,0,0,0,0,9,-8,5,0,0,0,0,5,-9,5,0,0,0,0,7,-100,-1,13,3,0,0,0,0,0,1,11,-6,9,0,0,0,0,0,0,3,-7,11,1,0,0,0,0,1,13,-100,11,0,0,0,0,0,0,0,0,0,3,-4,3,0,0,0,0,0,0,0,0,5,-5,1,0,0,0,0,0,0,0,0,9,-100,13,1,0,0,0,0,0,0,0,1,9,-4,1,0,0,0,0,0,0,0,1,5,-5,1,0,0,0,0,0,0,0,0,7,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt13[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-3,13,7,3,0,13,-5,13,7,1,0,0,3,7,-100,-2,5,0,0,0,0,-4,13,3,0,0,0,0,0,0,0,7,-100,7,1,0,0,0,0,0,-3,7,0,0,0,0,0,0,0,0,0,0,13,-100,1,0,0,0,0,0,0,13,9,1,0,5,11,13,-1,11,3,0,0,0,0,9,-100,13,3,0,0,0,0,0,1,1,7,-7,3,0,0,0,3,-100,-2,1,0,0,0,0,7,-9,13,0,0,0,1,-100,-2,7,0,0,0,0,-11,1,0,0,0,-100,-2,9,0,0,0,0,-11,1,0,0,0,13,-100,-2,11,0,0,0,0,-11,3,0,0,0,13,-100,-2,11,0,0,0,0,-11,5,0,0,0,11,-100,-2,11,0,0,0,0,-11,3,0,0,0,11,-100,-2,11,0,0,0,0,-11,1,0,0,0,11,-100,-2,11,0,0,0,0,-11,0,0,0,0,11,-100,-2,11,0,0,0,0,-11,0,0,0,0,11,-100,-2,11,0,0,0,0,-11,1,0,0,0,11,-100,-2,11,0,0,0,0,-11,3,0,0,0,11,-100,-2,11,0,0,0,0,-11,3,0,0,0,11,-100,-2,11,0,0,0,0,13,-10,5,0,0,0,11,-100,-2,11,0,0,0,0,13,-10,5,0,0,0,11,-100,-2,11,0,0,0,0,9,-10,5,0,0,0,9,-100,-2,7,0,0,0,0,5,-10,3,0,0,0,7,-100,-1,13,1,0,0,0,0,1,11,-7,11,5,0,0,0,0,0,3,9,-100,-1,1,0,0,0,0,0,0,0,0,3,-4,3,0,0,0,0,0,0,0,0,0,3,-100,-1,0,0,0,0,0,0,0,0,0,3,-4,5,1,0,0,0,0,0,0,0,0,1,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt14[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-7,13,7,3,1,0,0,1,5,9,-100,-6,7,0,0,0,0,0,0,0,0,0,1,7,-100,-4,11,1,0,0,1,9,13,-1,13,11,5,0,0,0,3,13,-100,-3,11,0,0,0,3,13,-6,13,1,0,0,0,13,-100,-2,11,0,0,0,1,13,-8,13,0,0,0,5,-100,-2,0,0,0,0,9,-10,5,0,0,0,11,-100,-1,7,0,0,0,1,-11,13,0,0,0,1,-100,-1,1,0,0,0,5,-12,1,0,0,0,9,-100,11,0,0,0,0,11,-12,5,0,0,0,3,-100,7,0,0,0,0,13,-12,9,0,0,0,0,-100,3,0,0,0,0,13,-12,11,0,0,0,0,-100,1,0,0,0,0,-13,11,0,0,0,1,-100,0,0,0,0,0,-13,11,0,0,0,1,-100,0,0,0,0,0,13,-12,11,0,0,0,0,-100,1,0,0,0,0,13,-12,9,0,0,0,1,-100,5,0,0,0,0,11,-12,5,0,0,0,3,-100,9,0,0,0,0,9,-12,3,0,0,0,7,-100,-1,1,0,0,0,5,-12,0,0,0,0,11,-100,-1,9,0,0,0,3,-11,13,0,0,0,3,-100,-2,3,0,0,0,13,-10,7,0,0,0,11,-100,-2,13,1,0,0,3,-9,13,0,0,0,7,-100,-3,13,1,0,0,3,13,-6,13,1,0,0,5,-100,-4,13,1,0,0,1,7,13,-3,9,0,0,0,7,-100,-6,7,0,0,0,0,0,0,0,0,0,3,11,-100,-7,13,7,3,0,0,0,0,3,11,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt15[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-6,11,7,-100,-4,11,3,0,0,7,11,5,3,0,0,0,1,5,9,-100,-2,11,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,5,-100,13,5,0,0,0,0,0,0,0,1,7,11,13,-1,13,3,0,0,0,5,-100,1,0,0,0,0,0,0,0,3,-7,7,0,0,0,7,-100,1,0,0,0,0,0,0,0,11,-8,7,0,0,0,13,-100,-1,11,5,0,0,0,0,0,11,-9,1,0,0,3,-100,-3,7,0,0,0,0,11,-9,5,0,0,0,11,-100,-3,9,0,0,0,0,11,-9,9,0,0,0,5,-100,-3,11,0,0,0,0,11,-9,11,0,0,0,0,13,-100,-3,11,0,0,0,0,11,-9,13,0,0,0,0,11,-100,-3,13,0,0,0,0,11,-10,0,0,0,0,11,-100,-3,13,0,0,0,0,11,-10,0,0,0,0,11,-100,-3,13,0,0,0,0,11,-10,0,0,0,0,11,-100,-4,0,0,0,0,11,-10,0,0,0,0,13,-100,-4,0,0,0,0,11,-10,0,0,0,0,13,-100,-4,0,0,0,0,13,-10,0,0,0,0,-100,-4,0,0,0,9,-11,0,0,0,3,-100,-4,0,0,0,3,-11,0,0,0,9,-100,-4,0,0,0,0,13,-10,0,0,0,13,-100,-4,0,0,0,0,11,-9,5,0,0,0,-100,-4,0,0,0,0,11,-8,7,0,0,0,7,-100,-4,0,0,0,0,5,-7,9,0,0,0,3,-100,-4,0,0,0,0,0,3,11,13,-3,9,0,0,0,1,-100,-4,0,0,0,0,5,7,0,0,0,1,1,0,0,0,1,13,-100,-4,0,0,0,0,11,-2,9,5,1,0,0,3,7,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,7,-100,-4,0,0,0,0,3,-100,-3,7,0,0,0,0,0,9,-100,-1,5,0,0,0,0,0,0,0,0,0,0,5,-100,-1,3,1,0,0,0,0,0,0,0,0,0,5,-100,-101};
char lt16[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-19,7,11,-100,-6,11,5,1,0,0,1,5,11,-4,5,0,3,-100,-4,13,3,0,0,0,0,0,0,0,0,1,11,13,5,0,0,1,-100,-3,13,1,0,0,1,5,11,-3,11,3,0,0,0,0,0,3,-100,-2,13,1,0,0,3,-8,3,0,0,0,0,5,-100,-1,13,1,0,0,0,13,-8,7,0,0,0,0,5,-100,-1,3,0,0,0,5,-9,11,0,0,0,0,7,-100,9,0,0,0,0,11,-9,13,0,0,0,0,9,-100,3,0,0,0,0,-10,13,0,0,0,0,9,-100,1,0,0,0,1,-11,0,0,0,0,9,-100,0,0,0,0,3,-11,0,0,0,0,11,-100,0,0,0,0,5,-11,0,0,0,0,11,-100,0,0,0,0,9,-11,0,0,0,0,11,-100,0,0,0,0,11,-11,0,0,0,0,11,-100,0,0,0,0,11,-11,0,0,0,0,11,-100,1,0,0,0,11,-11,0,0,0,0,11,-100,3,0,0,0,9,-11,0,0,0,0,11,-100,7,0,0,0,5,-11,0,0,0,0,11,-100,11,0,0,0,0,-11,0,0,0,0,11,-100,-1,1,0,0,0,7,-9,11,0,0,0,0,11,-100,-1,9,0,0,0,0,13,-8,9,0,0,0,0,11,-100,-2,3,0,0,0,1,13,-7,5,0,0,0,0,11,-100,-2,13,3,0,0,0,1,9,13,-3,13,7,0,0,0,0,0,11,-100,-4,9,1,0,0,0,0,0,1,0,0,0,0,0,0,0,0,11,-100,-6,11,7,3,1,0,0,5,9,-1,13,0,0,0,0,11,-100,-16,0,0,0,0,13,-100,-16,0,0,0,0,13,-100,-16,0,0,0,0,13,-100,-16,0,0,0,0,13,-100,-15,13,0,0,0,0,13,-100,-15,9,0,0,0,0,11,-100,-15,1,0,0,0,0,5,-100,-12,7,5,1,0,0,0,0,0,0,1,3,9,-100,-11,13,1,0,0,0,0,0,0,0,0,0,0,7,-100,-101};
char lt17[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-3,13,5,0,3,-5,9,3,1,0,0,3,-100,-1,11,3,0,0,0,0,-3,7,0,0,0,0,0,0,0,5,-100,9,0,0,0,0,0,0,-2,3,0,0,0,0,0,0,0,0,1,-100,0,0,0,0,0,0,0,11,3,0,0,0,0,0,0,0,0,0,1,-100,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,9,-100,-1,7,0,0,0,0,0,0,7,13,-2,11,7,3,1,3,11,-100,-2,3,0,0,0,0,3,-100,-2,7,0,0,0,0,9,-100,-2,11,0,0,0,0,13,-100,-2,13,0,0,0,0,-100,-3,0,0,0,0,-100,-3,0,0,0,0,13,-100,-3,0,0,0,0,13,-100,-3,0,0,0,0,13,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,11,-100,-3,0,0,0,0,9,-100,-1,13,3,0,0,0,0,1,13,-100,3,0,0,0,0,0,0,0,0,0,0,13,-100,5,1,0,0,0,0,0,0,0,0,3,13,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt18[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-3,13,7,1,0,1,3,9,11,9,9,13,-100,-2,13,1,0,0,0,0,0,0,0,0,0,5,-100,-2,1,0,5,13,-1,13,11,3,0,0,0,1,-100,-1,9,0,1,-6,9,0,0,0,13,-100,-1,3,0,9,-7,11,1,0,9,-100,-1,0,0,-9,13,1,5,-100,-1,0,0,11,-9,13,11,-100,13,0,0,1,13,-100,13,0,0,0,1,9,-100,-1,0,0,0,0,0,0,5,9,-100,-1,5,0,0,0,0,0,0,0,1,7,13,-100,-1,13,0,0,0,0,0,0,0,0,0,0,9,-100,-2,13,1,0,0,0,0,0,0,0,0,0,7,-100,-4,11,5,0,0,0,0,0,0,0,0,7,-100,-7,9,5,0,0,0,0,0,0,13,-100,-9,13,7,0,0,0,0,7,-100,-11,13,3,0,0,3,-100,-13,0,0,0,-100,7,5,-11,1,0,0,-100,1,0,5,-10,1,0,3,-100,0,0,0,3,-9,0,0,9,-100,1,0,0,0,3,13,-6,5,0,3,-100,7,0,0,0,0,1,7,11,13,13,9,3,0,1,13,-100,13,0,0,0,0,0,0,0,0,0,0,0,3,13,-100,-1,5,3,9,7,3,1,0,0,1,5,11,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt19[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-6,5,0,5,-100,-5,13,0,0,0,7,-100,-5,7,0,0,0,9,-100,-5,3,0,0,0,13,-100,-4,11,0,0,0,0,-100,-4,3,0,0,0,0,-100,-3,5,0,0,0,0,1,-100,-2,3,0,0,0,0,0,7,-100,13,1,0,0,0,0,0,0,1,11,-100,3,0,0,0,0,0,0,0,0,0,0,0,0,0,5,13,-100,1,0,0,0,0,0,0,0,0,0,0,0,0,0,5,-100,-3,9,0,0,0,0,7,13,-100,-4,0,0,0,0,11,-100,-4,1,0,0,0,11,-100,-4,1,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,0,0,0,0,11,-100,-4,1,0,0,0,11,-100,-4,3,0,0,0,11,-100,-4,5,0,0,0,11,-100,-4,3,0,0,0,11,-100,-4,3,0,0,0,11,-100,-4,1,0,0,0,9,-100,-4,0,0,0,0,5,-100,-4,0,0,0,0,1,-100,-4,1,0,0,0,0,11,-100,-4,3,0,0,0,0,1,13,-1,9,5,1,3,-100,-4,9,0,0,0,0,0,0,0,0,0,0,5,-100,-5,5,0,0,0,0,0,0,0,0,5,-100,-6,9,3,1,0,0,1,5,11,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt20[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-4,13,9,1,0,13,-11,11,5,1,5,-100,-2,11,3,0,0,0,0,11,-8,11,5,0,0,0,0,1,-100,13,3,0,0,0,0,0,0,11,-6,7,1,0,0,0,0,0,0,7,-100,5,0,0,0,0,0,0,0,11,-5,5,0,0,0,0,0,0,0,0,11,-100,11,1,0,0,0,0,0,0,11,-5,9,0,0,0,0,0,0,0,0,11,-100,-2,11,1,0,0,0,0,11,-6,13,7,3,0,0,0,0,0,11,-100,-3,9,0,0,0,0,11,-9,9,0,0,0,0,11,-100,-3,11,0,0,0,0,11,-10,0,0,0,0,11,-100,-3,13,0,0,0,0,11,-10,0,0,0,0,11,-100,-4,0,0,0,0,11,-10,0,0,0,0,11,-100,-4,0,0,0,0,11,-10,0,0,0,0,11,-100,-4,0,0,0,0,11,-10,0,0,0,0,11,-100,-4,0,0,0,0,11,-10,0,0,0,0,11,-100,-4,0,0,0,0,11,-10,0,0,0,0,11,-100,-4,0,0,0,0,11,-10,0,0,0,0,11,-100,-4,0,0,0,0,11,-10,0,0,0,0,11,-100,-4,0,0,0,0,11,-10,0,0,0,0,11,-100,-4,1,0,0,0,11,-9,13,0,0,0,0,11,-100,-4,1,0,0,0,11,-9,5,0,0,0,0,11,-100,-4,5,0,0,0,7,-8,7,0,0,0,0,0,11,-100,-4,7,0,0,0,0,13,-5,13,5,0,0,0,0,0,0,11,-100,-4,13,0,0,0,0,1,11,-1,13,11,5,0,0,7,5,0,0,0,0,3,13,-100,-5,3,0,0,0,0,0,0,0,0,0,3,13,-2,0,0,0,0,0,0,7,-100,-5,11,0,0,0,0,0,0,0,1,9,-4,0,0,0,0,0,0,0,-100,-6,13,5,1,0,1,3,9,-6,3,1,3,7,9,11,13,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt21[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-6,13,9,1,3,13,-5,13,1,0,0,0,0,1,3,9,-100,1,0,0,0,0,0,0,0,0,0,1,-5,1,0,0,0,0,0,0,0,0,9,-100,3,0,0,0,0,0,0,0,0,0,5,-5,3,0,0,0,0,0,0,0,0,13,-100,-1,9,3,0,0,0,0,0,5,13,-7,13,9,0,0,0,0,1,11,-100,-3,7,0,0,0,0,-11,7,0,0,5,-100,-4,0,0,0,0,9,-10,9,0,5,-100,-4,5,0,0,0,1,-10,5,0,11,-100,-4,11,0,0,0,0,9,-9,0,1,-100,-5,1,0,0,0,3,-8,9,0,7,-100,-5,7,0,0,0,0,13,-7,3,0,13,-100,-5,13,0,0,0,0,7,-6,13,0,3,-100,-6,3,0,0,0,1,-6,7,0,11,-100,-6,9,0,0,0,0,9,-5,0,1,-100,-6,13,0,0,0,0,3,-4,7,0,7,-100,-7,5,0,0,0,0,11,-3,1,0,13,-100,-7,11,0,0,0,0,1,-2,9,0,5,-100,-8,1,0,0,0,0,5,-1,1,0,11,-100,-8,7,0,0,0,0,0,0,0,3,-100,-8,13,0,0,0,0,0,0,0,9,-100,-9,3,0,0,0,0,0,1,-100,-9,9,0,0,0,0,0,7,-100,-10,0,0,0,0,0,13,-100,-10,5,0,0,0,1,-100,-10,13,1,0,0,7,-100,-11,11,1,5,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt22[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-29,13,-100,5,0,0,1,1,1,3,3,5,7,-3,7,0,0,0,0,0,0,0,0,0,11,-4,3,0,0,0,0,0,0,1,3,11,-100,5,0,0,0,0,0,0,0,1,7,-3,9,0,0,0,0,0,0,0,0,1,11,-4,9,1,0,0,0,0,0,0,1,13,-100,-1,13,5,0,0,0,0,0,13,-5,13,5,0,0,0,0,0,3,-8,9,0,0,0,0,5,-100,-3,5,0,0,0,0,-8,11,0,0,0,0,9,-9,9,0,0,9,-100,-4,1,0,0,0,13,-8,11,0,0,0,3,-10,0,3,-100,-4,7,0,0,0,11,-8,13,0,0,0,0,13,-8,9,0,11,-100,-4,13,0,0,0,7,-8,11,0,0,0,0,7,-8,1,1,-100,-5,5,0,0,1,-8,7,0,0,0,0,3,-8,5,11,-100,-5,11,0,0,0,9,-7,1,0,0,0,0,0,13,-100,-6,0,0,0,3,-6,9,0,3,13,0,0,0,7,-6,5,-100,-6,3,0,0,0,13,-5,1,0,11,-1,3,0,0,3,-6,1,-100,-6,9,0,0,0,9,-4,11,0,3,-2,7,0,0,0,13,-4,11,1,-100,-6,13,0,0,0,3,-4,5,0,9,-2,13,0,0,0,7,-4,5,3,-100,-7,3,0,0,0,13,-3,1,1,-4,0,0,0,1,-4,1,7,-100,-7,9,0,0,0,5,-2,13,0,7,-4,5,0,0,0,9,-2,9,0,13,-100,-8,1,0,0,0,13,-1,7,1,-5,11,0,0,0,1,-2,1,3,-100,-8,7,0,0,0,1,13,1,5,-6,1,0,0,0,13,9,0,9,-100,-8,13,0,0,0,0,0,0,11,-6,7,0,0,0,1,0,1,-100,-9,3,0,0,0,0,3,-7,13,0,0,0,0,0,9,-100,-9,9,0,0,0,0,5,-8,3,0,0,0,0,13,-100,-9,13,0,0,0,0,11,-8,9,0,0,0,1,-100,-10,3,0,0,0,-10,3,0,0,5,-100,-10,11,0,0,7,-10,13,1,1,13,-100,-11,11,11,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt23[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-16,13,13,-1,13,9,5,1,0,1,5,13,-100,-1,3,0,0,0,0,0,0,0,0,1,7,-4,1,0,0,0,0,0,0,0,0,0,1,-100,-1,1,0,0,0,0,0,0,0,0,1,11,-4,7,0,0,0,0,0,0,0,0,0,5,-100,-2,13,7,0,0,0,0,0,0,13,-6,13,5,0,0,0,0,5,9,13,-100,-4,13,3,0,0,0,0,3,-7,13,0,0,5,13,-100,-6,3,0,0,0,0,5,-6,7,0,7,-100,-7,3,0,0,0,0,11,-4,11,0,9,-100,-8,5,0,0,0,1,-3,11,0,7,-100,-9,3,0,0,0,1,11,11,0,7,-100,-9,13,1,0,0,0,0,0,7,-100,-10,13,1,0,0,0,0,9,-100,-11,11,0,0,0,0,1,-100,-12,0,0,0,0,0,7,-100,-11,9,0,0,0,0,0,0,11,-100,-10,9,0,5,13,3,0,0,0,1,13,-100,-9,11,0,3,-2,13,1,0,0,0,1,13,-100,-8,11,0,3,13,-3,13,1,0,0,0,1,13,-100,-7,9,0,1,13,-5,11,0,0,0,0,1,13,-100,-6,9,0,0,7,-7,9,0,0,0,0,1,11,-100,-5,5,0,0,0,13,-8,7,0,0,0,0,0,9,-100,-3,13,3,0,0,0,0,13,-8,13,0,0,0,0,0,0,5,-100,9,3,1,0,0,0,0,0,0,1,11,-6,11,1,0,0,0,0,0,0,0,1,3,13,-100,3,0,0,0,0,0,0,0,0,0,3,-6,11,5,3,1,0,0,0,1,1,3,5,-100,13,13,13,13,-100,-100,-100,-100,-100,-100,-100,-100,-100,-101};
char lt24[]={-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-100,-1,13,13,-2,13,13,11,11,11,13,-6,11,11,11,11,11,11,11,11,13,-100,3,0,0,0,0,0,0,0,0,0,0,3,-4,1,0,0,0,0,0,0,0,0,1,-100,7,0,0,0,0,0,0,0,0,0,0,5,-4,3,0,0,0,0,0,0,0,0,9,-100,-2,11,5,0,0,0,0,0,0,11,-6,11,0,0,0,0,1,7,13,-100,-4,11,0,0,0,0,0,-8,9,0,0,1,13,-100,-5,7,0,0,0,0,13,-7,9,0,0,13,-100,-6,1,0,0,0,9,-7,5,0,5,-100,-6,7,0,0,0,3,-7,1,0,13,-100,-6,13,0,0,0,0,13,-5,11,0,1,-100,-7,5,0,0,0,7,-5,7,0,7,-100,-7,11,0,0,0,3,-5,1,0,11,-100,-8,1,0,0,0,13,-3,13,0,3,-100,-8,7,0,0,0,7,-3,7,0,9,-100,-8,13,0,0,0,3,-3,1,1,-100,-9,5,0,0,0,13,-1,9,0,7,-100,-9,11,0,0,0,3,13,1,0,13,-100,-10,1,0,0,0,0,0,3,-100,-10,9,0,0,0,0,0,9,-100,-11,1,0,0,0,1,-100,-11,5,0,0,0,7,-100,-11,9,0,0,0,13,-100,-11,13,0,0,3,-100,-12,0,0,9,-100,-12,0,1,-100,-11,13,0,7,-100,-11,7,0,11,-100,-11,1,0,-100,-2,7,0,1,7,-4,11,0,3,-100,-1,11,0,0,0,0,1,9,13,11,1,0,9,-100,-1,3,0,0,0,0,0,0,0,0,0,3,-100,-1,0,0,0,0,0,0,0,0,0,1,13,-100,-1,7,0,0,0,0,0,0,0,1,13,-100,-2,9,3,0,0,1,3,7,-100,-101};
char *lt[]={lt0,lt1,lt2,lt3,lt4,lt5,lt0,lt7,lt8,lt9,lt10,lt11,lt12,lt13,lt14,lt15,lt16,lt17,lt18,lt19,lt20,lt21,lt22,lt23,lt24};
