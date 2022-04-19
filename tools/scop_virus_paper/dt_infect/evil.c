/*
 * l33t sp34k version of puts() for DT_NEEDED .so injection
 * elfmaster 2/15/2019
 */
#define _GNU_SOURCE
#include <dlfcn.h>

/*
 * This code is a l33t sp34k version of puts
 */

long _write(long, char *, unsigned long);

char _toupper(char c)
{
	if( c >='a' && c <= 'z')
		return (c = c +'A' - 'a');
	return c;
}

void ___memset(void *mem, unsigned char byte, unsigned int len)
{
	unsigned char *p = (unsigned char *)mem;
	int i = len;
	while (i--) {
		*p = byte;
		p++;
	}
}

int puts(const char *string)
{
	char *s = (char *)string;
	char new[1024];
	int index = 0;

	int (*o_puts)(const char *);

	o_puts = (int (*)(const char *))dlsym(RTLD_NEXT, "puts");

	___memset(new, 0, 1024);
	while (*s != '\0' && index < 1024) {
		switch(_toupper(*s)) {
			case 'I':
				new[index++] = '1';
				break;
			case 'E':
				new[index++] = '3';
				break;
			case 'S':
				new[index++] = '5';
				break;
			case 'T':
				new[index++] = '7';
				break;
			case 'O':
				new[index++] = '0';
				break;	
			case 'A':
				new[index++] = '4';
				break;
			default:
				new[index++] = *s;
				break;
		}
		s++;
	}

	return o_puts((char *)new);
}
