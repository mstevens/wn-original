/*
    Wn: A Server for the HTTP
    File: wndex/base64.c
    Version 2.3.4
    
    Copyright (C) 1995-2000  <by John Franks>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 1, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "wndex.h"
#include "../md5/md5.h"

static WN_CONST char base64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void
digest2b64( digest, out)
unsigned char	*digest;
char		*out;
{
	int	i;

	char *cp;

	cp = out;

	digest[MD5_DIGEST_LENGTH] = digest[MD5_DIGEST_LENGTH+1] = 0;

	for (i = 0; i < MD5_DIGEST_LENGTH; i += 3) {
		*cp++ = base64[digest[i]>>2];
		*cp++ = base64[((digest[i] & 0x3)<<4) |
				((digest[i+1] & 0xF0)>>4)];
		*cp++ = base64[((digest[i+1] & 0xF)<<2) | 
				((digest[i+2] & 0xC0)>>6)];
		*cp++ = base64[digest[i+2] & 0x3F];
	}
	*cp-- = '\0';
	*cp-- = '=';
	*cp-- = '=';
	return;
}



#define BUFSIZE (1024*16)

void md5_do_fp( fp, out)
FILE *fp;
char *out;
{
	MD5_CTX ctx;
	int fd;
	unsigned char md[MD5_DIGEST_LENGTH];
	static unsigned char buf[BUFSIZE];

	fd = fileno( fp);
	MD5_Init( &ctx);
	while (TRUE) {
		int n;

		n = read( fd, buf, BUFSIZE);
		if ( n <= 0)
			break;

		MD5_Update( &ctx, buf, (unsigned long)n);
	}
	MD5_Final( &(md[0]), &ctx);
	digest2b64( md, out);
}

