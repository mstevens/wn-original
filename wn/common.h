/*
    Wn: A Server for the HTTP
    File: wn/common.h
    Version 2.3.11
    
    Copyright (C) 1996-2000  <by John Franks>

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

#ifndef TRUE
#define TRUE	(1)
#endif

#ifndef FALSE
#define FALSE	(0)
#endif

#if MAKE_WNSSL
#define STANDARD_PORT	(443)
#else
#define STANDARD_PORT	(80)
#endif

#define	MIDLEN		(2048)
#define	SMALLLEN	(MIDLEN/8)
#define	BIGLEN		(2*MIDLEN)
#define	CACHELINE_LEN	(4*MIDLEN)
#define	HEADERTEXTLEN	(4*MIDLEN)
#define	RANGELEN	(1024)
#define	TINYLEN		(32)
#define USERNAME_LEN	(64)
#define INBUFFSIZE	(2048)
#define OUT_BUFFSIZE	(4096)  /* MUST be less than FFFF hex */
				/* see end_chunking in send.c  */

/* Bits in the Request attributes */
#define WN_DYNAMIC	(1<<0)
#define WN_NONDYNAMIC	(1<<1)
#define WN_POST_OK	(1<<2)
#define WN_PUT_OK	(1<<3)
#define WN_NO_POST	(1<<4)
#define	WN_FILTERED	(1<<5)
#define	WN_NOSEARCH	(1<<6)
#define	WN_PARSE	(1<<7)
#define	WN_NOPARSE	(1<<8)
#define	WN_CGI		(1<<9)
#define WN_ISMAP	(1<<10)
#define WN_NOCACHE	(1<<11)
#define WN_UNBUFFERED	(1<<12)
#define WN_CACHEABLE	(1<<13)
#define WN_NOKEEPALIVE	(1<<14)
#define WN_NO_GET	(1<<15)


/* Bits in the request attrib2 */
#define	WN_INCLUDE		(1<<0)
#define	WN_WRAPPED		(1<<1)
#define	WN_SWRAPPED		(1<<2)
#define	WN_LIST_INCL		(1<<3)
#define	WN_ISSEARCH		(1<<4)
#define	WN_ISACGIBIN		(1<<5)
#define	WN_FILEMOD		(1<<6)
#define WN_USE_DEF_CACHEFILE	(1<<7)

/* Bits in the request logtype */
#define		WN_NO_LOG		(1<<0)
#define		WN_COMMON_LOG		(1<<1)
#define		WN_VERBOSE_LOG		(1<<2)
#define		WN_NCSA_LOG		(1<<3)
#define		WN_LOG_SYSLOG		(1<<4)
#define		WN_VERBOSE_SYSLOG	(1<<5)
#define		NO_DNS_LOG		(1<<11)
#define		REV_DNS_LOG		(1<<12)
