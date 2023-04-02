/*
    Wn: A Server for the HTTP
    File: wn/cgi.h
    Version 2.3.0
    
    Copyright (C) 1995-9  <by John Franks>

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
#define CGI_BYTECHUNK	(128*1024)

typedef struct CGI_data {
char	cgi_content_type[SMALLLEN],  /* output content type */
	serv_protocol[TINYLEN],
	home[SMALLLEN],
	dataroot[SMALLLEN],
	dataroot2[SMALLLEN],
	dirpath[SMALLLEN],
	query[MIDLEN + SMALLLEN],
	pathinfo[MIDLEN],
	tpath[MIDLEN],
	scrname[MIDLEN],
	filescrname[MIDLEN],
	http_accept[ACCEPTLEN],
	http_lang[ACCEPTLEN/4],
	http_charset[ACCEPTLEN/4],
	http_encoding[ACCEPTLEN/4],
	http_te[ACCEPTLEN/4],
	http_cookie[ACCEPTLEN],
	http_referrer[MIDLEN],
	http_ua[SMALLLEN],
	http_from[SMALLLEN],
	http_myhost[SMALLLEN],
	http_via[2*SMALLLEN],
	http_xforwardedfor[2*SMALLLEN],
	lochost[SMALLLEN + TINYLEN],
	authtype[TINYLEN],
	authorization[MIDLEN],
	md5[2*TINYLEN],		/* Content-MD5 header */
	ruser[SMALLLEN],
	method[SMALLLEN],
	range[RANGELEN],
	content[SMALLLEN],  /* input content type */
	length[TINYLEN];
} CGI_data;

typedef struct CGI_con_data {
char	servsoft[TINYLEN],
	scheme[TINYLEN],
	rident[SMALLLEN],
	lport[TINYLEN],
	rport[TINYLEN],
	rhost[MAXHOSTNAMELEN + TINYLEN],
	raddr[2*TINYLEN];
} CGI_con_data;

