/*
    Wn: A Server for the HTTP
    File: wn/isearch.c
    Version 2.4.0
    
    Copyright (C) 1995-2001  <by John Franks>

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


#include <string.h>
#include "wn.h"
#include "regi.h"

/* Do index search of directory pointed to by ip->filepath */

void
send_isearch( ip)
Request	*ip;
{
	FILE	*sfp;

	int	c;

	char	linebuf[MIDLEN],
		querybuf[MIDLEN];

	*ip->length = '\0';
	check_query( ip, (struct regprog **)NULL, (struct regprog **)NULL);
	if ( *(ip->query)) {
		strcpy( querybuf, "QUERY_STRING=");
		mystrncat( querybuf, ip->query, MIDLEN);
		putenv( querybuf);
	}

	cgi_env( ip, WN_FULL_CGI_SET);


	if ( dir_p->attributes & WN_DIRNOSEARCH) {
		senderr( "403", err_m[32], ip->relpath);
		return;
	}

	search_prolog( ip, out_m[1]);  

	if ( (sfp = WN_popen( dir_p->indexmod, "r")) == (FILE *) NULL ) {
		senderr( SERV_ERR, err_m[33], dir_p->indexmod);
		return;
	}

        if ( ( c = getc( sfp)) == EOF) {
		send_nomatch( ip, 'd');
		pclose( sfp);
		return;
	}
	else
                ungetc( c, sfp);

	if ( dir_p->attributes & WN_DIRWRAPPED) 
		do_swrap( ip);

	if ( ip->status & WN_ERROR) {
		pclose( sfp);
		return;  /* abort this transaction */
	}

	while ( fgets( linebuf, MIDLEN, sfp))
		send_text_line( linebuf);

	if ( dir_p->attributes & WN_DIRWRAPPED) {
		do_swrap( ip);
	}
	else
		search_epilog( );

	writelog(  ip, log_m[11], "");
	pclose( sfp);
}


