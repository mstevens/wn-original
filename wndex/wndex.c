/*
    Wn: A Server for the HTTP
    File: wndex/wndex.c
    Version 2.4.3
    
    Copyright (C) 1995-2002  <by John Franks>

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
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include "wndex.h"
#include "reg.h"
#include "regi.h"
#include "version.h"


extern int	errno;

static FILE	*htmlopen();

static void	mkcache(),
		writetext(),
		writedir(),
		amperline(),
		htmlhead(),
		htmlclose(),
		do_recurse(),
		do_maxage(),
		onlyfirst(),
		doattrib(),
		doattrib_dir(),
		despace(),
		clear();

static int	is_filedir();

Entry		top;


int
main( argc, argv)
int	argc;
char	*argv[];
{

	Entry	*ep;

	ep = &top;
	clear( ep);
	init( argc, argv);
	mkcache( ep);
	return (0);
}


static void
clear( ep)
Entry	*ep;
{
	ep->content[0] = ep->cacheline[0] = ep->url[0] = ep->subdirs[0]
	= ep->file[0] = ep->charset[0] = ep->md5[0] = ep->title[0] = '\0';
	ep->flag = ep->attributes = ep->md5_attrib = 0;
	ep->isindexfile = ep->foundtitle = ep->foundkey 
			= ep->foundexp = FALSE;
	ep->attributes = ep->defattributes = 0;
}

static void
mkcache( ep)
Entry	*ep;
{
	FILE	*cntlfp,
		*cachefp,
		*htmlfp = NULL;

	char	*cp,
		*text,
		*bufp,
		*extp,
		buf[MIDLEN],
		mbuf[MIDLEN],
		tmpfpath[MIDLEN],
		htmlpath[MIDLEN];

	int	use_cntrlf = TRUE;

	ep->owner[0] = '\0';
	ep->firsttime = TRUE;
	ep->serveall = FALSE;
	clear_slist();
	mystrncpy( ep->default_content, DEFAULT_CONTENT_TYPE, SMALLLEN);
	mystrncpy( ep->default_charset, DEFAULT_CHARSET, SMALLLEN);
	ep->doindex = ep->inlist = FALSE;
	
	mystrncpy( tmpfpath, ep->cachefpath, MIDLEN);
	if ( (cp = strrchr( tmpfpath, '/')) == NULL )
		mystrncpy( tmpfpath, INDEX_TMPFILE, MIDLEN);
	else {
		*++cp = '\0';
		mystrncat( tmpfpath, INDEX_TMPFILE, MIDLEN);
	}
	if ( (!i_opt_used) 
	     && ((cachefp = fopen( ep->cachefpath, "r")) != (FILE *) NULL) ) {
		buf[0] = '\0';
		fgets( buf, MIDLEN, cachefp);
		if ( (bufp = strstr( buf, "cntlfname="))) {
			mystrncpy( buf, bufp + 10, MIDLEN);
			bufp = buf;
			while ( *bufp && (*bufp != '&') && (*bufp != '\n'))
				bufp++;
			*bufp = '\0';
			if ( (cp = strrchr( ep->cntlfpath, '/'))) {
				*++cp = '\0';
				mystrncat( ep->cntlfpath, buf, MIDLEN);
			}
		}
		fclose( cachefp);
	}

	if ( stdioflg)
		cntlfp = stdin;
	else if ( ((cntlfp = fopen( ep->cntlfpath, "r")) == (FILE *) NULL ) &&
		  ( (! *ep->cntlf2path) ||
		  ((cntlfp = fopen( ep->cntlf2path, "r")) == (FILE *) NULL ))){
		/* can't open */
		if ( strong_serveall) {
			use_cntrlf = FALSE;
			if ( !ep->serveall) {
				addpair( "serveall", "true", ep);
				ep->serveall = TRUE;
			}
		}
		else {
			fprintf( stderr, ERRMSG2, ep->cntlfpath); 
			return;
		}
	}

	if ( stdioflg)
		cachefp = stdout;
	else if ( (cachefp = fopen( tmpfpath, "w")) == (FILE *) NULL ) {
		fprintf( stderr, ERRMSG26, tmpfpath);  /* can't open */
		return;
	}

	while ( use_cntrlf && (bufp = get_next_line( mbuf, cntlfp))) {
		cp = strchr( bufp, '=');  /* guaranteed non-NULL */
		*cp++ = '\0';
		text = cp;
		if ( (extp = strchr( bufp, '(')) != NULL) {
			*extp++ = '\0';
			if ( (cp = strchr( bufp, ')')) == NULL) {
				fprintf( stderr, ERRMSG36, bufp, extp);
				exit( 1);
			}
			*cp = '\0';
		}
			
		strlower( bufp);
		while ( (cp = strchr( bufp, '-')) != NULL )
			strcpy( cp, cp + 1);  /* delete any '-' */

		if ( streq( bufp, "indexfile")) {
			if ( ep->firsttime)
				writedir( cachefp, ep);
			else {
				fprintf( stderr, ERRMSG3);
				exit( 2);
			}
			ep->doindex = ep->isindexfile = TRUE;
			mystrncpy( ep->file, text, SMALLLEN);
			/* used by getcontent() */

			mystrncpy( htmlpath, ep->cachefpath, MIDLEN - SMALLLEN);
			cp = strrchr( htmlpath, '/');
			mystrncpy( ++cp, text, SMALLLEN);

			add_to_slist( text);
			addpair( "file", text, ep);
			ep->flag |= WN_NOINDEX;

			htmlfp = htmlopen( htmlpath);

			continue;
		}

		if ( streq( bufp, "file") || streq( bufp, "link")) {
			if ( ep->firsttime) {
				writedir( cachefp, ep);
			}
			if ( *ep->cacheline)
				writeitem( cachefp, htmlfp, ep);
			mystrncpy( ep->file, text, SMALLLEN);
			add_to_slist( text);
			addpair( "file", text, ep);
			if ( *bufp == 'l') {	/* It's Link= */
				ep->flag |= WN_ISLINK;
				ep->md5_attrib |= WN_NO_MD5;
			}
			continue;
		}

		if ( streq( bufp, "url")) {
			if ( ep->firsttime) {
				writedir( cachefp, ep);
			}
			if ( *ep->cacheline)
				writeitem( cachefp, htmlfp, ep);
			addpair( "url", text, ep);
			mystrncpy( ep->url, text, MIDLEN);
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( streq( bufp, "text")) {
			if ( ep->firsttime) {
				writedir( cachefp, ep);
			}
			if ( *ep->cacheline)
				writeitem( cachefp, htmlfp, ep);

			if ( ep->doindex )
				writetext( cntlfp, htmlfp, ep);
			else
				fprintf( stderr, ERRMSG4);
			continue;
		}

		if ( streq( bufp, "authorizationrealm")) {
			if ( ep->firsttime)
				addpair( "authrealm", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}
		if ( streq( bufp, "putauthorizationrealm")) {
			if ( ep->firsttime)
				addpair( "pauthrealm", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "authdeniedfile")) {
			if ( ep->firsttime)
				addpair( "authdenied_file", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "authorizationmodule")) {
			if ( ep->firsttime)
				addpair( "authmod", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "putauthorizationmodule")) {
			if ( ep->firsttime)
				addpair( "pauthmod", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "authorizationtype")) {
			if ( ep->firsttime)
				addpair( "authtype", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "putauthorizationtype")) {
			if ( ep->firsttime)
				addpair( "pauthtype", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "nosuchfileurl")) {
			if ( ep->firsttime)
				addpair( "nofile_url", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "accessdeniedurl")) {
			if ( ep->firsttime)
				addpair( "noaccess_url", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "cachemodule")) {
			if ( ep->firsttime)
				addpair( "cachemod", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "filemodule")) {
			if ( ep->firsttime)
				addpair( "filemod", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "searchmodule")) {
			if ( ep->firsttime)
				addpair( "indexmod", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}
		if ( streq( bufp, "accessfile")) {
			if ( ep->firsttime) {
				mystrncpy( ep->accessfile, text, SMALLLEN);
				addpair( "accessfile", text, ep);
			}
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "owner")) {
			if ( ep->firsttime) {
				addpair( "owner", text, ep);
				mystrncpy( ep->owner, text, MIDLEN);
			}
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "subdirs")) {
			if ( !ep->firsttime) {
				onlyfirst( bufp);
				continue;
			}

			if ( streq( text, "<all>")) {
				which_subdirs = WNDEX_ALL;
				continue;
			}

			if ( streq( text, "<index>")) {
				which_subdirs = WNDEX_INDEX;
				continue;
			}

			addpair( "subdirs", text, ep);
			mystrncpy( ep->subdirs, text, CACHELINE_LEN);

			continue;
		}

		if ( streq( bufp, "title")) {
			if ( !is_filedir( bufp, ep))
				continue;
			addpair( "title", text, ep);
			mystrncpy( ep->title, text, MIDLEN);
			ep->foundtitle = TRUE;
			continue;
		}

		if ( streq( bufp, "header")) {
			if ( !is_filedir( bufp, ep))
				continue;
			addpair( "header", text, ep);
			continue;
		}

		if ( streq( bufp, "httpstatus")) {
			if ( !is_filedir( bufp, ep))
				continue;
			addpair( "status", text, ep);
			continue;
		}

		if ( streq( bufp, "refresh")) {
			if ( !is_filedir( bufp, ep))
				continue;
			mystrncpy( buf, "Refresh: ", 20);
			mystrncat( buf, text, MIDLEN);
			addpair( "header", buf, ep);
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( streq( bufp, "setcookie")) {
			if ( !is_filedir( bufp, ep))
				continue;
			mystrncpy( buf, text, MIDLEN);
			addpair( "cookie", buf, ep);
			continue;
		}

		if ( streq( bufp, "parse")) {
			if ( !is_filedir( bufp, ep))
				continue;
			ep->attributes |= WN_PARSE;
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( streq( bufp, "redirect")) {
			if ( !is_filedir( bufp, ep))
				continue;
			addpair( "redirect", text, ep);
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( streq( bufp, "keywords")) {
			if ( !is_filedir( bufp, ep))
				continue;
			ep->foundkey = TRUE;
			addpair( "keywords", text, ep);
			continue;
		}

		if ( strncmp( bufp, "field", 5) == 0) {
			if ( !is_filedir( bufp, ep))
				continue;
			addpair( bufp, text, ep);
			continue;
		}

		if ( strncmp( bufp, "charset", 7) == 0) {
			if ( !is_filedir( bufp, ep))
				continue;
			mystrncpy( ep->charset, text, SMALLLEN);
			if ( hascontent( ep) && (!quiet))
				fprintf( stderr, ERRMSG37, text);
			continue;
		}

		if ( streq( bufp, "contenttype")) {
			char cbuf[SMALLLEN];

			if ( !is_filedir( bufp, ep))
				continue;
			mystrncpy( cbuf, text, SMALLLEN);
			strlower( cbuf);
			add_charset( cbuf, ep);
			addpair( "content", cbuf, ep);
			mystrncpy( ep->content, cbuf, SMALLLEN);
			strlower( ep->content);
			ep->flag |= WN_HASCONTENT;
			continue;
		}

		if ( streq( bufp, "contentencoding")
			|| streq( bufp, "encoding")) {

			if ( !is_filedir( bufp, ep))
				continue;

			if ( !streq( text, "none")) {
				addpair( "encoding", text, ep);
			}
			ep->flag |= WN_HASENCODING;
			continue;
		}

		if ( streq( bufp, "includes")) {
			if ( !is_filedir( bufp, ep))
				continue;
			despace( text);
			addpair( "includes", text, ep);
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( streq( bufp, "listincludes")) {
			if ( !is_filedir( bufp, ep))
				continue;
			despace( text);
			addpair( "list", text, ep);
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( strncmp( bufp, "wrapper", 7) == 0 ) {
			if ( !is_filedir( bufp, ep))
				continue;
			despace( text);
			addpair( "wrappers", text, ep);
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( streq( bufp, "searchwrapper")) {
			if ( ep->firsttime)
				addpair( "dwrapper", text, ep);
			else {
				addpair( "swrapper", text, ep);
			}
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( streq( bufp, "emptysub")) {
			if ( !is_filedir( bufp, ep))
				continue;
			addpair( "nomatchsub", text, ep);
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( streq( bufp, "nomatchsub")) {
			addpair( "nomatchsub", text, ep);
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( streq( bufp, "filter")) {
			if ( !is_filedir( bufp, ep))
				continue;
			ep->attributes |= WN_FILTERED;
			addpair( "filter", text, ep);
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( streq( bufp, "cgihandler")) {
			if ( !is_filedir( bufp, ep))
				continue;
			ep->attributes |= WN_CGI;
			addpair( "handler", text, ep);
			ep->md5_attrib |= WN_NO_MD5;
			continue;
		}

		if ( streq( bufp, "puthandler")) {
			if ( !is_filedir( bufp, ep))
				continue;
			ep->attributes |= WN_PUT_OK;
			addpair( "phandler", text, ep);
			continue;
		}

		if ( streq( bufp, "expires")) {
			if ( !is_filedir( bufp, ep))
				continue;
			addpair( "expires", text, ep);
			ep->foundexp = TRUE;
			continue;
		}
		if ( streq( bufp, "maxage")) {
			char	minbuf[TINYLEN];

			if ( !is_filedir( bufp, ep))
				continue;
			do_maxage( text, minbuf);
			addpair( "maxage", minbuf, ep);
			ep->foundexp = TRUE;
			continue;
		}
		if ( streq( bufp, "nosearch")) {
			if ( !is_filedir( bufp, ep))
				continue;
			ep->attributes |= WN_NOSEARCH;
			continue;
		}

		if ( streq( bufp, "defaultcontent")) {
			/* must go to server when serveall */
			strlower( text);
			if ( ep->firsttime) {
				mystrncpy( ep->default_content, text, SMALLLEN);
				addpair( "default_content", text, ep);
			}
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "defaultcharset")) {
			/* must go to server when serveall */
			strlower( text);
			if ( ep->firsttime) {
				mystrncpy( ep->default_charset, text, SMALLLEN);
				/* Do addpair in writedir */
			}
			else
				onlyfirst( bufp);
			continue;
		}

		if ( strncmp( bufp, "defaultwrapper", 14) == 0 ) {
			/* must go to server because of serveall */
			if ( ep->firsttime) {
				addpair( "defwrapper", text, ep);
			}
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "defaultincludes")) {
			/* must go to server because of serveall */
			if ( ep->firsttime) {
				addpair( "defincludes", text, ep);
			}
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "defaultlistincludes")) {
			/* must go to server because of serveall */
			if ( ep->firsttime) {
				addpair( "deflist", text, ep);
			}
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "defaultdocument")) {
			if ( ep->firsttime)
				addpair( "default_document", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "defaultcgihandler")) {
			if ( ep->firsttime)
				addpair( "default_handler", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "defaultputhandler")) {
			if ( ep->firsttime)
				addpair( "default_phandler", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}
		if ( streq( bufp, "defaultcookie")) {
			if ( ep->firsttime)
				addpair( "default_cookie", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "defaultfilter")) {
			if ( ep->firsttime)
				addpair( "default_filter", text, ep);
			else
				onlyfirst( bufp);
			continue;
		}

		if ( streq( bufp, "defaultmaxage")) {
			if ( ep->firsttime) {
				char	minbuf[TINYLEN];

				do_maxage( text, minbuf);
				addpair( "default_maxage", minbuf, ep);
			}
			else
				onlyfirst( bufp);
			continue;
		}
		if ( streq( bufp, "logtype")) {
			char	minbuf[TINYLEN];
			unsigned logtype = 0;

			if ( ep->firsttime) {
				if ( (cp = strchr(text, ':')) != NULL) {
					if ( streq( cp, ":nodns")) {
						logtype = NO_DNS_LOG;
						*cp = '\0';
					}
					else if ( streq( cp, ":revdns")) {
						logtype = REV_DNS_LOG;
						*cp = '\0';
					}
				}
				if ( strcasecmp( text, "nolog") == 0) {
					logtype = WN_NO_LOG + NO_DNS_LOG;
				}
				if ( strcasecmp( text, "common") == 0) {
					logtype |= WN_COMMON_LOG;
				}
				if ( strcasecmp( text, "verbose") == 0) {
					logtype |= WN_VERBOSE_LOG;
				}
				if ( strcasecmp( text, "ncsa") == 0) {
					logtype |= WN_NCSA_LOG;
				}
#ifndef NO_SYSLOG
				if ( strcasecmp( text, "syslog") == 0) {
					logtype |= WN_LOG_SYSLOG;
				}
				if ( strcasecmp( text, "vsyslog") == 0) {
					logtype |= WN_VERBOSE_SYSLOG;
				}
#endif
			}
			else
				onlyfirst( bufp);

			if ( logtype == 0 ) {
				if ( !quiet) 
					fprintf( stderr, ERRMSG34, text);
			}
			else {
				sprintf( minbuf, "%u", logtype);
				addpair( "logtype", minbuf, ep);
			}
			continue;
		}

		if ( strncmp( bufp, "attribute", 9) == 0 ) {
			strlower( text);
			while ( (cp = strchr( text, '-')) != NULL )
				strcpy( cp, cp + 1);  /* delete any '-' */
			despace( text);
			if ( ep->firsttime)
				doattrib_dir( text, ep);
			else
				doattrib( text, ep, &(ep->attributes));
			continue;
		}

		if ( strncmp( bufp, "defaultattribute", 16) == 0 ) {
			if ( ep->firsttime) {
				strlower( text);
				while ( (cp = strchr( text, '-')) != NULL )
					strcpy( cp, cp + 1); /* delete '-' */
				despace( text);
				doattrib( text, ep, &(ep->defattributes));
			}
			else
				onlyfirst( bufp);
			continue;
		}

		fprintf( stderr, ERRMSG5, bufp);
	}	

	if ( ep->firsttime) {
		writedir( cachefp, ep);
	}
	if ( *ep->cacheline)
		writeitem( cachefp, htmlfp, ep);

	if ( ep->doindex && htmlfp) {
		htmlclose( htmlfp, ep);
		fclose( htmlfp);
	}
	if ( ep->serveall) {
		mystrncpy( buf, ep->cachefpath, MIDLEN);
		if ( (cp = strrchr( buf, '/')))
			*++cp = '\0';
		do_serveall( buf, cachefp, htmlfp, ep);
	}

	if ( use_cntrlf)
		fclose( cntlfp);
	fclose( cachefp);

	if ( !stdioflg && (rename( tmpfpath, ep->cachefpath) != 0) ) {
		fprintf( stderr, ERRMSG25, tmpfpath, ep->cachefpath);
		return;
	}

	if ( !quiet)
		printf( MSG1, ep->cachefpath);

}

static void
do_recurse( subdirs, ep)
char	*subdirs;
Entry	*ep;
{
	int	done = FALSE;

	char	*cp,
		*cp2,
		*currsub,
		subs[MIDLEN];

	Entry	next;

	clear( &next);
	mystrncpy( subs, subdirs, MIDLEN);
	cp = subs;
	while ( *cp ) {
		if ( isspace( *cp)) 
			strcpy( cp, cp + 1);
		cp++;
	}
	cp = subs;
	while ( !done && *cp  ) {
		if ( (cp2 = strchr( cp, ',')) == NULL)
			done = TRUE;
		else {
			*cp2 = '\0';
			cp2++;
		}
		currsub = cp;

		if ( !*cp || streq( cp, ".") || streq(cp, ".."))
			continue;

		mystrncpy( next.cntlfpath, ep->cntlfpath, MIDLEN);
		if ( (cp = strrchr( next.cntlfpath, '/')) == NULL ) {
			fprintf( stderr, ERRMSG6, ep->cntlfpath);
			return;
		}
		*++cp = '\0';
		mystrncat( next.cntlfpath, currsub, MIDLEN);
		mystrncat( next.cntlfpath, "/", MIDLEN);
		mystrncat( next.cntlfpath, cntlfname, MIDLEN);

		if ( *(ep->cntlf2path)) {
			mystrncpy( next.cntlf2path, ep->cntlf2path, MIDLEN);
			if ( (cp = strrchr( next.cntlf2path, '/')) == NULL ) {
				fprintf( stderr, ERRMSG6, ep->cntlf2path);
				return;
			}
			*++cp = '\0';
			mystrncat( next.cntlf2path, currsub, MIDLEN);
			mystrncat( next.cntlf2path, "/", MIDLEN);
			mystrncat( next.cntlf2path, cntlf2name, MIDLEN);
		}
		else
			next.cntlf2path[0] = '\0';

		mystrncpy( next.cachefpath, ep->cachefpath, MIDLEN);
		if ( (cp = strrchr( next.cachefpath, '/')) == NULL ) {
			fprintf( stderr, ERRMSG6, ep->cachefpath);
			return;
		}
		*++cp = '\0';
		mystrncat( next.cachefpath, currsub, MIDLEN);
		mystrncat( next.cachefpath, "/", MIDLEN);
		mystrncat( next.cachefpath, cachefname, MIDLEN);

		mkcache( &next);
		clear( &next);
		cp = cp2;
	}
}



static void
onlyfirst( s)
char	*s;
{
	if ( quiet)
		return;
	fprintf( stderr, ERRMSG8, s);
}

static int
is_filedir( s, ep)
char	*s;
Entry	*ep;
{
	if ( ep->firsttime) {
		if ( !quiet)
			fprintf( stderr, ERRMSG23, s);
		return FALSE;
	}
	return TRUE;
}





void 
writeitem( cfp, hfp, ep)
FILE	*cfp,
	*hfp;
Entry	*ep;
{
	char	buf[MIDLEN];

	if ( ep->isindexfile && hfp)
		htmlhead( hfp, ep);
	getcontent( ep);
	if ( (strncmp( ep->content, "text/html", 9) == 0) && 
		((!ep->foundexp) || (!ep->foundtitle) || (!ep->foundkey)))
		getkeytitle( ep);

	if ( ep->md5_attrib & (WN_DO_MD5 + WN_DEF_DO_MD5) ) {
		if ( !(ep->md5_attrib & (WN_NO_MD5 + WN_UNDO_MD5)) ) {
			getmd5( ep);
		}
	}

	if ( !*ep->title ) {
		fmt2( buf, MIDLEN, "File ", ep->file);
		addpair ("title", buf, ep);
		mystrncpy( ep->title, buf, MIDLEN);
	}

	if ( ep->attributes) {
		sprintf( buf, "%d", ep->attributes);
		addpair( "attributes", buf, ep);
	}

	if ( !(ep->flag & WN_ISLINK))
		fprintf( cfp, "%s\n", ep->cacheline);

	if ( ep->doindex && hfp && !(ep->flag & WN_NOINDEX) ) {
		if ( !ep->inlist) {
			ep->inlist = TRUE;
			fprintf( hfp, "<ul>\n");
		}	
		amperline( buf, ep->title, MIDLEN);
		if ( *ep->file)
			fprintf( hfp, "<li> <a href=\"%s\">%s</a>\n",
				ep->file, buf);
		if ( *ep->url) {
			char	*cp,
				buf2[MIDLEN];

			mystrncpy( buf2, ep->url, MIDLEN);
			cp = buf2;
			cp++;
			while ( *cp ) {
				if ( (*cp == '&') && ( *(cp -1) == '\\'))
					mystrncpy( cp - 1, cp, MIDLEN);
				else
					cp++;
			}
			fprintf( hfp, "<li> <a href=\"%s\">%s</a>\n",
						buf2, buf);
		}
	}
	if ( ep->md5_attrib & WN_DEF_DO_MD5 ) {
		clear( ep);
		ep->md5_attrib |= WN_DEF_DO_MD5;
	}
	else
		clear( ep);
}


static void 
writedir( fp, ep)
FILE	*fp;
Entry	*ep;
{
	char	buf[MIDLEN],
		*cp;

	if ( (which_subdirs != WNDEX_NONE) && !*(ep->subdirs)) {
		mystrncpy( buf, ep->cachefpath, MIDLEN);
		if ( (cp = strrchr( buf, '/')))
			*cp = '\0';
		mksubd_list( buf, ep);
		if ( *(ep->subdirs))
			addpair( "subdirs", ep->subdirs, ep);
	}

	if ( recurse) {
		do_recurse( ep->subdirs, ep);
	}

	if ( (!streq( cntlfname, CONTROLFILE_NAME)) &&
			     (!streq( cntlfname, CONTROLFILE2_NAME)) ) {
		mystrncpy( buf, ep->cntlfpath, MIDLEN);
		if ( (cp = strrchr( buf, '/')))
			mystrncpy( buf, cp+1, MIDLEN);
		addpair( "cntlfname", buf, ep);
	}

	if ( ep->defattributes) {
		sprintf( buf, "%d", ep->defattributes);
		addpair( "defattributes", buf, ep);
	}

	if ( !streq( ep->default_content, DEFAULT_CONTENT_TYPE))
		addpair( "default_content", ep->default_content, ep);
	if ( !streq( ep->default_charset, DEFAULT_CHARSET))
		addpair( "default_charset", ep->default_charset, ep);

	fprintf( fp, "%s\n\n", ep->cacheline);
	ep->firsttime = FALSE;
	if ( ep->md5_attrib & WN_DEF_DO_MD5 ) {
		clear( ep);
		ep->md5_attrib |= WN_DEF_DO_MD5;
	}
	else
		clear( ep);
}

static void 
writetext( cfp, hfp, ep)
FILE	*cfp,
	*hfp;
Entry	*ep;
{
	char buf[MIDLEN];

	if ( !hfp)
		return;

	if ( ep->inlist) {
		ep->inlist = FALSE;
		fprintf( hfp, "</ul>\n\n");
	}

	while ( fgets( buf, MIDLEN, cfp)) {
		if ( strncasecmp( buf, "endtext=", 8) == 0 )
			break;
		fprintf( hfp, "%s", buf);
	}
	fprintf( hfp, "\n");
}

static void
htmlhead( hfp, ep)
FILE	*hfp;
Entry	*ep;
{
	char	buf[MIDLEN];

	if ( !hfp)
		return;
	amperline( buf, ep->title, MIDLEN);
	if ( !*ep->owner)
		mystrncpy( ep->owner, MAINTAINER, MIDLEN);
	fprintf( hfp, "<html>\n<head>\n<title>%s</title>\n", buf);
	fprintf( hfp, "<link rev=\"made\" href=\"%s\">\n", ep->owner);
	fprintf( hfp, "</head>\n<body>\n<h2>%s</h2>\n", buf);
}

static void
htmlclose( hfp, ep)
FILE	*hfp;
Entry	*ep;
{
	if ( !hfp)
		return;
	if ( ep->inlist)
		fprintf( hfp, "</ul>\n");
	fprintf( hfp, "</body>\n</html>\n");
}


/*
 * addpair( field, value, ep) 
 * Add &field=value to cacheline escaping any ampersands in
 * value and removing any trailing whitespace.
 */

void
addpair( field, value, ep)
char	*field,
	*value;
Entry	*ep;
{
	char	*cp,
		buf[BIGLEN];


	mystrncpy( buf, value, BIGLEN);

	cp = buf + strlen( buf);
	if ( cp > buf)
		cp--;
	while ( (*cp == ' ') && ( cp >= buf ))
		*cp-- = '\0';

	cp = buf;
	while ( (cp = strchr( cp, '&')) != NULL){
		char buf2[BIGLEN];
		mystrncpy( buf2, cp, BIGLEN);
		*cp++ = '\\';
		*cp++ = '\0';
		mystrncat( buf, buf2, BIGLEN);
	}

	if ( strlen( ep->cacheline) + strlen( buf) > CACHELINE_LEN - 20 ) {
		fprintf( stderr, ERRMSG1, ep->cacheline);
		exit( 2);
	}
	if ( buf[0] != '\0' ) {
		if ( *ep->cacheline) {
			mystrncat( ep->cacheline, "&", CACHELINE_LEN);
		}
		mystrncat( ep->cacheline, field, CACHELINE_LEN);
		mystrncat( ep->cacheline, "=", CACHELINE_LEN);
		mystrncat( ep->cacheline, buf, CACHELINE_LEN);
	}
	else if ( !quiet) {
		fprintf( stderr, ERRMSG18, field, ep->cacheline);
	}
}

/* 
 * Read in line, skip lines with no "=" in them, deal with comments (#),
 * get rid of leading and trailing whitespace.  If line ends with '\' 
 * it continues on next line.  Maximum allowed size of a line is MIDLEN/2.
 */
			
char
*get_next_line( buf, fp)
char	*buf;
FILE	*fp;
{
	register char	*cp,
			*cp2;

	char	*bufp,
		extrabuf[MIDLEN];

	while ( (bufp = fgets( buf, MIDLEN/2, fp))) {
		chop( bufp);

		cp = bufp;
		while ( (cp = strchr( cp, '#')) != NULL) {
			if ( ( cp != bufp) && (*(cp-1) == '\\'))
				strcpy( cp-1, cp);
			else {
				*cp = '\0';
				break;
			}
		}

		cp = buf + strlen(buf) - 1;
		while ( isspace( *cp) && ( cp >= buf))
			*cp-- = '\0';	/* remove trailing whitespace */

		while ( *cp == '\\') {
			*cp = '\0';
			fgets( extrabuf, MIDLEN/2, fp);
			chop( extrabuf);

			if ( (cp = strchr( extrabuf, '#')) != NULL) {
				if ( ( cp != extrabuf) && (*(cp-1) == '\\'))
					strcpy( cp-1, cp);
				else
					*cp = '\0';
			}

			if ( strlen( buf) + strlen( extrabuf) 
						> MIDLEN/2 ) {
				fprintf( stderr, ERRMSG1, buf);
				exit( 2);
			}
			cp = extrabuf;
			while ( isspace( *cp))
				cp++;
			mystrncat( buf, cp, MIDLEN);
			cp = buf + strlen(buf) - 1;
		}

		while ( (*bufp == '\t') || (*bufp == ' '))
			bufp++;
		if ( (cp = strchr( bufp, '=')) == NULL) {
			if ( !quiet && *bufp)
				fprintf( stderr, ERRMSG27, bufp);
			continue;
		}
		break;
	}

	if ( bufp == NULL )
		return NULL;
	if ( (cp2 = cp = strchr( bufp, '=')) == NULL) {
		fprintf( stderr, "Unknown internal error\n");
		exit( 1);
	}

	/* Delete white space around first '=' sign */
	cp--;
	while ( isspace( *cp) && (cp > bufp))
		cp--;
	cp++;
	if ( cp < cp2) {
		*cp = '\0';
		mystrncat( bufp, cp2, MIDLEN);
	}
	cp2 = cp;
	cp++;
	while ( *cp && isspace( *cp))
		cp++;
	cp2++;
	if ( cp > cp2) {
		*cp2 = '\0';
		mystrncat( bufp, cp, MIDLEN);
	}
	return bufp;
}
	


static FILE
*htmlopen( path)
char	*path;
{
	FILE	*htmlfp;

	char	buf[SMALLLEN];

	mystrncpy( buf, path, SMALLLEN);
	mystrncat( buf, ".bak", SMALLLEN);

	if ( (rename( path, buf) < 0) && (errno != ENOENT)) {
		fprintf( stderr, ERRMSG16, path);
		return NULL;
	}
	if ( (htmlfp = fopen( path, "w")) == (FILE *) NULL ) {
		fprintf( stderr, ERRMSG2, path);
		return NULL;
	}
	if ( !quiet) 
		printf( MSG2, path);

	return htmlfp;
}


char *
strlower( st)
char	*st;
{
	register char	*cp;

	cp = st;
	while ( *cp) {
		*cp =  (isupper(*cp) ? *cp - 'A' + 'a' : *cp );
		cp++;
	}
	return (st);
}


/*
 * int amperline( p1, p2, maxlen)  Copy p2 to p1 until p2 is
 * exhausted or (at most) maxlen - 1 characters are transfered.
 * Encode '<', '>', and & as "&lt;", etc.
 */

static void
amperline ( p1, p2, maxlen)
char	*p1,
	*p2;
long	maxlen;
{
	char *svp2;
	register char *cp;

	svp2 = p2;
	maxlen--;
	while ( *p2 ) {
		if ( --maxlen < 5 ) {
			fprintf( stderr, ERRMSG33, svp2); 
			break;
		}
		switch( *p2) {
		case '<':
			strcpy( p1, "&lt;");
			maxlen -= 3;
			p1 += 4;
			p2++;
			break;
		case '>':
			strcpy( p1, "&gt;");
			maxlen -= 3;
			p1 += 4;
			p2++;
			break;
		case '&':
			cp = p2;
			cp++;
			while ( isalnum( *cp))
				cp++;

			if ( *cp == ';') {
				*p1++ = *p2++;
			}
			else {
				strcpy( p1, "&amp;");
				maxlen -= 4;
				p1 += 5;
				p2++;
			}
			break;
		default:
			*p1++ = *p2++;
		}
	}
	*p1 = 0;
}


#if NEED_STRNCASECMP

/*
 *  Case insensitive comparison of first n chars of two strings
 */

int
strncasecmp( s1, s2, n)
char	*s1,
	*s2;
int	n;

{
	int	r;

	while ( *s1 && *s2 && ( n > 0)) {
		if ( (r = (tolower( *s1) - tolower( *s2))) != 0 )
			return r;
		s1++;
		s2++;
		n--;
	}
	return ( n == 0 ? 0 : *s1 - *s2);
}
#endif


#if NEED_STRSTR
/*
 * Find the first occurrence of find in s.
 *
 * For copyright, see ../wn/misc.c
 */
char *
strstr(s, find)
char	*s, *find;
{
	register char c,
	  sc;
	register size_t len;

	if ((c = *find++) != 0) {
		len = strlen(find);
		do {
			do {
				if ((sc = *s++) == 0)
					return (NULL);
			} while (sc != c);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char *) s);
}
#endif

/* Replace comma followed by spaces with comma only */

static void 
despace( s) 
char	*s;
{
	register char	*cp;

	cp = s;
	while ( *cp ) {
		if ( isspace(*cp) && (*(cp + 1) == ',')) {
			strcpy( cp, cp + 1);
			continue;
		}
		if ( (*cp == ',') && isspace(*(cp + 1))) {
			strcpy( cp + 1, cp + 2);
			continue;
		}
		cp++;
	}
}


static void
doattrib( text, ep, attrib)
char		*text;
Entry		*ep;
unsigned	*attrib;
{
	char	*word,
		*nextword;

	word = nextword = text;
	while ( nextword ) {
		word = nextword;
		if ( (nextword = strchr( word, ',')) != NULL)
			*nextword++ = '\0';

		if ( streq( word, "invisible") ) {
			ep->flag |= WN_NOINDEX;
			*attrib |= WN_NOSEARCH;
			continue;
		}
		if ( streq( word, "noindex") ) {
			ep->flag |= WN_NOINDEX;
			continue;
		}
		if ( streq( word, "nosearch") ) {
			*attrib |= WN_NOSEARCH;
			continue;
		}
		if ( streq( word, "imagemap") ) {
			*attrib |= WN_ISMAP;
			continue;
		}
		if ( streq( word, "dynamic") ) {
			*attrib |= WN_DYNAMIC;
			continue;
		}
		if ( streq( word, "nondynamic") ) {
			*attrib |= WN_NONDYNAMIC;
			continue;
		}
		if ( streq( word, "keepalive") ) {
			*attrib &= ~(WN_NOKEEPALIVE);
			continue;
		}
		if ( streq( word, "nokeepalive") ) {
			*attrib |= WN_NOKEEPALIVE;
			continue;
		}
		if ( strncmp( word, "cach", 4) == 0 ) {
			*attrib |= WN_CACHEABLE;
			continue;
		}
		if ( strncmp( word, "noncach", 7) == 0 ) {
			*attrib |= WN_NOCACHE;
			continue;
		}
		if ( streq( word, "parse") ) {
			*attrib |= WN_PARSE;
			continue;
		}
		if ( streq( word, "post") ) {
			*attrib |= WN_POST_OK;
			continue;
		}
		if ( streq( word, "nopost") ) {
			*attrib |= WN_NO_POST;
			continue;
		}
		if ( streq( word, "noget") ) {
			*attrib |= WN_NO_GET;
			continue;
		}
		if ( streq( word, "put") ) {
			*attrib |= WN_PUT_OK;
			continue;
		}
		if ( streq( word, "noparse") ) {
			*attrib |= WN_NOPARSE;
			continue;
		}
		if ( streq( word, "cgi") ) {
			*attrib |= WN_CGI;
			continue;
		}
		if ( streq( word, "unbuffered") ) {
			*attrib |= WN_UNBUFFERED;
			continue;
		}
		if ( streq( word, "md5") ) {
			if ( attrib == &(ep->attributes) )
				ep->md5_attrib |= WN_DO_MD5;
			else if ( attrib == &(ep->defattributes) )
				ep->md5_attrib |= WN_DEF_DO_MD5;
			continue;
		}
		if ( streq( word, "nomd5") ) {
			if ( attrib == &(ep->attributes) )
				ep->md5_attrib |= WN_UNDO_MD5;
			continue;
		}
		fprintf( stderr, ERRMSG19, word);
			continue;
	}
}


static void
doattrib_dir( text, ep)
char		*text;
Entry		*ep;
{
	char	*word,
		*nextword;

	word = nextword = text;
	while ( nextword ) {
		word = nextword;
		if ( (nextword = strchr( word, ',')) != NULL)
			*nextword++ = '\0';

		if ( streq( word, "serveall") ) {
#if NO_SERVEALL
			if ( !quiet)
				fprintf( stderr, ERRMSG31);
#else
			if ( !ep->serveall) {
				addpair( "serveall", "true", ep);
				ep->serveall = TRUE;
			}
#endif
			continue;
		}
		if ( streq( word, "nosearch") ) {
			addpair( "nosearch", "true", ep);
			continue;
		}
		fprintf( stderr, ERRMSG20, word);
		continue;
	}
}

static void
do_maxage( words, seconds)
char	*words,
	*seconds;
{
	long	n,
		secs = 0;

	int	use_lmd = FALSE;

	char	*cp,
		buf[SMALLLEN];
	
	if ( (cp = strstr( words, "after")) != NULL) {
		*cp = '\0';
		use_lmd = TRUE;
	}

	buf[0] = '\0';
	sscanf( words, "%30ld %15s", &n, buf);

	switch ( tolower(buf[0])) {
	case 'm':
			secs = n * (60);
			break;

	case 'h':
			secs = n * (60 * 60);
			break;

	case 'd':
			secs = n * (24 * 60 * 60);
			break;

	case 'w':
			secs = n * (7 * 24 * 60 * 60);
			break;
	case 's':
	default:
			secs = n;
			break;
	}

	if ( use_lmd) 
		sprintf( seconds, "L%ld", secs);
	else
		sprintf( seconds, "%ld", secs);

}
