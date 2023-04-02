/*
    Wn: A Server for the HTTP
    File: wndex/content.c
    Version 2.4.3
    
    Copyright (C) 1996-2002  <by John Franks>

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

#define WNDEX

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "wndex.h"
#include "content.h"

#define NOTHING		(0)
#define EXPIRES		(1)
#define KEYWORDS	(2)

extern void	md5_do_fp( );
static void	dometa();

static char	*findword();



void
getcontent( ep)
Entry	*ep;
{

	register char	*cp;

	char	suffix[SMALLBUF],
		cbuf[SMALLLEN],
		buf[SMALLBUF];
	int	i = 0;

	if ( ep->flag & WN_ISURL)
		return;
	mystrncpy( buf, ep->file, SMALLBUF);
	strlower( buf);

	cp = strrchr( buf, '.');

	if ( cp == NULL ) { /*There's no suffix */
		if ( hascontent( ep))
			return;

		mystrncpy( cbuf, ep->default_content, SMALLLEN);
		strlower( cbuf);
		add_charset( cbuf, ep);
		addpair( "content", cbuf, ep);
		mystrncpy( ep->content, cbuf, SMALLLEN);
		return;
	}
	*cp++ = '\0';
	mystrncpy( suffix, cp, SMALLBUF);

	if ( (PARSE_EXT != "") && streq( suffix, PARSE_EXT) && 
					!(ep->attributes  & WN_NOPARSE))
		ep->attributes |= WN_PARSE;

	if ( strcasecmp( suffix, MAPFILE_EXT) == 0) {
		ep->attributes |=  WN_ISMAP;
		fmt2( cbuf, SMALLLEN, "text/plain; charset=", ep->default_charset);
		addpair( "content", cbuf, ep);
		mystrncpy( ep->content, cbuf, SMALLLEN);
		ep->flag |= WN_HASCONTENT;
	}

	if ( (cp = strstr( CGI_EXT_LIST, suffix)) != NULL ) {
		if ( *(cp-1) == '.' ) {
			cp += strlen( suffix);
			if ( (!*cp) || (*cp == ',')) {
				ep->attributes |=  WN_CGI;
			}
		}
	}

	if ( hascontent( ep))
		return;

	while ( mimelist[i][0] != NULL) {
		if ( streq( mimelist[i][0], suffix)) {
			mystrncpy( cbuf, mimelist[i][1], SMALLLEN);
			strlower( cbuf);
			add_charset( cbuf, ep);
			addpair( "content", cbuf, ep);
			mystrncpy( ep->content, cbuf, SMALLLEN);
			return;
		}
		i++;
	}

	/* Unrecognized suffix */
	mystrncpy( cbuf, ep->default_content, SMALLLEN);
	strlower( cbuf);
	add_charset( cbuf, ep);
	addpair( "content", cbuf, ep);
	mystrncpy( ep->content, cbuf, SMALLLEN);
	return;
}

void
add_charset( buf, ep)
char *buf;
Entry *ep;
{
	char *csptr;
	if ( (strncmp( buf, "text/", 5) != 0) ||
			     ( strstr( buf, "charset") != NULL)) {
		return;
	}

	if ( *ep->charset)
		csptr = ep->charset;
	else
		csptr = ep->default_charset;
	fmt3( buf, SMALLLEN, buf, "; charset=", csptr);
}

void
loadmime()
{
	
	register char	*cp, *cp2, *slash;
	char	buf[2*SMALLBUF];
	FILE	*mimefp;
	int	i = 0;

	if ( (mimefp = fopen( MIME_TYPE_FILE, "r")) == (FILE *) NULL) {
		if ( verboseflg)
			fprintf(stderr, ERRMSG9, MIME_TYPE_FILE );
		return;
	}

	while ( fgets( buf, 2*SMALLBUF, mimefp)) {
		chop( buf);
		if ( !buf[0] || buf[0] == '#')
			continue;

		if ( (cp = malloc( SMALLBUF)) == NULL) {
			fprintf(stderr, ERRMSG10);
			exit( 2);	
		}
		mystrncpy( cp, buf, SMALLBUF);
		while ( isspace( *cp))
			cp++;
		cp2 = cp;

		while ( *cp2 && !isspace( *cp2))
			cp2++;
		if ( (slash = strchr( cp, '/')) == NULL) {
			fprintf(stderr, ERRMSG11, MIME_TYPE_FILE );
			fprintf(stderr, "\tLine = %s\n", buf);
			continue;
		}

		if ( !*cp2)
			continue; /* There are no suffixes, so ignore it */

		if ( slash < cp2) {
			/* Format is "type<space>suffix<space>suffix..." */
				*cp2++ = '\0';
		}
		else {
			/* It's old style "suffix<tab>type" */
			cp2 = cp; /* cp2 now points to suffix list */
			cp = slash;
			while ( (cp > cp2) && !isspace( *cp))
				cp--;
			*cp++ = '\0';  /* cp now points to MIME type */
		}

		while ( isspace( *cp2))
			cp2++;

	/* mimelist[i][0] is the suffix, mimelist[i][1] is the MIME type */

		mimelist[i][0] = cp2;
		mimelist[i][1] = cp;

		/* Handle multiple suffixes for one type */

		while ( *cp2 ) {
			while ( *cp2 && !isspace( *cp2))
				cp2++;
			if ( *cp2 ) {
				*cp2++ = '\0';
				while ( *cp2 && isspace( *cp2))
					cp2++;
				if ( !*cp2)
					break;
				i++;
				if ( i >= MAXMIME) {
					fprintf(stderr, ERRMSG12);
					exit( 2);
				}
				mimelist[i][0] = cp2;
				mimelist[i][1] = mimelist[i-1][1];
			}
		}
		i++;
		if ( i >= MAXMIME) {
			fprintf(stderr, ERRMSG12);
			exit( 2);
		}
	}
	mimelist[i][0] = mimelist[i][1] = NULL;
	fclose( mimefp);
}

/*
 * void getkeytitle( ep) Read the HTML file to get the keywords and/or 
 * title.
 */

void
getkeytitle( ep)
Entry	*ep;
{

	char		*cp,
			*cp2 = NULL;

	int	i = 0;

	FILE	*fp;
	char	filepath[MIDLEN],
		tbuf[MIDLEN],
		buf[MIDLEN];

	if ( ep->flag & WN_ISURL)
		return;

	mystrncpy( filepath, ep->cachefpath, MIDLEN);

	if ( (cp = strrchr( filepath, '/')) != NULL)
		*++cp = '\0';
	else
		mystrncpy( filepath, "./", MIDLEN);

	mystrncat( filepath, ep->file, MIDLEN);

	if ( (fp = fopen( filepath, "r")) == (FILE *) NULL ) {
		if ( (!quiet) && (!ep->foundtitle) 
				&& (!strstr( ep->cacheline, "&redirect=")) ) {
			fprintf( stderr, ERRMSG14, filepath);
		}
		if ( !ep->foundtitle) {
			fmt2( buf, MIDLEN, "File ", ep->file);
			addpair ("title", buf, ep);
			mystrncpy( ep->title, buf, MIDLEN);
		}
		return;
	}

	while ( fgets( buf, MIDLEN, fp) && i < NUM_TITLE_LINES ) {
		chop( buf);
		i++;
		if ( (!ep->foundtitle) && (cp = findword( buf, "<title")) ) {
			cp += 7;
			tbuf[0] = '\0';
			while ( cp && !(cp2 = findword( cp, "</title>")) ) {
				if ( strlen( tbuf) + strlen( cp) >= MIDLEN) {
					fprintf( stderr, ERRMSG17, tbuf);
					cp = cp2 = NULL;
					break;
				}
				mystrncat( tbuf, cp, MIDLEN);
				if ( *cp)
					mystrncat( tbuf, " ", MIDLEN);
				if ( (cp = fgets( buf, MIDLEN, fp)) == NULL)
					break;
				chop( buf);
				i++;
			}
			if ( cp2 && cp && (cp2 >= cp) ) {
				*cp2 = '\0';
				mystrncat( tbuf, cp, MIDLEN);
				mystrncpy( buf, cp2 + 8, MIDLEN);
				/* copy remainder of line to buf */
			}

			addpair( "title", tbuf, ep);
			mystrncpy( ep->title, tbuf, MIDLEN);
			ep->foundtitle = TRUE;
			
		}

		if ( (cp = findword( buf, "<meta")) )
			dometa( cp, ep);

		if ( ep->foundkey && ep->foundtitle && ep->foundexp)
			break;
		if ( findword( buf, "</head>") ) 
			break;

	}
	if ( !*ep->title && !quiet && verboseflg) {
		fprintf( stderr, ERRMSG15, filepath);
	}
	if ( !*ep->title ) {
		fmt2( buf, MIDLEN, "File ", ep->file);
		addpair ("title", buf, ep);
		mystrncpy( ep->title, buf, MIDLEN);
	}
	fclose( fp);
}


static void
dometa( linebuf, ep)
char	*linebuf;
Entry	*ep;
{
	register char	*cp,
			*cp2;

	int		httpequiv = NOTHING;

	if ( (cp = strchr( linebuf, '=')) == NULL )
		return;
	cp++;
	while ( isspace( *cp) || *cp == '"')
		cp++;
	if ( strncasecmp( cp, "keywords", 8) == 0 )
		httpequiv = KEYWORDS;
	if ( strncasecmp( cp, "expires", 7) == 0 )
		httpequiv = EXPIRES;
	if ( (cp = strchr( cp, '=')) == NULL )
		return;
	cp++;
	while ( isspace( *cp) || *cp == '"')
		cp++;
	if ( (cp2 = strchr( cp, '"')) == NULL )
		return;
	*cp2 = '\0';
	switch( httpequiv) {
	case KEYWORDS:
		if ( ep->foundkey)
			break;
		addpair( "keywords", cp, ep);
		ep->foundkey = TRUE;
		break;

	case EXPIRES:
		if ( ep->foundexp)
			break;
		addpair( "expires", cp, ep);
		ep->foundexp = TRUE;
		break;
	}
}

static char *
findword( line, word)
char	*line,
	*word;
{
	char	*cp,
		wordbuf[SMALLLEN],
		buf[MIDLEN];

	mystrncpy( buf, line, MIDLEN);
	mystrncpy( wordbuf, word, SMALLLEN);
	strlower( buf);
	strlower( wordbuf);
	if ( (cp = strstr( buf, wordbuf)) == NULL)
		return NULL;
	return ( line + ( cp - buf));
}





/*
 * void getmd5( ep) Read the file and calculate base64( MD5(file)).
 */

void
getmd5( ep)
Entry	*ep;
{

	register char	*cp;

	char	filepath[MIDLEN];
	FILE	*fp;


	if ( (ep->md5_attrib == 0 ) || (ep->md5_attrib & WN_UNDO_MD5 ) )
		return;

	*ep->md5 = '\0';

	if ( (ep->attributes & (WN_CGI + WN_DYNAMIC + WN_PARSE + WN_ISMAP)) ||
			(ep->flag & WN_ISURL) || (ep->md5_attrib & WN_NO_MD5) ) {
		if ( !quiet)
			fprintf( stderr, ERRMSG32, ep->file);
		return;
	}

	mystrncpy( filepath, ep->cachefpath, MIDLEN);
	if ( (cp = strrchr( filepath, '/')) != NULL)
		*++cp = '\0';
	else
		mystrncpy( filepath, "./", MIDLEN);


	mystrncat( filepath, ep->file, MIDLEN);

	if ( (fp = fopen( filepath, "r")) == (FILE *) NULL ) {
		if ( (!quiet) && (!strstr( ep->cacheline, "&redirect=")) ) {
			fprintf( stderr, ERRMSG14, filepath);
		}
		return;
	}
	md5_do_fp( fp, ep->md5 );

	addpair( "md5", ep->md5, ep);

	fclose( fp);

}

/*
 * mystrncpy( s1, s2, n) is an strncpy() which guarantees a null
 * terminated string in s1.  At most (n-1) chars are copied.
 * Returns -1 if truncation occurred and (n-1) minus number of
 * bytes copied otherwise.
 */

/*
int
mystrncpy( s1, s2, n)
char	*s1,
	*s2;
int	n;

    replaced by macro fmt3( s1, n, s2, NULL, NULL)
*/


/*
 * mystrncat( s1, s2, n) is an strncat() which guarantees a null
 * terminated string in s1.  At most (n-1) chars TOTAL are in the
 * concatenated string.  If the original s1 had more than that
 * it is truncated.
 * Returns -1 if truncation occurred and (n-1) minus number of
 * bytes in new s1 otherwise.
 */

/*
int
mystrncat( s1, s2, n)
char	*s1,
	*s2;
int	n;

     replaced by macro fmt3( s1, n, s1, s2, NULL)
*/


/*
 * fmt3( buf, maxlen, s1, s2, s3) concatenates s1, s2, s3 in buf and
 * guarantees a null terminated string.  At most (n-1) chars TOTAL are
 * in the concatenated string.  Returns -1 if truncation occurred and
 * (n-1) minus number of bytes in new buf otherwise.  It will do the
 * right thing if buf == s1.  If any of s1, s2, or s3 are NULL they
 * are skipped.
 */

int
fmt3( buf, maxlen, s1, s2, s3)
char *buf;
int maxlen;
char	*s1,
	*s2,
	*s3;
{
	register char	*cpo,
			*cpi;
	int errflg = FALSE;

	if ( (cpo = buf) == NULL)
		return (-1);
	cpi = s1;

	maxlen--;

	if ( s1 == buf) { /* we're appending to buf */
		while ( *cpi && (maxlen > 0)) {
			cpi++;
			cpo++;
			maxlen--;
		}
	}
	else if ( cpi != NULL) {
		while ( *cpi && (maxlen > 0)) {
			maxlen--;
			*cpo++ = *cpi++;
		}
	}
	if ( cpi && *cpi)
		errflg = TRUE;

	if ( (cpi = s2) != NULL) {
		while ( *cpi && (maxlen > 0)) {
			maxlen--;
			*cpo++ = *cpi++;
		}
	}
	if ( cpi && *cpi)
		errflg = TRUE;

	if ( (cpi = s3) != NULL) {
		while ( *cpi && (maxlen > 0)) {
			maxlen--;
			*cpo++ = *cpi++;
		}
	}
	if ( cpi && *cpi)
		errflg = TRUE;

	*cpo = '\0';
	if ( errflg ) {
		fprintf( stderr, ERRMSG33, buf);
		return (-1);
	}
	else
		return (maxlen);

}

#if NEED_STRCASECMP

/*
 *  Case insensitive comparison of two strings
 */

int
strcasecmp( s1, s2)
char	*s1,
	*s2;

{
	int	r;

	while ( *s1 && *s2 ) {
		if ( (r = (tolower( *s1) - tolower( *s2))) != 0 )
			return r;
		s1++;
		s2++;
	} 
	return ( *s1 - *s2);
}
#endif
