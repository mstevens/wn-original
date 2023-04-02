/*
    WN: A Server for the HTTP
    File: puth/puth.c
    Version 2.3.9
    
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

#define DEBUG
#define DEBUG_LOG	"/tmp/PUTH_DEBUG"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/signal.h>

#include "../config.h"
#include "puth.h"

#define PUTH_TIMEOUT	(60)

extern char *optarg;
extern int optind;

extern char	*getenv();

static void	put_abort( ),
		success( ),
		puth_timeout();


#ifdef DEBUG
static void	log_debug();
#endif

static int	copy_file( char *, char *),
		mystrncpy( char *, char *, int),
		mystrncat( char *, char *, int);

int
main( argc, argv)
int	argc;
char	*argv[];

{
	register char	*cp;


	char	method[SMALLLEN],
		uri_filename[MIDLEN],
		new_filename[MIDLEN],
		buf[MIDLEN],
		tmpfilename[MIDLEN];

	signal( SIGALRM, puth_timeout);
	alarm( PUTH_TIMEOUT);

	tmpfilename[0] = uri_filename[0] = '\0';

	if ( (cp = getenv( "REQUEST_METHOD")) != NULL )
		mystrncpy( method, cp, SMALLLEN);
	else
		put_abort( P_ERRMSG1, NULL);

	if ( (cp = getenv( "SCRIPT_FILENAME")) != NULL )
		mystrncpy( uri_filename, cp, MIDLEN);
	else
		put_abort( P_ERRMSG2, NULL);

	if ( streq( method, "PUT")) {
		int res = 0;

		if ( (cp = getenv( "HTTP_PUT_FILE")) != NULL )
			mystrncpy( tmpfilename, cp, MIDLEN);
		else
			put_abort( P_ERRMSG3, NULL);

#ifdef DEBUG
		log_debug( "TEMPFILE=", tmpfilename);
#endif

		/* try to link first */
		if ((res = link( tmpfilename, uri_filename))
					&& errno != EEXIST ) {
			/* else copy */
			if ( copy_file( tmpfilename, uri_filename)) {
				put_abort( P_ERRMSG4, uri_filename);
			}
		}
		else if ( (res == -1) && (errno == EEXIST) ) {
			if ( unlink( uri_filename) != 0 )
				put_abort( P_ERRMSG5, uri_filename);
			/* try to link first */
			if ( link( tmpfilename, uri_filename)) {  
				/* else copy */
				if ( copy_file( tmpfilename, uri_filename)) {
					put_abort( P_ERRMSG4, uri_filename);
				}
			}
		}

		if ( chmod( uri_filename, 0644))
			put_abort( P_ERRMSG11, uri_filename);

		success( "PUT Success", NULL );
		return ( 0);
	}

	if ( streq( method, "DELETE")) {
		if ( unlink( uri_filename) != 0 )
			put_abort( P_ERRMSG5, uri_filename);
		success( "DELETE Success", NULL );
		return ( 0);
	}
	if ( streq( method, "MOVE")) {
		char *cp2 = NULL;
		if ( (cp = getenv( "HTTP_NEW_URI")) != NULL )
			mystrncpy( new_filename, cp, MIDLEN);
		else
			put_abort( P_ERRMSG6, NULL);

		mystrncpy( buf, uri_filename, MIDLEN);
		if ( ((cp = strrchr( new_filename, '/')) == NULL) ||
				((cp2 = strrchr( buf, '/')) == NULL)) {
			put_abort( P_ERRMSG9, uri_filename);
		}
		*cp2 = '\0';
		mystrncat( buf, cp, MIDLEN);
		if ( rename( uri_filename, buf) != 0 )
			put_abort( P_ERRMSG7, new_filename);
		success( "MOVE Success", NULL );
		return ( 0);
	}
	put_abort( P_ERRMSG8, method);
	return ( 0);
}


/* Copy file, return 0 on success, (-1) on failure */

static int
copy_file( srcfile, destfile)
char	*srcfile,
	*destfile;
{

	FILE	*sfp,
		*dfp;


	int	c;

	if ( streq( srcfile, destfile))
	     return (0);  /* should never happen */

	if ( (sfp = fopen( srcfile, "r")) == (FILE *) NULL ) {
#ifdef DEBUG
		log_debug( "Can't open: ", srcfile);
		log_debug(  strerror( errno), "srcfile");
		sleep( 30);
#endif
		return (-1);
	}

	if ( (dfp = fopen( destfile, "w")) == (FILE *) NULL ) {
#ifdef DEBUG
		log_debug( "Can't open: ", destfile);
		log_debug(  strerror( errno), "destfile");
#endif
		return (-1);
	}

	while ( (c = getc( sfp)) != EOF )
		putc( c, dfp);

	fclose( sfp);
	fclose( dfp);
	return (0);

}



/*
 * static in mystrncpy( s1, s2, n) is a strncpy() which guarantees a null
 * terminated string in s1.  At most (n-1) chars are copied.
 * Returns -1 if truncation occurred and (n-1) minus number of
 * bytes copied otherwise.
 */

static int
mystrncpy( s1, s2, n)
char	*s1,
	*s2;
int	n;
{
	register char	*cp1,
			*cp2;
	cp1 = s1;
	cp2 = s2;
	n--;

	while ( *cp2 && (n > 0)) {
		n--;
		*cp1++ = *cp2++;
	}
	*cp1 = '\0';
	if ( *cp2 ) {
		return (-1);
	}
	return (n);
}

/*
 * int mystrncat( s1, s2, n) is an strncat() which guarantees a null
 * terminated string in s1.  At most (n-1) chars TOTAL are in the
 * concatenated string.  If the original s1 had more than that
 * it is truncated.
 * Returns -1 if truncation occurred and (n-1) minus number of
 * bytes in new s1 otherwise.
 */

static int
mystrncat( s1, s2, n)
char	*s1,
	*s2;
int	n;
{
	register char	*cp1,
			*cp2;
	cp1 = s1;
	cp2 = s2;
	n--;

	while ( *cp1 && (n > 0)) {
		n--;
		cp1++;
	}
	if ( n == 0 ) {
		if ( *cp1 ) {
			*cp1 = '\0';
			return (-1);
		}
		return (0);
	}

	while ( *cp2 && (n > 0)) {
		n--;
		*cp1++ = *cp2++;
	}
	*cp1 = '\0';
	if ( *cp2 ) {
		return (-1);
	}
	return (n);
}

static void
puth_timeout()
{
	signal( SIGALRM, SIG_DFL);
	put_abort( P_ERRMSG16, NULL);
}


static void
put_abort( msg, msg2)
char 	*msg,
	*msg2;
{
	char buf[MIDLEN];

	printf( "Content-type: text/html\r\nStatus: 500 Failed\r\n\r\n");
	Snprintf2( buf, MIDLEN, "<html>\nFailed:\n%.500s\n %s</html>\n",
		   		msg, strerror( errno));
	if ( msg2 != NULL)
		printf( buf, msg2);
	else
		printf( buf);
#ifdef DEBUG
	log_debug(  msg, msg2);
	log_debug(  strerror( errno), NULL);
#endif
	exit( 2);
}

static void
success( msg, msg2)
char 	*msg,
	*msg2;
{
	char *status;
	char buf[MIDLEN];

	if ( strncmp( msg, "DELETE", 3) == 0 )
		status = "200 OK";
	else
		status = "201 Created";
	printf( "Content-type: text/html\r\nStatus: %s\r\n\r\n", status);
	/*printf( "Location: %s\r\n");*/
	Snprintf1( buf, MIDLEN, "<html>\nSuccess:\n%.500s\n</html>\n", msg);
	if ( msg2 != NULL)
		printf( buf, msg2);
	else
		printf( buf);

}

#ifdef DEBUG
static void
log_debug( msg, msg2)
char	*msg,
	*msg2;
{
	time_t	clock;
	struct tm *ltm;
	char date[TINYLEN];
	FILE	*logfp;


	if ( (logfp = fopen( DEBUG_LOG, "a")) == NULL) {
		fprintf( stderr, "Can't open debug log %s\n", DEBUG_LOG);
		logfp = stderr;
	}

	time(&clock);
	ltm = (struct tm *) localtime(&clock);
	strftime( date, TINYLEN, "[%d/%h/%Y:%T] ", ltm);

	fputs( date, logfp);
	if ( msg2) 
		fprintf( logfp, "%s %s\n", msg, msg2);
	else
		fprintf( logfp, "%s\n", msg);
	fclose( logfp);
}
#endif
