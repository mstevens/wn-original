/*
    Wn: A Server for the HTTP
    File: wn/wn.c
    Version 2.4.5
    
    Copyright (C) 1996-2003  <by John Franks>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 1, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more deatails.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef AIX
#include <sys/select.h>
#endif

#include <sys/signal.h>
#include <sys/socket.h>
#ifndef NO_UNISTD_H
#include <unistd.h>
#endif


#include "wn.h"
#include "version.h"
#include "cgi.h"

#if MAKE_WNSSL
#include "wnssl.h"
#endif


#define INITIAL_TIMEOUT		(30)
#define KEEPALIVE_TIMEOUT	(10)
#define BROWSER_BUGS		(TRUE)
#define AUTHENT_TIMEOUT		(10)
#define KEEPALIVE_MAX		(25)

#define AWAIT_REQUEST		(1)
#define AWAIT_HEADER		(2)
#define AWAIT_TRANSACTION	(3)

extern int	daemon_init();
extern long	atol();
extern void	parse_request(),
		write_debug(),
		start_chunking(),
		end_chunking();

extern time_t	time();

static void	do_post(),
		do_trace(),
		do_options(),
		do_allow_header(),
		do_cookie(),
		get_header(),
		end_headers(),
		wn_timeout(),
		send_keepalive(),
		install_htext(),
		chk_method(),
		remk_postdir(),
		client_closed();

static void	wnssl_setup();

static Methodtype parse_header( );
static char	*get_input();

static int	chk_continue(),
		reset_buf(),
		load_inbuf(),
		wn_getc(),
		get_chunk(),
		mk7bit(),
		etag_match(),
		await_state,
		await_timeout = INITIAL_TIMEOUT;

Request		*this_rp = NULL;

Inheader	*inheadp = NULL;
Outheader	*outheadp = NULL;
Dir_info	*dir_p = NULL;
Connection	*this_conp = NULL;

int		port = 0;

int
main( argc, argv)
int	argc;
char	*argv[];
{
	wn_init( argc, argv);

#if	STANDALONE
	daemon_init();

	signal( SIGQUIT, SIG_IGN);
	signal( SIGINT, SIG_IGN);

	do_standalone();
#else
	get_local_info( fileno( stdin));
	do_connection();
#endif
	return 	( 0);
}


void
do_connection()
{
	char		request[BIGLEN];
	Request		thisreq;
	Outheader	outheader;
	Connection	thiscon;
	Dir_info	thisdir;

	Inbuffer	*readbufp = NULL;

	char		buf[TINYLEN];


	thiscon.keepalive = FALSE;
	thiscon.trans_cnt = 0;
	thiscon.remotehost[0] = thiscon.remaddr[0] = '\0';
	thiscon.rfc931name[0] = thiscon.logbuf[0] = '\0';
	thiscon.pid = getpid();
	if ( readbufp == NULL) {
		if ((readbufp = (Inbuffer *) malloc(sizeof (Inbuffer))) == NULL ) {
			senderr( SERV_ERR, err_m[64], "Inbuffer");
			wn_exit( 2); /* senderr: SERV_ERR */
		}
	}
	readbufp->bcp = NULL;
	readbufp->cur_sz = 0;
	thiscon.bufp = readbufp;
	this_rp = &thisreq;
	if ( inheadp == NULL) {
		if ((inheadp = (Inheader *) malloc(sizeof (Inheader))) == NULL ) {
			senderr( SERV_ERR, err_m[64], "Inheader");
			wn_exit( 2); /* senderr: SERV_ERR */
		}
	}
	outheadp = &outheader;
	this_conp = &thiscon;
	this_conp->out_ptr = this_conp->outbuf;
	this_conp->scheme = "http";
	this_conp->con_status = 0;

	 /* Start a debug entry if debugging enabled. */
	if ( debug_log) {
		write_debug( 0, "\nRequest starting: ", VERSION);
	}

	get_remote_ip( );
	signal( SIGALRM, wn_timeout );
	signal( SIGPIPE, client_closed );

	dir_p = &thisdir;


	if ( MAKE_WNSSL)
		wnssl_setup();
	while ( this_conp->trans_cnt < KEEPALIVE_MAX) {
		this_conp->trans_cnt++;
		request[0] = '\0';
		clear_req( );
		bzero( (char *) inheadp, sizeof( Inheader));
		inheadp->current_htext = inheadp->htext;
		inheadp->ua = wn_empty;
		inheadp->range = wn_empty;
		
		bzero( (char *) outheadp, sizeof( Outheader));
		alarm( await_timeout);
		await_state = AWAIT_REQUEST;
		if ( get_input( request, TRUE, BIGLEN) == NULL ) {
			client_closed(); /* no one there? */
		}

		if ( !*request) {
			/* extra CRLF at end of previous request ? */
			if (this_conp->keepalive == TRUE)
				continue;
			else
				break;
		}

		await_state = AWAIT_HEADER;

		mystrncpy( thisreq.request, request, BIGLEN);

		if ( parse_header( request) == UNKNOWN ) {
			wn_exit( 2); /* parse_header() == UNKNOWN */
		}

		await_state = AWAIT_TRANSACTION;
		await_timeout = KEEPALIVE_TIMEOUT;
		/* await_timeout may have been set for authentication */

		if  ( ! USE_KEEPALIVE)
			this_conp->keepalive = FALSE;
		else if ( BROWSER_BUGS) {
			if ( this_conp->keepalive ) {
				if ( strstr( inheadp->ua, "Mozilla/2.0") ||
				     strstr( inheadp->ua, "MSIE 4.0b") ) {
					this_conp->keepalive = FALSE;
					inheadp->protocol =  HTTP1_0;
				}
			}
		}
		if ( debug_log && this_conp->keepalive) {
			Snprintf2( buf, TINYLEN, 
					"pid = %d, count = %d\n", this_conp->pid,
					this_conp->trans_cnt);
			write_debug( 1, "Keep-Alive: ", buf);
		}

		alarm( TRANSACTION_TIMEOUT);
		process_url(&thisreq, inheadp->url_path);

		if ( this_rp->status & WN_ABORTED)
			wn_exit( 2);  /* WN_ABORTED */

 		if ( !(this_conp->keepalive)) {
			break;
			/* if not keepalive then exit */
		}

		if ( this_conp->more_in_buf )
			continue;
		else
			flush_outbuf();
	}
	wn_exit(0);
}

static void
wn_timeout( )
{
	char	buf[SMALLLEN];

	this_conp->con_status |= WN_CON_TIMEDOUT;
	signal( SIGALRM, SIG_DFL);
	alarm( 20);  	/* Give ourselves 20 seconds to get remote DNS data
			 * and write log entry.
			 */

	if ( await_state != AWAIT_REQUEST) {
		mystrncpy( outheadp->status, "408 Timed Out", SMALLLEN);
		Snprintf2( buf, TINYLEN, "Process %d, await_state (%d) ",
			this_conp->pid, await_state);
		senderr( "408", err_m[60], buf);
	}
	wn_exit( 0);  /* wn_timeout */
}



static void
client_closed( )
{
	if ( debug_log ) {
		char	buf[SMALLLEN];
		fmt3( buf, SMALLLEN, log_m[19], this_conp->pid, await_state);
		write_debug( 1, buf, "");
	}
	if ( await_state != AWAIT_REQUEST) {
		*(this_rp->length) = '\0';
		get_remote_info( );
		writelog( this_rp, log_m[18], (await_state == AWAIT_HEADER 
			? "header" : "transaction"));
	}
	wn_exit( 0);  /* client_closed */
}

void
process_url( ip, url_path)
Request	*ip;
char	*url_path;
{
	Reqtype	itemtype;

	ip->attributes = ip->filetype = ip->status = dir_p->logtype = 0;
	/* These may need clearing if we came from redirect */


	ip->status |= WN_HAS_BODY; /* assume it has a body */
	parse_request( ip, url_path);

	if ( ip->type != RTYPE_FINISHED)
		chk_cntrl( ip);

	itemtype = ip->type;

	if ( (itemtype != RTYPE_DENIED) && (itemtype != RTYPE_NO_AUTH)
				&& (itemtype != RTYPE_NOACCESS)
				&& (itemtype != RTYPE_REDIRECT) 
				&& (itemtype != RTYPE_FINISHED)) {

		switch (inheadp->method) {
		case HEAD:
			chk_method( WN_M_HEAD);
			itemtype = RTYPE_HEAD;
			break;

		case OPTIONS:
			chk_method( WN_M_OPTIONS);
			itemtype = RTYPE_OPTIONS;
			break;

		case GET:
			chk_method( WN_M_GET);
			break;

		case CONDITIONAL_GET:
			inheadp->method = GET;
			chk_method( WN_M_GET);

			if ( ip->attributes & WN_DYNAMIC) {
				break;
			}				

			if ( inheadp->conget & IFNMATCH) {
				if ( etag_match( ))
					itemtype = RTYPE_NOT_MODIFIED;
				break;
			}

			if ( inheadp->conget & IFMATCH) {
				if ( !etag_match( ))
					itemtype = RTYPE_PRECON_FAILED;
				break;
			}

			if ( (inheadp->conget & IFRANGE) && *inheadp->etag) {
				if ( !etag_match( ))
					ip->filetype &= ~(WN_RFC_BYTERANGE
						+ WN_BYTERANGE
						+ WN_LINERANGE);
				break;
			}
			else if ( (inheadp->conget & IFRANGE) && 
				(date_cmp( ip, inheadp->inmod_date, TRUE))) {
				ip->filetype &= ~(WN_RFC_BYTERANGE
						+ WN_BYTERANGE
						+ WN_LINERANGE);
				break;
			}
			if ( (inheadp->conget & IFUNMODSINCE)
				&& date_cmp( ip, inheadp->inmod_date, TRUE)) {
				itemtype = RTYPE_PRECON_FAILED;
				break;
			}

			if ( (inheadp->conget & IFMODSINCE) 
				&& !date_cmp( ip, inheadp->inmod_date, TRUE)) {
				itemtype = RTYPE_NOT_MODIFIED;

			}
			break;

		case POST:
			chk_method( WN_M_POST);
			do_post( inheadp);
			break;
		case PUT:
			chk_method( WN_M_PUT);
			do_post( inheadp);
			break;
		case MOVE:
			chk_method( WN_M_MOVE);
			break;
		case DELETE:
			chk_method( WN_M_DELETE);
			break;
		default:
			break;
		}
	}
	
	switch (itemtype) {
		case RTYPE_FINISHED:
			break;
		case RTYPE_FILE:
			if ( ip->attributes & WN_CGI )
				cgi_env( ip, WN_FULL_CGI_SET);

			if ( ip->filetype & WN_TEXT )
				sendtext( ip);
			else
				sendbin( ip);
			break;
		case RTYPE_MARKLINE:
			if ( ip->attributes & WN_CGI )
				cgi_env( ip, WN_FULL_CGI_SET);

			if ( ip->filetype & WN_TEXT )
				sendtext( ip);
			else
				senderr( DENYSTATUS, err_m[47], ip->filepath);
			break;

		case RTYPE_CGI:
		case RTYPE_NPH_CGI:
		case RTYPE_CGI_HANDLER:
			sendcgi( ip);
			break;
		
		case RTYPE_PUT_HANDLER:
			do_put( ip);
			break;

		case RTYPE_GSEARCH:
		case RTYPE_CONTEXTSEARCH:
		case RTYPE_LINESSEARCH:
			ip->attrib2 |= WN_ISSEARCH;
			sendgrep( ip);
			break;
		case RTYPE_TSEARCH:
		case RTYPE_KSEARCH:
		case RTYPE_TKSEARCH:
		case RTYPE_FIELDSEARCH:
			ip->attrib2 |= WN_ISSEARCH;
			cache_search( ip);
			break;
		case RTYPE_ISEARCH:
			ip->attrib2 |= WN_ISSEARCH;
			if ( ip->attributes & WN_CGI )
				cgi_env( ip, WN_FULL_CGI_SET);
			send_isearch( ip);
			break;
		case RTYPE_LISTSEARCH:
			ip->attrib2 |= WN_ISSEARCH;
			list_search( ip);
			break;
		case RTYPE_IMAGEMAP:
			image( );
			break;
		case RTYPE_INFO:
			sendinfo( ip);
			break;
		case RTYPE_HEAD:
			ip->status &= ~(WN_HAS_BODY);
			http_prolog( );
			writelog( ip, log_m[6], "");
			break;
		case RTYPE_OPTIONS:
			do_options( ip);
			break;
		case RTYPE_REDIRECT:
			sendredirect( ip, "301 Moved Permanently", 
				outheadp->location);
			break;
		case RTYPE_NOT_MODIFIED:
			strcpy( outheadp->status, "304 Not Modified");
			ip->status &= ~(WN_HAS_BODY);
			http_prolog( );
			strcpy( ip->length, "0");
			writelog( ip, log_m[5], "");
			break;

		case RTYPE_NO_AUTH:
			break;

		case RTYPE_PRECON_FAILED:
			senderr( PRECON_FAILED_STATUS, out_m[5], ip->filepath);
			ip->type = RTYPE_FINISHED;
			break;

		case RTYPE_NOACCESS:
			if ( *(dir_p->noaccess_url) && 
				*dir_p->noaccess_url &&
				!streq( ip->relpath, dir_p->noaccess_url)) {
				sendredirect( ip, "301 Moved Permanently", 
					dir_p->noaccess_url);
				break;
			}
			/* Falls through */
		case RTYPE_DENIED:
			if ( 	*dir_p->cantstat_url &&
				!streq( ip->relpath, dir_p->cantstat_url)) {
				sendredirect( ip, "301 Moved Permanently", 
					dir_p->cantstat_url);
				break;
			}
			/* Falls through */

		case RTYPE_UNCHECKED:
		default:
#ifdef DENYHANDLER
			{
				FILE	*fp;
				cgi_env( ip, WN_FULL_CGI_SET);
				if ((fp = WN_popen( DENYHANDLER, "r")) != NULL) {
					ip->attributes |= WN_UNBUFFERED;
					this_conp->keepalive = FALSE;
					fmt3( outheadp->status, SMALLLEN,
						DENYSTATUS, " ", out_m[0]);
					send_out_fd( fileno( fp));
					pclose( fp);
					writelog( this_rp, out_m[0], ip->filepath);
					ip->type = RTYPE_FINISHED;
					ip->status |= WN_ERROR;
					return;
				}
				/*
				 * If handler cannot be run, fall thru
				 * to standard error document.
				 */
			}
#endif
			senderr( DENYSTATUS, out_m[0], ip->filepath);
			ip->type = RTYPE_FINISHED;
	}

	if ( this_conp->chunk_status & WN_USE_CHUNK) {
		/* if chunking end end it */
		end_chunking();
	}


	ip->type = RTYPE_FINISHED;
	return;

	/*
	 * End of process_url()
	 * We come here after every error free transaction 
	 * or to return above or perhaps exit for some parsed docs.
	 */
}


static Methodtype
parse_header( req)
char	*req;
{
	register char	*cp,
			*cp2;

	char		method[SMALLLEN];
	Inheader	*ih;

	ih = inheadp;
	cp = req;
	while ( *cp && !isspace( *cp))
		cp++;
	*cp++ = '\0';
	mystrncpy( method, req, SMALLLEN);
	req = cp;
	while (  *req && isspace( *req))
		req++;
	cp = req;
	while (  *cp && !isspace( *cp))
		cp++;
	if ( *cp ) { /* There's more, check HTTP Version */
		*cp++ = '\0';
		while (  *cp && isspace( *cp))
			cp++;
	}

	if ( !*cp ) {
		ih->protocol =  HTTP0_9;
		this_conp->keepalive = FALSE;
	}
	else if ( strncasecmp( cp, "HTTP/1.", 7) == 0 ) {
		cp2 = cp + 7;
		while (  *cp2 && (isspace( *cp2) || isdigit( *cp2)))
				cp2++;
		if ( *cp2) {
		/* there is garbage after HTTP/1. */
			*cp2 = '\0';
			senderr( "505", err_m[125], cp);
			wn_exit( 2);  /* 505 HTTP version not supported */
		}
		if ( *(cp + 7) == '0' ) {
			ih->protocol =  HTTP1_0;
			this_conp->keepalive = FALSE;
		}
		else  {
			ih->protocol =  HTTP1_1;
			this_conp->keepalive = TRUE;
		}
	}
	else {
		senderr( "505", err_m[125], cp);
		wn_exit( 2);  /* 505 HTTP version not supported */
	}
	mystrncpy( ih->url_path, req, BIGLEN);

	if ( streq( method, "GET")) {
		ih->method = GET;
		if ( ih->protocol != HTTP0_9 ) 
			get_header( ih);
		return	(ih->method);

	}
	if ( streq( method, "POST") ) {
		if (serv_perm & WN_FORBID_EXEC) {
			senderr( "501", err_m[4], "");
			return	(ih->method = UNKNOWN);
		}
		else {
			get_header( ih);
			return	(ih->method = POST);
		}
	}
	if ( streq( method, "PUT") ) {
		if (serv_perm & WN_FORBID_EXEC) {
			senderr( "501", err_m[4], "");
			return	(ih->method = UNKNOWN);
		}
		else {
			get_header( ih);
			return	(ih->method = PUT);
		}
	}
	if ( streq( method, "DELETE") ) {
		if (serv_perm & WN_FORBID_EXEC) {
			senderr( "501", err_m[4], "");
			return	(ih->method = UNKNOWN);
		}
		else {
			get_header( ih);
			return	(ih->method = DELETE);
		}
	}
	if ( streq( method, "MOVE") ) {
		if (serv_perm & WN_FORBID_EXEC) {
			senderr( "501", err_m[4], "");
			return	(ih->method = UNKNOWN);
		}
		else {
			get_header( ih);
			return	(ih->method = MOVE);
		}
	}
	if ( streq( method, "HEAD") ) {
		get_header( ih);
		return	(ih->method = HEAD);
	}

	if ( streq( method, "OPTIONS") ) {
		get_header( ih);
		return	(ih->method = OPTIONS);
	}

	if ( streq( method, "TRACE") ) {
		do_trace();
		return	(ih->method = TRACE);
	}


	senderr( "501", err_m[119], "");
	return	(ih->method = UNKNOWN);
}



static void
do_trace( )
{
	register char	*cp;
	char	headerline[BIGLEN];

	this_conp->keepalive = FALSE;
	this_rp->content_type = "message/http";

	http_prolog();

#if WN_ENABLE_TRACE
	send_text_line( this_rp->request);
	send_text_line( "\r\n");
#else
	send_text_line( err_m[153]);
	send_text_line( "\r\n");
#endif

	while ( get_input( headerline, TRUE, BIGLEN) != NULL) {
		if ( !*headerline) {	/* Blank line, end of headers */
			send_text_line( "\r\n");
			break;
		}
		if ( strncasecmp( headerline, "Host:", 5) == 0 ) {
			cp = headerline + 5;
			while ( isspace( *cp))
				cp++;
			mystrncpy( inheadp->host_head,  cp, SMALLLEN);
		}
#if WN_ENABLE_TRACE
		send_text_line( headerline);
		send_text_line( "\r\n");
#endif
	}

	writelog( this_rp, log_m[21], inheadp->host_head);
	return;
}

static void
get_header( ih)
Inheader	*ih;
{
	register char	*cp;
	char	headerline[BIGLEN];

	while ( get_input( headerline, FALSE, BIGLEN) != NULL) {
		if ( !*headerline)	/* Blank line, end of headers */
			return;

		if ( ! USE_LATIN1)
			mk7bit( headerline);

		if ( strncasecmp( headerline, "Accept:", 7) == 0 ) {
			cp = headerline + 7;
			while ( isspace( *cp))
				cp++;
			if ( *(ih->accept) )
				mystrncat( ih->accept, ", ", ACCEPTLEN);
			if ( mystrncat( ih->accept, cp, ACCEPTLEN) < 0 )
				logerr( err_m[19], "");
			continue;
		}

		if ( strncasecmp( headerline, "Accept-Language:", 16) == 0 ) {
			cp = headerline + 16;
			while ( isspace( *cp))
				cp++;
			if ( *(ih->lang) )
				mystrncat( ih->lang, ", ", ACCEPTLEN/4);
			if ( mystrncat( ih->lang, cp, ACCEPTLEN/4) < 0 )
				logerr( err_m[19], "");
			continue;
		}

		if ( strncasecmp( headerline, "Accept-Charset:", 15) == 0 ) {
			cp = headerline + 15;
			while ( isspace( *cp))
				cp++;
			if ( *(ih->charset) )
				mystrncat( ih->charset, ", ", ACCEPTLEN/4);
			if ( mystrncat( ih->charset, cp, ACCEPTLEN/4) < 0 )
				logerr( err_m[19], "");
			continue;
		}

		if ( strncasecmp( headerline, "Accept-Encoding:", 16) == 0 ) {
			cp = headerline + 16;
			while ( isspace( *cp))
				cp++;
			if ( *(ih->a_encoding) )
				mystrncat( ih->a_encoding, ", ", ACCEPTLEN/4);
			if ( mystrncat( ih->a_encoding, cp, ACCEPTLEN/4) < 0 )
				logerr( err_m[19], "");
			continue;
		}

		if ( strncasecmp( headerline, "TE:", 3) == 0 ) {
			cp = headerline + 3;
			while ( isspace( *cp))
				cp++;
			if ( *(ih->te) )
				mystrncat( ih->te, ", ", ACCEPTLEN/4);
			if ( mystrncat( ih->te, cp, ACCEPTLEN/4) < 0 )
				logerr( err_m[19], "");
			continue;
		}

		if ( strncasecmp( headerline, "Cookie:", 7) == 0 ) {
			cp = headerline + 7;
			while ( isspace( *cp))
				cp++;
			if ( *(ih->cookie) )
				mystrncat( ih->cookie, "; ", ACCEPTLEN);

			if ( mystrncat( ih->cookie, cp, ACCEPTLEN) < 0 )
				logerr( err_m[79], "");
			continue;
		}

		if ( strncasecmp( headerline, "Authorization:", 14) == 0 ) {
			cp = headerline + 14;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->authorization, cp, MIDLEN);
			mystrncpy( ih->auth_url_path, ih->url_path, MIDLEN);
			continue;
		}

		if ( strncasecmp( headerline, "Content-type:", 13) == 0 ) {
			cp = headerline + 13;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->content, cp, SMALLLEN);
		}
		if ( strncasecmp( headerline, "Content-length:", 15) == 0 ) {
			cp = headerline + 15;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->length, cp, SMALLLEN);
			continue;
		}
		if ( strncasecmp( headerline, "Content-encoding:", 17) == 0 ) {
			cp =  headerline + 17;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->encoding, cp, SMALLLEN);
			continue;
		}
		if ( strncasecmp( headerline, "Transfer-encoding:", 18) == 0 ){
			cp =  headerline + 18;
			while ( isspace( *cp))
				cp++;
			strlower( cp);
			if ( streq( cp, "chunked"))
				ih->attrib |= INPUT_CHUNKED;
			continue;
		}
		if ( strncasecmp( headerline, "Host:", 5) == 0 ) {
			cp = headerline + 5;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->host_head,  cp, SMALLLEN);
			continue;
		}
		if ( strncasecmp( headerline, "New-URI:", 8) == 0 ) {
			cp = headerline + 8;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->new_uri_env, "HTTP_NEW_URI=" , MIDLEN/2);
			mystrncat( ih->new_uri_env,  cp, MIDLEN/2);
			ih->new_uri = ih->new_uri_env + sizeof( "HTTP_NEW_URI=");
			continue;
		}
		if ( strncasecmp( headerline, "Referer:", 8) == 0 ) {
			cp = headerline + 8;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->referrer,  cp, MIDLEN);
			continue;
		}
		if ( strncasecmp( headerline, "Connection:", 11) == 0 ) {
			cp = headerline + 11;
			while ( isspace( *cp))
				cp++;
			if ( strncasecmp( cp, "keep-alive", 10) == 0 )
				this_conp->keepalive = TRUE;
			if ( strncasecmp( cp, "close", 5) == 0 )
				this_conp->keepalive = FALSE;
			continue;
		}
		if ( strncasecmp( headerline, "from:", 5) == 0 ) {
			cp = headerline + 5;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->from,  cp, SMALLLEN);
			continue;
		}

		if ( strncasecmp( headerline, "Range:", 6) == 0 ) {
			cp = headerline + 6;
			while ( isspace( *cp))
				cp++;
			install_htext( ih, &(ih->range), cp, RANGELEN );
			continue;
		}

		if ( strncasecmp( headerline, "User-Agent:", 11) == 0 ) {
			cp = headerline + 11;
			while ( isspace( *cp))
				cp++;
			install_htext( ih, &(ih->ua), cp, SMALLLEN );
			continue;
		}

		if ( strncasecmp( headerline, "X-Forwarded-For:", 16) == 0 ) {
			cp = headerline + 16;
			install_htext( ih, &(ih->xforwardedfor), cp, 
					(3*SMALLLEN)/2 );
			continue;
		}

		if ( strncasecmp( headerline, "Via:", 4) == 0 ) {
			cp = headerline + 4;
			install_htext( ih, &(ih->via), cp, (3*SMALLLEN)/2 );
			continue;
		}

		if ( strncasecmp( headerline, "Expect:", 7) == 0 ) {
			cp = headerline + 7;
			while ( isspace( *cp))
				cp++;
			if ( strncasecmp( cp, "100-Continue", 12) == 0 ) {
				send_text_line( HTTPVERSION);
				send_text_line( "100 Continue\r\n\r\n");
				flush_outbuf();
				alarm( KEEPALIVE_TIMEOUT);
			}
			continue;
		}
		if ( strncasecmp( headerline, "If-Modified-Since:", 18) == 0) {
						/* it's a wart */
			if ( ih->method == POST)
				continue;
			cp = headerline + 18;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->inmod_date, cp, SMALLLEN);
			ih->method = CONDITIONAL_GET;
			ih->conget |= IFMODSINCE;
			continue;
		}

		if ( strncasecmp( headerline, "If-Unmodified-Since:", 20)
									== 0) {
						/* another wart */
			if ( ih->method == POST)
				continue;
			cp = headerline + 20;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->inmod_date, cp, SMALLLEN);
			ih->method = CONDITIONAL_GET;
			ih->conget |= IFUNMODSINCE;
			continue;
		}

		if ( strncasecmp( headerline, "If-None-Match:", 14) == 0) {
			if ( ih->method == POST)
				continue;
			cp = headerline + 14;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->etag, cp, SMALLLEN);
			ih->conget |= IFNMATCH;
			ih->method = CONDITIONAL_GET;
			continue;
		}

		if ( strncasecmp( headerline, "If-Match:", 9) == 0) {
			if ( ih->method == POST)
				continue;
			cp = headerline + 9;
			while ( isspace( *cp))
				cp++;
			mystrncpy( ih->etag, cp, SMALLLEN);
			ih->conget |= IFMATCH;
			ih->method = CONDITIONAL_GET;
			continue;
		}

		if ( strncasecmp( headerline, "If-Range:", 9) == 0) {
			if ( ih->method == POST)
				continue;
			cp = headerline + 9;
			while ( isspace( *cp))
				cp++;
			if ( strchr( cp, ':') != NULL )   /* It's a date */
				mystrncpy( ih->inmod_date, cp, SMALLLEN);
			else	/* It's an ETag */
				mystrncpy( ih->etag, cp, SMALLLEN);
			ih->conget |= IFRANGE;
			ih->method = CONDITIONAL_GET;
			continue;
		}
	}
}

/*
 * static void install_htext copies header text into the header text 
 * buffer at inheadp->current_htext and updates this pointer.
 * The address of the text added in put in *paddr.
 */

static void
install_htext( ih, paddr, text, maxlen)
Inheader *ih;
char	**paddr,
	*text;
unsigned maxlen;
{
	register char	*cp1,
			*cp2;

	cp1 = text;
	while ( isspace( *cp1))
		cp1++;

	cp2 = ih->current_htext;
	while ( *cp1 && ( cp2 < (ih->htext + HEADERTEXTLEN))
			&& ( cp2 < (ih->current_htext + maxlen)))
		*cp2++ = *cp1++;

	if ( cp2 < (ih->htext + HEADERTEXTLEN)
			&& ( cp2 < (ih->current_htext + maxlen))) {
		*cp2++ = '\0';
		*paddr = ih->current_htext;
		ih->current_htext = cp2;
	}
	else
		logerr( "header truncated", text);
}

/*
 * static int etag_match( ) returns TRUE if this_rp->etag matches anything in
 * the comma separated list of quoted strings inheap->etag.  Otherwise
 * returns FALSE.
 */

static int /*bool*/
etag_match( )
{
	register char	*cp,
			*cp2,
			*cp3;

	cp2 = cp = inheadp->etag;
	while ( (cp = strchr( cp2, ',')) != NULL) {
		*cp++ = '\0';
		while ( isspace( *cp2)) /* skip leading LWS */
			cp2++;

		if ( *cp2 == '"')	/* skip leading quote */
			cp2++;
		if ( (cp3 = strchr( cp2, '"')) != NULL)
			*cp3 = '\0';	/* stop before ending quote */
		if ( streq( this_rp->etag, cp2))
			return TRUE;

		cp2 = cp;
	}
	while ( isspace( *cp2)) /* skip leading LWS */
		cp2++;

	if ( streq( cp2, "*"))
		return TRUE;

	if ( *cp2 == '"')	/* skip leading quote */
		cp2++;
	if ( (cp3 = strchr( cp2, '"')) != NULL)
		*cp3 = '\0';	/* stop before ending quote */
	if ( streq( this_rp->etag, cp2))
		return TRUE;
	else
		return FALSE;
}

static void
do_post( ih)
Inheader	*ih;
{
	static int	num = 0;
#if (! FORBID_CGI)
	long	len;
	char	*cp = NULL;
	int	n,
		c,
		error = 0;

	FILE	*fp;

	if ( ! STANDALONE)
		umask( 077);

	if ( POST_NO_KEEPALIVE)
		this_rp->attributes &= WN_NOKEEPALIVE;

	if (inheadp->method == PUT) 
		cp = "HTTP_PUT_FILE=";
	else if (inheadp->method == POST) 
		cp = "HTTP_POST_FILE=";
	else {
		senderr( SERV_ERR, err_m[53], "");
		wn_exit( 2); /* senderr: SERV_ERR */
	}

	mystrncpy( inheadp->tmpfile_env, cp, 20);
	cp = inheadp->tmpfile_env;
	while (*cp)
		cp++;

	inheadp->tmpfile_name = cp;
	Snprintf4( inheadp->tmpfile_name, SMALLLEN - 20, 
			"%.150s/WNpost-%lx-%x-%x", wn_tmpdir, time( NULL),
		   		this_conp->pid, num++);

	putenv( inheadp->tmpfile_env);

	len = 0;
	if ( (fp = fopen( ih->tmpfile_name, "w")) == (FILE *) NULL ) {
		remk_postdir();
		if ( (fp = fopen( ih->tmpfile_name, "w")) == (FILE *) NULL ) {
			senderr( SERV_ERR, err_m[53], ih->tmpfile_name);
			wn_exit( 2); /* senderr: SERV_ERR */
		}
	}

	/* Timeout after TRANSACTION_TIMEOUT seconds */
	alarm( TRANSACTION_TIMEOUT);

	if ( ih->attrib & INPUT_CHUNKED ) {
		while ( (n = get_chunk( fp))) {
			len += n;
			if ( len > MAX_POST_LEN) {
				senderr( REQ_TOO_LONG_STATUS, err_m[126], "");
				wn_exit( 2); /* senderr: REQ_TOO_LONG_STATUS */
			}
		}
		Snprintf1( ih->length, TINYLEN, "%ld", len);
	}
	else if ( *ih->length) {
		len = atol( ih->length);
		if ( len > MAX_POST_LEN) {
			senderr( REQ_TOO_LONG_STATUS, err_m[126], "");
			wn_exit( 2); /* senderr: 413 REQ_TOO_LONG_STATUS */
		}

		while ( (len > 0) && (c = wn_getc( )) != EOF) {
			len--;
			putc( c, fp);
		}

		if ( len < 0 )
			error++;
	}
	else {
		error++;
	}

	if ( error) {
		senderr( CLIENT_ERR, err_m[57], "");
		wn_exit( 2);  /* senderr: CLIENT_ERR */
	}

	if ( len > MAX_POST_LEN) {
		senderr( "413", err_m[74], "");
		wn_exit( 2);  /* senderr: 413 */
	}
	fclose( fp);
#endif /* (! FORBID_CGI) */

}

static void
remk_postdir( )
{
#if (! FORBID_CGI)
	struct stat	stat_buf;
	uid_t		my_id;

	my_id = getuid();
	if ( lstat( wn_tmpdir, &stat_buf) == -1) {
		if ( (errno != ENOENT) || (mkdir( wn_tmpdir, 0711) != 0) ) {
			senderr( SERV_ERR,  err_m[122], wn_tmpdir);
			wn_exit( 2);  /* senderr: SERV_ERR */
		}
	}
	else if ( (!S_ISDIR(stat_buf.st_mode))
				|| (stat_buf.st_uid != my_id)
				|| (chmod( wn_tmpdir, 0711) != 0) ) {
		senderr( SERV_ERR,  err_m[122], wn_tmpdir);
		wn_exit( 2);  /* senderr: SERV_ERR */
	}
#endif /* (! FORBID_CGI) */
}

static int
get_chunk( fp)
FILE	*fp;
{
	int	c,
		n,
		error = 0;

	long	len = -1;

	char	buf[TINYLEN],
		trailer[BIGLEN];

	buf[TINYLEN - 1] = '\0';
	for ( n = 0; n < TINYLEN - 1; n++) {
		c = wn_getc( );
		if ( (c  == EOF)) {
			error++;
			break;
		}
		if ( c == '\r') {
			if ( (c = wn_getc( )) != '\n') {
				error++;
				break;
			}
			buf[n] = '\0';
			break;
		}
		buf[n] = (char) c;
	}

 	if ( !error)
 		sscanf( buf, "%lx", &len);

	if ( (len > MAX_POST_LEN) || (len < 0)) {
		senderr( "413", err_m[74], "");
		wn_exit( 2);  /* senderr: 413 */
	}

	n = len;

	while ( (n > 0) && (c = wn_getc( )) != EOF) {
		n--;
		putc( c, fp);
	}


	if ( len == 0 ) {	/* get any trailer lines */
		while ( get_input( trailer, FALSE, BIGLEN) != NULL) {
			if ( !*trailer)/* Blank line, end of headers */
				break;
			if ( ! USE_LATIN1)
				mk7bit( trailer);
		}
	}
	else {
		if ( (c = wn_getc( )) != '\r')
			error++;
		if ( (c = wn_getc( )) != '\n')
			error++;
	}
	if ( error || (len < 0)) {
		senderr( CLIENT_ERR, err_m[118], "");
		wn_exit( 2);  /* senderr: 400 */
	}
	return len;
}


static int
wn_getc()
{
	int		n,
			c;

	Inbuffer	*bp;

	bp = this_conp->bufp;

	if ( bp->bcp >= bp->buffer + bp->cur_sz) {
		n = load_inbuf( bp);
		if ( n <= 0 )
			return EOF;
	}
	c = (unsigned char) *(bp->bcp);
	(bp->bcp)++;
	return c;
}


/*
 * static char *get_input()
 * Returns NULL if no input (client quit), otherwise places next line
 * of input in "line" and returns "line".  Any CRLF are removed.
 * Thus *line == '\0' indicates end of headers. 
 *
 * The function get_input() reads lines from a buffer thiscon.bufp.
 * If the buffer is empty or does not contain a complete line it reloads
 * it.  It looks ahead to see if the line continues (i.e. next line starts
 * with white space.  The lookahead is only done for header lines
 * (no_continuation = FALSE) not for the request line.
 * The maximum size of line is 'maxsize' and no more than that will
 * be put in line.  Attempted overflows generate an error.
 */

static char *
get_input( line, no_continuation, maxsize)
char	*line;
int	no_continuation,
	maxsize;
{
	int	llen = 0,
		n = 0;
	Inbuffer	*bp;

	register char	*cp;

	bp = this_conp->bufp;
	if ( bp->bcp == NULL)
		bp->bcp = bp->buffer;

	*line = '\0';

	while ( TRUE) {
		if ( reset_buf( bp) == FALSE ) {  /* buffer is empty */
			n = load_inbuf( bp);
			if ( n <= 0) {
				if ( debug_log) {
					char	tmpbuf[SMALLLEN];
					Snprintf2( tmpbuf, SMALLLEN, log_m[20],
							this_conp->pid, n);
					write_debug(1, tmpbuf, "");
				}
				return NULL;
			}
		}

		if ( ( cp = strchr( bp->bcp, '\n')) == NULL) {
			/* an incomplete header has been read */
			/* put what there is into line */
			bp->buffer[bp->cur_sz] = '\0';
			mystrncat( line, bp->bcp, maxsize);
			llen = strlen( line);

			cp = bp->bcp;
			while ( *cp)
				cp++;

			if ( (cp < &(bp->buffer)[bp->cur_sz])
							&& (cp > bp->bcp) ) {
				bp->bcp = ++cp;
			}
			else {
				bp->cur_sz = 0;
				bp->bcp = bp->buffer;
				bp->buffer[0] ='\0';
			}
			/* then read more */

			n = load_inbuf( bp);
			if ( n <= 0 ) {
				senderr( CLIENT_ERR, err_m[66], line); 
				wn_exit( 2); /* senderr: CLIENT_ERR */
			}
			continue;
		}
		
		/* cp now points to next NL in the in_bufer */
		*cp++ = '\0';


		mystrncat( line, bp->bcp, maxsize);

		llen = mk7bit( line);

		if ( llen >= maxsize - 3 ) {
			senderr( URI_TOO_LONG_STATUS, err_m[124], line); 
			wn_exit( 2); /* senderr: 414 URI too long */
		}

		if ( (llen > 0) && (line[llen-1] == '\r'))
			line[--llen] = '\0';

		bp->bcp = cp;

		this_conp->more_in_buf = reset_buf(bp);

		if ( debug_log)
			write_debug(1, " -> ", line);

		if ( (!*line) || no_continuation) {
			return ( line);
			/* Don't allow continuation for request line */
		}


		if ( ! chk_continue( bp) ) 
			break; /* We're done with this line */
			/* otherwise its a continuation line */
	}
	return ( line);
}


static int
mk7bit( str)
char	*str;
{
	int len = 0;
	while ( *str ) {
		len++;
		if ( ! USE_LATIN1)
			*str++ &= 0x7f;
	}
	return len;
}


/*
 * static int load_inbuf( bp)
 * Load and adjust input buffer.
 */

static int
load_inbuf( bp)
Inbuffer	*bp;
{
		char	*base;
		int	n = 0,
			size;

		register char	*cp;

		size = bp->cur_sz;
		base = &(bp->buffer)[0];
		cp = bp->bcp;

		if (cp > base) {
			size = ( base + size - cp);
			size = ( size < 0 ? 0 : size);
			mymemcpy( base, cp, size);
			bp->bcp = cp = base;
			bp->cur_sz = size;
		}

		n = WN_read( (fileno( stdin)), (base + size), 
				((INBUFFSIZE - 4) - size));

		if ( n > 0 ) {
			size += n;
			bp->cur_sz = size;
			*(base + size) = '\0';
		}
		else if ( size <= 0) {
			bp->cur_sz = 0;
			bp->bcp = bp->buffer;
			*base ='\0';
		}

		return n;
}

	
/*
 * static int chk_continue( bp)
 * Check if input line continues (next line starts with whitespace.
 * If buffer is empty, reinitialize it.
 */

static int
chk_continue( bp)
Inbuffer	*bp;
{
	char	c;
	int	n;

	if ( bp->cur_sz == 0) {
		n = load_inbuf( bp);
		if ( n <= 0) {
			return FALSE;
		}
	}	
	c = *(bp->bcp);
	if ( ( c != ' ') && (c != '\t'))
		return FALSE;
	else
		return TRUE;
}


/*
 * static void reset_buf( bp)
 * Check if buffer is empty and reset it.
 * Return FALSE if empty and TRUE otherwise.
 */

static int
reset_buf( bp)
Inbuffer	*bp;
{
	if ( bp->bcp - bp->buffer >= bp->cur_sz) {
		/* it's empty */
		bp->bcp = bp->buffer;
		*(bp->bcp) = '\0';
		bp->cur_sz = 0;
		return FALSE;
	}
	else
		return TRUE;  /* it's not empty yet */

}


void
clear_req( )
{
	bzero( (char *) this_rp, sizeof( Request));
	bzero( (char *) dir_p, sizeof( Dir_info));
	this_rp->do_wrap_1st_time = TRUE;
}

/*
 * http_prolog() sends the HTTP headers (or does nothing for HTTP/0.9)
 * If it has already been called for this request it returns FALSE
 * and does nothing.  If it has not been called it returns TRUE after
 * writing appropriate headers to stdout.
 */

int
http_prolog( )
{

	struct tm	*gmt;
	time_t		clock,
			clock2;
	Request		*ip;
	char		buf[CACHELINE_LEN],
			mod_date[SMALLLEN],	
					/* Last-Modified HTTP header line */
			datebuf[2*TINYLEN];
	unsigned	unbuffered;


	ip = this_rp;
	if ( ip->status & WN_PROLOGSENT )
		return FALSE;

	ip->status |= WN_PROLOGSENT;
	unbuffered = ip->attributes & WN_UNBUFFERED;
	ip->attributes &= ~(WN_UNBUFFERED);  /* always buffer HTTP headers */

	if ( strncmp( outheadp->status, "505", 3) == 0)
		inheadp->protocol =  HTTP1_0;

	if ( inheadp->protocol ==  HTTP0_9) {
		ip->attributes |= unbuffered;
		return TRUE;
	}

	send_text_line( HTTPVERSION);
	if ( *outheadp->status) {
		send_text_line(  outheadp->status);
		send_text_line(  "\r\n");
	}
	else {
		send_text_line( "200 OK\r\n");
	}
	fmt3( buf, SMALLLEN, "Server: ", VERSION, "\r\n");
	send_text_line( buf);

		/* Find date and serve the HTTP Date header */
	time(&clock);
	gmt = gmtime(&clock);
	strftime( datebuf, SMALLLEN, 
			"Date: %a, %d %h %Y %T GMT\r\n", gmt);
	send_text_line( datebuf);
	if ( strncmp( outheadp->status, "204", 3) == 0 ) {
		/* 204 No Response (null action) */
		end_headers();
		return TRUE;
	}

	if  ((ip->attrib2 & (WN_ISSEARCH + WN_FILEMOD)) ||
			(ip->attributes & 
			(WN_CGI + WN_PARSE + WN_FILTERED + WN_DYNAMIC))) {
		/* If any of these hold we don't really know the length */
		*ip->length = *outheadp->md5 = '\0';
	}

	if ( strncmp( outheadp->status, "401", 3) == 0 ) {
		send_text_line( outheadp->list);
		send_keepalive();
		await_timeout = AUTHENT_TIMEOUT;

		if ( !*ip->length )
			mystrncpy( ip->length, "0", TINYLEN);
		fmt3( buf, SMALLLEN, "Content-length: ", ip->length, "\r\n");
		send_text_line( buf);
		end_headers();
		return TRUE;
	}

	if ( *outheadp->location) {
		if ( outheadp->ohstat & OHSTAT_ISREDIR)
			send_text_line( "Location: ");
		else
			send_text_line( "Content-Location: ");
		send_text_line( outheadp->location);
		send_text_line( "\r\n");
	}

	if ( outheadp->ohstat & OHSTAT_ISREDIR) {
		fmt3( buf, SMALLLEN, "Content-type: ", 
				BUILTIN_CONTENT_TYPE, "\r\n");
		send_text_line( buf);

		if ( !*ip->length ) {
			fmt3( buf, SMALLLEN, "Content-length: ", 
			      ip->length, "\r\n");
			send_text_line( buf);
		}
		else {
			this_conp->keepalive = FALSE;
		}
		send_keepalive();
		if ( *(outheadp->list))
			send_text_line( outheadp->list);
		end_headers();
		return TRUE;
	}

	if ( *outheadp->allow)
		send_text_line( outheadp->allow);

	if ( ip->attributes & WN_DYNAMIC) {
		ip->mod_time = (time_t) 0;
	}

	if ( ip->attributes & WN_NOCACHE) {
		send_text_line( "Pragma: no-cache\r\n");
		if ( inheadp->protocol ==  HTTP1_1)
			send_text_line( "Cache-control: no-cache\r\n");
	}
	if ( ip->mod_time) {
		gmt = gmtime(&ip->mod_time);
		strftime( mod_date, SMALLLEN,
				"Last-Modified: %a, %d %h %Y %T GMT\r\n", gmt);
		send_text_line( mod_date);

		/* No ETag for filtered, parsed, or info documents */

		if ( ip->filetype & (WN_BYTERANGE + WN_LINERANGE))
			; /* do nothing */
		else if ( ip->attributes & (WN_FILTERED + WN_PARSE))
			; /* do nothing */
		else if ( (ip->type == RTYPE_INFO) || !*ip->length )
			; /* do nothing */
		else if ((clock - ip->mod_time) > 2 )  {
			fmt3( buf, SMALLLEN, "ETag: \"", ip->etag, "\"\r\n");
			send_text_line( buf);
		}
	}

	if ( ip->maxage && *ip->maxage) {
		long	delta;

		if ( *ip->maxage == 'L') {
			ip->maxage++;
			clock2 = ip->mod_time + atol( ip->maxage);
			delta = clock2 - clock;

			if ( delta > 0) {
				Snprintf1( buf, SMALLLEN, 
					"Cache-Control: max-age=%ld\r\n", delta);
				send_text_line( buf);
			}
		}
		else {
			clock2 = clock + atol( ip->maxage);
			fmt3( buf, SMALLLEN, "Cache-Control: max-age=",
			      ip->maxage, "\r\n");
			send_text_line( buf);
		}
	}

	if ( ip->expires && *ip->expires) {
		fmt3( buf, SMALLLEN, "Expires: ", ip->expires, "\r\n");
		send_text_line( buf);
	}
	else if ( *outheadp->expires) {
		send_text_line( outheadp->expires);
	}
	else if ( ip->maxage && *ip->maxage) {
		gmt = gmtime(&clock2);
		strftime( datebuf, SMALLLEN, 
			"Expires: %a, %d %h %Y %T GMT\r\n", gmt);
		send_text_line( datebuf);
	}

	if ( inheadp->method == CONDITIONAL_GET) {
		/* It's not modified */
		send_keepalive();
		end_headers();
		return TRUE;
	}

	if ( ip->content_type) {
		fmt3( buf, SMALLLEN, "Content-type: ",
		      ip->content_type, "\r\n");
		send_text_line( buf);
	}

	if ( *outheadp->md5 && *ip->length && (!*outheadp->range) ) {
		if ( dir_p->cmod_time <= ip->mod_time ) {
			*outheadp->md5 = '\0';
			logerr( err_m[123], ip->cachepath);
		}
		else
			send_text_line( outheadp->md5);
	}

	if ( ip->filetype & WN_RFC_BYTERANGE) {
		fmt3( buf, SMALLLEN, "ETag: \"", ip->etag, "\"\r\n");
		send_text_line( buf);
		send_text_line( "Accept-Ranges: bytes\r\n"); 
	}

	if  ( (inheadp->method == HEAD) && *ip->length ) {
		send_text_line( "Accept-Ranges: bytes\r\n"); 
		fmt3( buf, SMALLLEN, "Content-length: ",
		      ip->length, "\r\n");
		send_text_line( buf);
	}
	else if ( (ip->status & WN_HAS_BODY) ) {
		if ( !*ip->length ) {		/* chunk if HTTP/1.1 */
			if (inheadp->protocol ==  HTTP1_0) {
				this_conp->keepalive = FALSE;
				/* can't chunk so close connection */
			}
			else if ( !(ip->filetype & WN_RFC_BYTERANGE)) {
				send_text_line(
					"Transfer-Encoding: chunked\r\n");
				this_conp->chunk_status |= WN_USE_CHUNK;
			}

		}
		else {	/* not dynamic and has length */
			fmt3( buf, SMALLLEN, "Content-length: ",
			      ip->length, "\r\n");
			send_text_line( buf);
			if ( *outheadp->range ) {
				send_text_line( "Content-Range: bytes ");
				send_text_line( outheadp->range);
				send_text_line( "\r\n");
			}

			if ( !(ip->filetype & WN_BYTERANGE)
					&& !*(outheadp->status)) {
				/* !*(outheadp->status) means status 200 */
				send_text_line( "Accept-Ranges: bytes\r\n"); 
			}

		}
	}

	send_keepalive();
			
	if ( ip->encoding && *ip->encoding) {
		fmt3( buf, MIDLEN, "Content-encoding: ", ip->encoding, "\r\n");
		send_text_line( buf);
	}

#ifdef USE_TITLE_KEYWORD_HEADERS
	if ( ip->title && *ip->title) {
		fmt3( buf, CACHELINE_LEN, "Content-description: ", ip->title,
		      "\r\n");
		/* formerly Title: */
		send_text_line( buf);
	}

	if ( ip->keywords && *ip->keywords) {
		fmt3( buf, CACHELINE_LEN, "Keywords: ", ip-keywords, "\r\n");
		send_text_line( buf);
	}
#endif
	if ( dir_p->dir_owner && *dir_p->dir_owner) {
		fmt3( buf, SMALLLEN, "Link: <",	dir_p->dir_owner, 
		      ">; rev=\"Made\"\r\n");
		send_text_line( buf);
	}

	if ( ip->cookie && *ip->cookie ) {
		send_text_line( "Set-Cookie: ");
		if ( *ip->cookie != '!') {
			send_text_line( ip->cookie);
		}
		else {
			do_cookie( ip->cookie);
		}
		send_text_line( "\r\n");

	}

	if ( *outheadp->list ) {
		send_text_line( outheadp->list);
	}

	ip->attributes |= unbuffered;

	end_headers();
	return TRUE;
}


static void
end_headers()
{
	send_text_line( "\r\n");
	if ( this_conp->chunk_status & WN_USE_CHUNK)
		this_conp->chunk_status |= WN_START_CHUNK;
		/* start chunking */
}

static void
send_keepalive()
{

	if ( (this_conp->keepalive) && (inheadp->protocol ==  HTTP1_0) )
		send_text_line( "Connection: Keep-Alive\r\n");

	if ( (!this_conp->keepalive) && (inheadp->protocol ==  HTTP1_1))
		send_text_line( "Connection: close\r\n");

}


static void
chk_method( allow)
unsigned	allow;
{


	/* allow must be WN_M_* */
	if ( this_rp->allowed & allow ) {
		if ( allow & (WN_M_PUT + WN_M_MOVE + WN_M_DELETE) ) {
			if ( !*(dir_p->pauthmod)) {
				logerr( err_m[131], "");
				senderr( DENYSTATUS, err_m[127], "");
				wn_exit( 2);  /* auth required for PUT etc */
			}
			else if ( (serv_perm & WN_PERMIT_PUT) && *(this_rp->phandler))
				return;
			else
				logerr( err_m[132], "");
		}
		else 
			return;	
	}
	do_allow_header( );
	senderr( "405", err_m[117], "");
	wn_exit( 2);  /* senderr: 405 method not allowed */
}

static void
do_options( ip)
Request	*ip;
{
	do_allow_header( );
	mystrncpy( outheadp->list, "Content-length: 0\r\n", 30);

	ip->status &= ~(WN_HAS_BODY);
	http_prolog( );
	writelog( ip, log_m[22], "");
}


static void
do_cookie( cookie_prog)
char *cookie_prog;
{
	char	buf[MIDLEN],
		linebuf[MIDLEN];

	FILE	*fp;

	/* We should always have  *cookie_prog == '!' */
	cookie_prog++;
	getfpath( buf, cookie_prog, this_rp);

	if ((fp = WN_popen( buf, "r")) == NULL) {
		logerr( err_m[137], buf);
		this_rp->cookie = wn_empty;
		return;
	}
	while ( fgets( linebuf, MIDLEN, fp)) {
		chop( linebuf);
		send_text_line( linebuf);
	}
}

static void
do_allow_header( )
{
	if ( FORBID_CGI)
		this_rp->allowed &= ~(WN_M_PUT + WN_M_POST + WN_M_DELETE + WN_M_MOVE);
	else if (serv_perm & WN_FORBID_EXEC)
		this_rp->allowed &= ~(WN_M_PUT + WN_M_POST + WN_M_DELETE + WN_M_MOVE);

	if ( !(serv_perm & WN_PERMIT_PUT))
		this_rp->allowed &= ~(WN_M_PUT + WN_M_DELETE + WN_M_MOVE);

	mystrncat( outheadp->allow, "Allow: TRACE", SMALLLEN); 

	if ( this_rp->allowed & WN_M_HEAD)
		mystrncat(outheadp->allow, ", HEAD", SMALLLEN); 
	if ( this_rp->allowed & WN_M_GET)
		mystrncat(outheadp->allow, ", GET", SMALLLEN); 
	if ( this_rp->allowed & WN_M_POST)
		mystrncat(outheadp->allow, ", POST", SMALLLEN); 
	if ( this_rp->allowed & WN_M_OPTIONS)
		mystrncat(outheadp->allow, ", OPTIONS", SMALLLEN); 
	if ( this_rp->allowed & WN_M_PUT)
		mystrncat(outheadp->allow, ", PUT", SMALLLEN); 
	if ( this_rp->allowed & WN_M_DELETE)
		mystrncat(outheadp->allow, ", DELETE", SMALLLEN); 
	if ( this_rp->allowed & WN_M_MOVE)
		mystrncat(outheadp->allow, ", MOVE", SMALLLEN); 
	mystrncat( outheadp->allow, "\r\n", SMALLLEN);
}


static void wnssl_setup()
{
#if MAKE_WNSSL
	X509 *cert;

	ssl_con=(SSL *)SSL_new(ssl_ctx);
	SSL_set_fd(ssl_con,fileno(stdout));

	if (SSL_use_RSAPrivateKey( ssl_con, ssl_private_key) == 0)  {
		daemon_logerr( err_m[140], "", errno);
		wn_exit( 2);
	}

	if (SSL_use_certificate( ssl_con, ssl_public_cert) == 0) {
		daemon_logerr( err_m[141],"", errno);
		wn_exit( 2);
	}

	SSL_set_verify( ssl_con,ssl_verify_flag, NULL);

	if ( SSL_accept( ssl_con) <= 0 )  {
		int xerr = 0;
		char errbuf[MIDLEN];

		while ( (xerr = ERR_get_error())) {
			ERR_error_string( xerr, errbuf);
			logerr ( err_m[28], errbuf);
		}
		sleep(1);
		wn_exit( 2);
	}

	if ( WNSSL_ENVIRON) {
		fmt2( env_cipher, 2*SMALLLEN, "CC_CIPHER=", SSL_get_cipher(ssl_con));
		putenv (env_cipher);
		ssl_buf[0] = '\0';
		if ( (cert = SSL_get_peer_certificate( ssl_con))) {
			X509_NAME_oneline( X509_get_subject_name(cert), ssl_buf, 220);
			fmt2( env_subject, 2*SMALLLEN, "CC_SUBJECT=", ssl_buf);
			putenv(env_subject);
			X509_NAME_oneline( X509_get_issuer_name(cert), ssl_buf, 220);
			fmt2( env_issuer, 2*SMALLLEN, "CC_ISSUER=", ssl_buf);
			putenv(env_issuer);
			X509_free (cert);
		}
	}

	if ( WNSSL_DEBUG) {
		FILE *errfp;

		errfp = fopen("/tmp/sslerror", "a+");
		fprintf( errfp, "%s\n", env_subject );
		fprintf( errfp, "%s\n", env_issuer );
		fclose( errfp );
	}
	this_conp->scheme = "https";
#endif
}


#if MAKE_WNSSL 

int
WN_read( a, b, c)
int     a;
char    *b;
int     c;
{
       if ( is_ssl_fd( ssl_con, (fileno(stdin))))
	       return (SSL_read( ssl_con, b, c));
       else
	       return (-1);
}


int
WN_write( a, b, c)
int     a;
char    *b;
int     c;
{
        if ( is_ssl_fd( ssl_con, a))
                return (SSL_write( ssl_con, b, c));
        else {
		logerr( err_m[75], "wnssl WN_write");
		return (-1);
	}
}
#endif /* MAKE_WNSSL */



