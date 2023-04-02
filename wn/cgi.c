/*
    Wn: A Server for the HTTP
    File: wn/cgi.c
    Version 2.4.4
    
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


#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "wn.h"
#include "version.h"
#include "cgi.h"

#ifdef RFC931_TIMEOUT
extern void	get_rfc931();
#endif

static void	full_cgi_env(),
		pathinfo_env(),
		cgi_headers();

static CGI_data	*cgip = NULL;

static CGI_con_data	*cgiconp = NULL;

/*
 * sendcgi( ip)  Open pipe from "ip->filepath" command
 * and send output using CGI standards
 */

void
sendcgi( ip)
Request	*ip;
{
#if (! FORBID_CGI)
	FILE	*fp;

	int		fdfp,
			buflen;

	char	command[MIDLEN],
		location[MIDLEN],
		cgibuf[OUT_BUFFSIZE + 4],
		buf[BIGLEN],
		*bufptr;


	exec_ok( ip);

	location[0] = '\0';
	*ip->length = '\0';  /* Don't send length of script!! */

	if ( ip->type == RTYPE_CGI_HANDLER) {
		if ( (inheadp->method != GET) && (inheadp->method != POST) ) {
			senderr( SERV_ERR, err_m[117], ip->filepath);
			return;
		}
		mystrncpy( ip->pathinfo, ip->relpath, MIDLEN);
		getfpath( buf, ip->handler, ip);
		mystrncpy( command, buf, MIDLEN);
	}
	else { /* RTYPE_CGI or RTYPE_NPH_CGI */
		if ( ip->filetype & WN_DIR ) {
			senderr( SERV_ERR, err_m[55], ip->filepath);
			return;
		}
		mystrncpy( command, ip->filepath, MIDLEN);
	}
	mystrncpy( buf, ip->filepath, MIDLEN);

	if ( ip->attributes & WN_FILTERED) {
		senderr( SERV_ERR, err_m[52], ip->filepath);
		return;
	}

	if ( ! WN_SU_EXEC) {
		char *cp;

		if ( (cp = strrchr( buf, '/')) != NULL)
			*cp = '\0';

		if ( chdir( buf) != 0  ) {
			logerr( err_m[106], buf);
		}
	}

	cgi_env( ip, WN_FULL_CGI_SET);  /* Full CGI environment */

	if ( (inheadp->method == POST) 	&& (inheadp->tmpfile_name) 
				&& (*inheadp->tmpfile_name != '\0')) {
		mystrncat( command, " < ", MIDLEN);
		mystrncat( command, inheadp->tmpfile_name, MIDLEN);
	}

	if ( !*ip->query || (strchr( ip->query, '=') != NULL)
	     		|| ( ip->type == RTYPE_CGI_HANDLER) 
	     		|| ( (inheadp->method != GET) &&
			     (inheadp->method != POST)) ) {
		/* '=' in query so don't use on command line */
		if ((fp = WN_popen( command, "r")) == (FILE *) NULL ) {
			senderr( SERV_ERR, err_m[55], command);
			return;
		}
	} else { /* no '=' means its an isindex, ugh!  */
		www_unescape( ip->query, ' ');
		if ( (fp = safer_popen( command, ip->query))
					== (FILE *) NULL )
			if ( (fp = WN_popen( command, "r")) 
						== (FILE *) NULL ) {
				senderr( SERV_ERR, err_m[55], command);
				return;
			}
	}

	fdfp = fileno( fp);

	if ( ip->type == RTYPE_NPH_CGI) {  /* CGI handles headers */
		ip->attributes |= WN_UNBUFFERED;  /* Don't buffer CGI */
		this_conp->keepalive = FALSE;

		send_out_fd( fdfp);

		pclose( fp);
		writelog( ip, log_m[7], ip->filepath);
		if ( inheadp->tmpfile_name && *inheadp->tmpfile_name) {
			unlink( inheadp->tmpfile_name);
			*inheadp->tmpfile_name = '\0';
		}
		return; /* to end of process_url */
	}

	/* It's a standard CGI, not an nph-CGI.  We do headers */
	cgi_headers( fp, cgibuf, location, &bufptr, &buflen);
	if ( ip->status & WN_ERROR)
		return;


	if ( !*location) {

		http_prolog( );
		ip->attributes |= WN_UNBUFFERED;  /* Don't buffer CGI */
		send_out_mem( bufptr, buflen);
		send_out_fd( fdfp);

		pclose( fp);
		writelog( ip, log_m[8], ip->filepath);
		if ( inheadp->tmpfile_name && *inheadp->tmpfile_name) {
			unlink( inheadp->tmpfile_name);
			*inheadp->tmpfile_name = '\0';
		}
		return;  /* to end of process_url */
	}
	else {
		writelog( ip, log_m[9], location);
		fmt2( ip->request, MIDLEN, log_m[12], location);
		dolocation( location, ip, 302); /* should be 303 */
		pclose( fp);
		if ( inheadp->tmpfile_name && *inheadp->tmpfile_name) {
			unlink( inheadp->tmpfile_name);
			*inheadp->tmpfile_name = '\0';
		}
		return; /* to end of process_url */
	}
#endif /* (! FORBID_CGI) */
}

/*
 * do_put( ip)  Invoke put handler to handle PUT, DELETE, MOVE
 */

void
do_put( ip)
Request	*ip;
{
#if (! FORBID_CGI)
	FILE	*fp;

	int		fdfp,
			result,
			buflen;

	char	command[MIDLEN],
		location[MIDLEN],
		cgibuf[OUT_BUFFSIZE + 4],
		buf[BIGLEN],
		*methstr,
		*success,
		*bufptr;


	exec_ok( ip);

	location[0] = '\0';
	*ip->length = '\0';  /* Don't send length of script!! */

	mystrncpy( ip->pathinfo, ip->relpath, MIDLEN);
	getfpath( buf, ip->phandler, ip);
	mystrncpy( command, buf, MIDLEN);

	mystrncpy( buf, ip->filepath, MIDLEN);

	if ( ! WN_SU_EXEC) {
		char *cp;

		if ( (cp = strrchr( buf, '/')) != NULL)
			*cp = '\0';

		if ( chdir( buf) != 0  ) {
			logerr( err_m[106], buf);
		}
	}

	cgi_env( ip, WN_FULL_CGI_SET);  /* Full CGI environment */

	if ( inheadp->new_uri && *inheadp->new_uri) {
		putenv( inheadp->new_uri_env);
	}

	if ( (inheadp->tmpfile_name) && (*inheadp->tmpfile_name )) {
		fmt3( command, MIDLEN, command, " < ", inheadp->tmpfile_name);
	}
	else if ( inheadp->method == PUT) {
		senderr( SERV_ERR, err_m[53], "");
		return;
	}

	if ((fp = WN_popen( command, "r")) == (FILE *) NULL ) {
		senderr( SERV_ERR, err_m[55], command);
		return;
	}

	fdfp = fileno( fp);


	/* It's like a standard CGI.  We do headers */

	cgi_headers( fp, cgibuf, location, &bufptr, &buflen);
	if ( ip->status & WN_ERROR)
		return;

	http_prolog( );
	ip->attributes |= WN_UNBUFFERED;
	send_out_mem( bufptr, buflen);
	send_out_fd( fdfp);
	result = pclose( fp);

	switch (inheadp->method) {
	case (PUT):
		methstr = "PUT";
		break;
	case (MOVE):
		methstr = "MOVE to";
		break;
	case (DELETE):
		methstr = "DELETE";
		break;
	default:
		methstr = "UNKNOWN";
		result = 1;
		break;
	}

	if ( result)
		success = "Failed to";
	else
		success = "Successful";

	fmt3( buf, SMALLLEN, success, " ", methstr);

	if ( inheadp->method == MOVE)
		writelog( ip, buf, inheadp->new_uri);
	else
		writelog( ip, buf, ip->filepath);

	if ( inheadp->tmpfile_name && *inheadp->tmpfile_name) {
		unlink( inheadp->tmpfile_name);
		*inheadp->tmpfile_name = '\0';
	}
	return;  /* to end of process_url */
#endif /* (! FORBID_CGI) */

}


/*
 * void cgi_env( ip, set_size) Create environment variables required for CGI.
 * Also WN_ROOT and WN_DIR_PATH.  If auth = TRUE then only do a 
 * small subset of the variables for authentication. 
 */

void
cgi_env( ip, set_size)
Request	*ip;
int	set_size;
{
	register char	*cp;


	if ( cgip == NULL) {
		if ((cgip = (CGI_data *) malloc(sizeof (CGI_data))) == NULL ) {
			logerr( err_m[64], "cgi_env");
			return;
		}
	}

	if ( cgiconp == NULL) {
		if ((cgiconp = (CGI_con_data *) malloc(sizeof (CGI_con_data)))
		    						== NULL ) {
			logerr( err_m[64], "cgi_env");
			return;
		}
	}

	if ( ip->status & WN_FULL_CGI_SET) {
		pathinfo_env( ip);
		return;		/* CGI environment vars already set */
	}

	if ( ip->status & WN_SMALL_CGI_SET) {
		if ( set_size == WN_FULL_CGI_SET) {
			full_cgi_env( ip);
			ip->status |= WN_FULL_CGI_SET;
		}
		return;
	}

	putenv( "PATH_INFO");
	putenv( "PATH_TRANSLATED");

	bzero( (char *)cgip, sizeof( CGI_data)); 
	mystrncpy( cgip->method, "REQUEST_METHOD=", SMALLLEN);
	switch ( inheadp->method) {
	case GET:
		mystrncat( cgip->method, "GET", SMALLLEN);
		break;
	case POST:
		mystrncat( cgip->method, "POST", SMALLLEN);
		break;
	case PUT:
		mystrncat( cgip->method, "PUT", SMALLLEN);
		break;
	case MOVE:
		mystrncat( cgip->method, "MOVE", SMALLLEN);
		break;
	case DELETE:
		mystrncat( cgip->method, "DELETE", SMALLLEN);
		break;
	default:
		break;
	}
	putenv( cgip->method);

	mystrncpy( cgip->dirpath, "WN_DIR_PATH=", SMALLLEN);
	mystrncat( cgip->dirpath, ip->filepath, SMALLLEN );
	if ( (cp = strrchr( cgip->dirpath, '/')) != NULL )
		*cp = '\0';
	putenv( cgip->dirpath);

	if ( *(ip->authuser)) {
		mystrncpy( cgip->ruser, "REMOTE_USER=", SMALLLEN);
		mystrncat( cgip->ruser, ip->authuser, SMALLLEN );
		putenv( cgip->ruser);
	}

	if ( dir_p->authtype && *(dir_p->authtype)) {
		mystrncpy( cgip->authtype, "AUTH_TYPE=", TINYLEN);
		mystrncat( cgip->authtype, dir_p->authtype, TINYLEN );
		putenv( cgip->authtype);
	}

#ifdef LETS_OPEN_A_BIG_SECURITY_HOLE
	if ( *(inheadp->authorization)) {
		mystrncpy( cgip->authorization, "HTTP_AUTHORIZATION=", SMALLLEN);
		mystrncat( cgip->authorization, 
				inheadp->authorization,	MIDLEN );
		putenv( cgip->authorization);
	}
#endif

	if ( DIGEST_AUTHENTICATION && (strncasecmp( inheadp->authorization, "Digest", 6) == 0) &&
			dir_p->authtype && (strcasecmp( dir_p->authtype, "Digest") == 0) ) {
		if ( !(*cgip->authorization)) {
			mystrncpy( cgip->authorization,
					"HTTP_AUTHORIZATION=", MIDLEN);
			mystrncat( cgip->authorization, inheadp->authorization,
							MIDLEN );
			putenv( cgip->authorization);
		}
		if ( (cp = strchr( outheadp->md5, ':')) != NULL ) {
			mystrncpy( cgip->md5, "CONTENT_MD5=", TINYLEN);
			cp++;
			while ( isspace ( *cp))
				cp++;
			mystrncat( cgip->md5, cp, TINYLEN );
			putenv( cgip->md5);
		}
	}

	if ( *(inheadp->host_head) ) {
		mystrncpy( cgip->http_myhost, "HTTP_HOST=", SMALLLEN);
		mystrncat( cgip->http_myhost, inheadp->host_head,
							SMALLLEN );
		putenv( cgip->http_myhost);
	}

	mystrncpy( cgip->lochost, "SERVER_NAME=", TINYLEN);
	mystrncat( cgip->lochost, hostname, SMALLLEN + TINYLEN);
	putenv( cgip->lochost);

	mystrncpy( cgip->dataroot, "WN_ROOT=", SMALLLEN);
	mystrncat( cgip->dataroot, ip->rootdir, SMALLLEN );
	putenv( cgip->dataroot);

	mystrncpy( cgip->home, "HOME=", SMALLLEN);
	mystrncat( cgip->home, ip->rootdir, SMALLLEN );
	putenv( cgip->home);

	mystrncpy( cgip->dataroot2, "DOCUMENT_ROOT=", SMALLLEN);
	mystrncat( cgip->dataroot2, ip->rootdir, SMALLLEN );
	putenv( cgip->dataroot2);

	if ( !(this_conp->con_status & WN_CON_CGI_SET)) {
		mystrncpy( cgiconp->raddr, "REMOTE_ADDR=", TINYLEN);
		mystrncat( cgiconp->raddr, this_conp->remaddr, TINYLEN);
		putenv( cgiconp->raddr);

		fmt2( cgiconp->scheme, TINYLEN, "URL_SCHEME=",
		      this_conp->scheme);
		putenv( cgiconp->scheme);

		Snprintf1( cgiconp->lport, TINYLEN, "SERVER_PORT=%d", port);
		putenv( cgiconp->lport);

 		mystrncpy( cgiconp->rport, "REMOTE_PORT=", TINYLEN);
 		mystrncat( cgiconp->rport, this_conp->remport, TINYLEN);
 		putenv( cgiconp->rport);
 
	}

	ip->status |= WN_SMALL_CGI_SET;  /* mark small environment as setup */
	/* End of auth set of CGI variables */
	if ( (set_size == WN_FULL_CGI_SET) 
				|| (this_conp->con_status & WN_CON_CGI_SET)) {
		/* if we ever set env in this connection we must redo it */
		full_cgi_env( ip);
	}
	return;
}

static void
pathinfo_env( ip )
Request	*ip;
{
	if ( *(ip->pathinfo) && (cgip != NULL)) {
		mystrncpy( cgip->pathinfo, "PATH_INFO=", MIDLEN);
		mystrncat( cgip->pathinfo, ip->pathinfo, MIDLEN);
		putenv( cgip->pathinfo);
		mystrncpy( cgip->tpath, "PATH_TRANSLATED=", MIDLEN);
		mystrncat( cgip->tpath, ip->rootdir, MIDLEN);
		mystrncat( cgip->tpath,	ip->pathinfo, MIDLEN);
		putenv( cgip->tpath);
	}
}

static void
full_cgi_env( ip )
Request	*ip;
{
	char	*cp;

	pathinfo_env( ip );
	if ( !(this_conp->con_status & WN_CON_CGI_SET)) {

		this_conp->con_status |=  WN_CON_CGI_SET;

		if ( !*this_conp->remotehost )
				/* Get remote hostname if not already done */
			get_remote_info( );

		mystrncpy( cgiconp->rhost, "REMOTE_HOST=", TINYLEN);
		mystrncat( cgiconp->rhost, this_conp->remotehost, MAXHOSTNAMELEN);
		putenv( cgiconp->rhost);

		putenv("GATEWAY_INTERFACE=CGI/1.1");
	
		mystrncpy( cgiconp->servsoft, "SERVER_SOFTWARE=", TINYLEN);
		mystrncat( cgiconp->servsoft, VERSION, TINYLEN);
		putenv( cgiconp->servsoft);

#ifdef RFC931_TIMEOUT
		get_rfc931( );
		if ( *(this_conp->rfc931name)) {
			mystrncpy( cgiconp->rident, "REMOTE_IDENT=", SMALLLEN);
			mystrncat( cgiconp->rident,
					this_conp->rfc931name, SMALLLEN);
			putenv( cgiconp->rident);
		}
#endif                    
	}

	if ( *(ip->query)) {
		mystrncpy( cgip->query, "QUERY_STRING=", TINYLEN);
		mystrncat( cgip->query, ip->query, MIDLEN + SMALLLEN);
		putenv( cgip->query);
	}

	mystrncpy( cgip->serv_protocol, "SERVER_PROTOCOL=", TINYLEN);
	switch ( inheadp->protocol) {
	case HTTP0_9:
		mystrncat(cgip->serv_protocol, "HTTP/0.9", TINYLEN);
		break;
	case HTTP1_1:
		mystrncat(cgip->serv_protocol, "HTTP/1.1", TINYLEN);
		break;
	default:
		mystrncat( cgip->serv_protocol, "HTTP/1.0", TINYLEN);
		break;
	}

	putenv( cgip->serv_protocol);

	mystrncpy( cgip->scrname, "SCRIPT_NAME=", MIDLEN);
	if ( *(ip->user_dir) == '/' )
		mystrncat( cgip->scrname, ip->user_dir, MIDLEN );
	cp = ip->filepath + strlen( ip->rootdir);
	mystrncat( cgip->scrname, cp, MIDLEN );

	if ( *(cgip->scrname) )
		putenv( cgip->scrname);

	strcpy( cgip->filescrname, "SCRIPT_FILENAME=");
	if ( (ip->type == RTYPE_CGI_HANDLER) && (*ip->handler))
		mystrncat( cgip->filescrname, ip->handler, MIDLEN );
	else {
		mystrncat( cgip->filescrname, ip->filepath, MIDLEN );
	}
	putenv( cgip->filescrname);

	if ( *(inheadp->content) ) {
		strcpy( cgip->content, "CONTENT_TYPE=");
		mystrncat( cgip->content, inheadp->content, SMALLLEN);
		putenv( cgip->content);
	}

	if ( *(inheadp->length) ) {
		strcpy( cgip->length, "CONTENT_LENGTH=");
		mystrncat( cgip->length, inheadp->length, SMALLLEN);
		putenv( cgip->length);
	}

	if ( *(inheadp->accept) ) {
		strcpy( cgip->http_accept, "HTTP_ACCEPT=");
		mystrncat( cgip->http_accept, inheadp->accept, ACCEPTLEN);
		putenv( cgip->http_accept);
	}

	if ( *(inheadp->charset) ) {
		strcpy( cgip->http_charset, "HTTP_ACCEPT_CHARSET=");
		mystrncat( cgip->http_charset, inheadp->charset, ACCEPTLEN/4);
		putenv( cgip->http_charset);
	}

	if ( *(inheadp->a_encoding) ) {
		strcpy( cgip->http_encoding, "HTTP_ACCEPT_ENCODING=");
		mystrncat( cgip->http_encoding, 
				inheadp->a_encoding, ACCEPTLEN/4);
		putenv( cgip->http_encoding);
	}

	if ( *(inheadp->te) ) {
		strcpy( cgip->http_te, "HTTP_TE=");
		mystrncat( cgip->http_te, inheadp->te, ACCEPTLEN/4);
		putenv( cgip->http_te);
	}

	if ( *(inheadp->lang) ) {
		strcpy( cgip->http_lang, "HTTP_ACCEPT_LANGUAGE=");
		mystrncat( cgip->http_lang, inheadp->lang, ACCEPTLEN/4);
		putenv( cgip->http_lang);
	}

	if ( *(inheadp->cookie) ) {
		strcpy( cgip->http_cookie, "HTTP_COOKIE=");
		mystrncat( cgip->http_cookie, inheadp->cookie, ACCEPTLEN);
		putenv( cgip->http_cookie);
	}

	if ( inheadp->range && *inheadp->range ) {
		strcpy( cgip->range, "HTTP_RANGE=");
		mystrncat( cgip->range, inheadp->range, RANGELEN - TINYLEN);
		putenv( cgip->range);
	}

	if ( *(inheadp->referrer) ) {
		strcpy( cgip->http_referrer, "HTTP_REFERER=");
		mystrncat( cgip->http_referrer, inheadp->referrer, MIDLEN);
		putenv( cgip->http_referrer);
	}

	if ( inheadp->ua && *inheadp->ua ) {
		strcpy( cgip->http_ua, "HTTP_USER_AGENT=");
		mystrncat( cgip->http_ua, inheadp->ua, SMALLLEN );
		putenv( cgip->http_ua);
	}

	if ( *(inheadp->from) ) {
		strcpy( cgip->http_from, "HTTP_FROM=");
		mystrncat( cgip->http_from, inheadp->from, SMALLLEN );
		putenv( cgip->http_from);
	}

	if ( inheadp->xforwardedfor && *(inheadp->xforwardedfor) ) {
		mystrncpy( cgip->http_xforwardedfor,
			"HTTP_X_FORWARDED_FOR=", 2*SMALLLEN);
		mystrncat( cgip->http_xforwardedfor,
			inheadp->xforwardedfor, 2*SMALLLEN);
		putenv( cgip->http_xforwardedfor);
	}

	if ( inheadp->via && *(inheadp->via) ) {
		mystrncpy( cgip->http_via, "HTTP_VIA=", 2*SMALLLEN);
		mystrncat( cgip->http_via, inheadp->via, 2*SMALLLEN);
		putenv( cgip->http_via);
	}

	ip->status |= WN_FULL_CGI_SET;  /* mark environment as setup */
}

static void
cgi_headers( fp, cgibuf, location, bufptr, buflen)
FILE	*fp;
char	*cgibuf,
	*location,
	**bufptr;

int	*buflen;
{
	register char	*beginl,
			*endl,
			*cp = NULL;

	int		fd,
			n,
			m;

	fd = fileno( fp);
	while ( (n = read( fd, cgibuf, OUT_BUFFSIZE )) <= 0 ) {
		char errbuf[SMALLLEN];

		Snprintf1( errbuf, SMALLLEN, "cgi_headers: %.150s", strerror(errno));
		if ( (n == -1) && (errno == EINTR))
			continue;
		senderr( SERV_ERR, err_m[76], errbuf);
		pclose( fp);
		return;
	}

	beginl = cgibuf;
	cgibuf[n] = '\0';

	while ( TRUE) {
		if ( ( endl = strchr( beginl, '\n')) == NULL) {
			/* not all headers have been read; read more */
			n -= (beginl - cgibuf);
			mymemcpy( cgibuf, beginl, n);
			while ( (m = read( fd, cgibuf + n, OUT_BUFFSIZE - n))
								<= 0 ) {
				if ( (m == -1) && (errno == EINTR))
					continue;
				senderr( SERV_ERR, err_m[104], "");
				pclose( fp);
				return;
			}

			n += m;
			cgibuf[n] = '\0';
			beginl = cgibuf;
			continue;
		}
		if (endl > cgibuf && endl[-1] == '\r')
			endl[-1] = '\0';
		*endl++ = '\0';
		if ( *beginl == '\0' ) { 	/* blank line: end of header */
			beginl = endl;
			n -= (beginl - cgibuf);
			break;
		}

		if ( strncasecmp( "Content-type:", beginl, 13) == 0) {
			cp = beginl + 13;
			while ( isspace( *cp))
				cp++;
			mystrncpy( cgip->cgi_content_type, cp, SMALLLEN);
			this_rp->content_type = cgip->cgi_content_type;
		}
		else if ( (strncasecmp("Location:", beginl, 9) == 0)) {
			cp = beginl + 9;
			while ( isspace( *cp))
				cp++;
			mystrncpy( location, cp, MIDLEN);
		}
		else if ( (strncasecmp("Status:", beginl, 7) == 0)) {
			cp = beginl + 7;
			while ( isspace( *cp))
				cp++;
			mystrncpy( outheadp->status, cp, SMALLLEN);
		}
		else if ( (strncasecmp("Expires:", beginl, 8) == 0)) {
			mystrncpy( outheadp->expires, beginl, SMALLLEN - 2);
			mystrncat( outheadp->expires, "\r\n", SMALLLEN);
		}
		else {
			if (strlen(beginl) + strlen(outheadp->list) < BIGLEN - 3) {
				mystrncat( outheadp->list, beginl, BIGLEN);
				mystrncat( outheadp->list, "\r\n", BIGLEN);
			}
			else {
				senderr( SERV_ERR, err_m[56], "");
				pclose( fp);
				return;
			}

		}
		beginl = endl;
	}
	*buflen = n;
	*bufptr = endl;
}
