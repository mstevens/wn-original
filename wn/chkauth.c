/*
    Wn: A Server for the HTTP
    File: wn/chkauth.c
    Version 2.4.5

    Copyright (C) 1996-2003  <by John Franks>

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
#include <ctype.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "wn.h"
#include "auth.h"


#if WN_PAM_ENABLED
#include <security/pam_appl.h>

int wn_conv( );

static struct pam_conv wnconv = {
	wn_conv,
	NULL
};

static char *pam_pword;

#endif /* WN_PAM_ENABLED */


static void	sendauth(),
		decode64();

static int	
	send_noauth(),
	check_pam(),
	pam_auth_err = 0;

static
WN_CONST
short int tr[128]={
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,
    10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,
    28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,
    -1,-1,-1,-1,-1
};



static void
decode64( bufcoded, out)
char	*bufcoded,
	*out;
{

	register char	*in;
	char		buf[SMALLLEN + TINYLEN];

	
	while( isspace(*bufcoded))
		bufcoded++;

	mystrncpy( buf, bufcoded, SMALLLEN);
	in = buf;

	while( *in && (tr[(unsigned) (*in &= 0177)] >= 0))
		in++;
	*in++ = 0;
	*in++ = 0;
	*in++ = 0;
	*in = 0;
    
	in = buf;
    
	while ( in[3] ) {
        	*out++ = (unsigned char) (tr[(unsigned)in[0]] << 2 
						| tr[(unsigned)in[1]] >> 4);
	        *out++ = (unsigned char) (tr[(unsigned)in[1]] << 4 
						| tr[(unsigned)in[2]] >> 2);
        	*out++ = (unsigned char) (tr[(unsigned)in[2]] << 6 
						| tr[(unsigned)in[3]]);
		in += 4;
	}
	
    	if ( in[2] ) {
        	*out++ = (unsigned char) (tr[(unsigned)in[0]] << 2 
						| tr[(unsigned)in[1]] >> 4);
	        *out++ = (unsigned char) (tr[(unsigned)in[1]] << 4 
						| tr[(unsigned)in[2]] >> 2);
        	*out++ = (unsigned char) tr[(unsigned)in[2]] << 6;
	}
	else if ( in[1]) {
        	*out++ = (unsigned char) (tr[(unsigned)in[0]] << 2 
						| tr[(unsigned)in[1]] >> 4);
	        *out++ = (unsigned char) tr[(unsigned)in[1]] << 4;
	}
	else if ( in[0] ) {
        	*out++ = (unsigned char) tr[(unsigned)in[0]] << 2;
	}
	*out = '\0';
}


/*
 * chkauth( ip) check whether authorization is in use and whether the
 * client is authenticated.
 */

int
chkauth( ip )
Request	*ip;
{
	register char	*cp,
			*cp2;

	char	*authmod,
		*authtype,
		*authrealm,
		*authheadp = NULL,
		authcmd[MIDLEN + 2*SMALLLEN],
		buf[MIDLEN];

	int	status,
		result;

	FILE	*fp = NULL;

	signal( _WN_SIGCHLD, SIG_DFL);

	result = AUTH_UNTESTED;

	authmod = dir_p->authmodule;
	if ( (inheadp->method == PUT) || (inheadp->method == DELETE) ||
		     				(inheadp->method == MOVE)) {
		authtype = dir_p->pauthtype;
		authrealm = dir_p->pauthrealm;
	}
	else {
		authtype = dir_p->authtype;
		authrealm = dir_p->authrealm;
	}

	mystrncpy( authcmd, authmod, SMALLLEN);

	cp = inheadp->authorization;

	if ( *cp ) {
		if ( strncasecmp( cp, "Basic", 5) == 0 &&
				strcasecmp( authtype, "Basic") == 0) {
			char	*cp3;

			/* construct "Basic user:password" in buf */
			mystrncpy( buf, "Basic ", MIDLEN);
			cp += 5;
			cp2 = buf + 6;
			decode64( cp, cp2);

			if ( ( cp3 = strchr( cp2, ':')) != NULL)
				*cp3 = '\0';
			mystrncpy( ip->authuser, cp2, USERNAME_LEN);
			if ( cp3 != NULL)
				*cp3 = ':';

			if ( ip->attributes & WN_CGI )
				cgi_env( ip, WN_FULL_CGI_SET);
			else
				cgi_env( ip, WN_SMALL_CGI_SET);

			authheadp = buf;

			if ( WN_USE_PAM &&
				( strncasecmp( authcmd, "pam", 3) == 0) &&
				( (!authcmd[3]) || isspace( authcmd[3]))) {
					result = check_pam( authheadp, authcmd);
			}
			else {
				if ((fp = WN_popen( authcmd, "w")) == (FILE *) NULL ) {
					senderr( SERV_ERR, err_m[14], authcmd);
					wn_exit( 2);   /* senderr: SERV_ERR */
				}
				fprintf( fp, "%.500s\n", authheadp);
			}
		}
		else if ( strncasecmp( cp, "cert", 4) == 0 &&
			strcasecmp( authtype, "Certificate") == 0) {

			strcpy(  inheadp->authorization, "cert");
			if ( ip->attributes & WN_CGI )
				cgi_env( ip, WN_FULL_CGI_SET);
			else
				cgi_env( ip, WN_SMALL_CGI_SET);

			if ((fp = WN_popen( authcmd, "w"))  == (FILE *) NULL ) {
				senderr( SERV_ERR, err_m[14], authcmd);
				wn_exit( 2);   /* senderr: SERV_ERR */
			}
			strcpy( buf, "Client Cert");
			authheadp = buf;
			fprintf( fp, "%.500s\n", authheadp);
		}
		else if ( DIGEST_AUTHENTICATION && (strncasecmp( cp, "Digest", 6) == 0) &&
					(strcasecmp( authtype, "Digest") == 0) ) {
			char	auth_uri[MIDLEN];

			mystrncat( authcmd, " -r ", SMALLLEN);
			mystrncat( authcmd, authrealm, SMALLLEN);

			cp2 = inheadp->authorization;
			if ( (cp = strstr( cp2, "username")) == NULL)
				cp = strstr( cp2, "Username");
			if ( cp != NULL) {
				char *cp3;

				cp2 = strchr( cp, '"');
				cp2++;
				if ( (cp3 = strchr( cp2, '"')) != NULL)
					*cp3 = '\0';
				mystrncpy( ip->authuser, cp2, USERNAME_LEN);
				if ( cp3 != NULL)
					*cp3 = '"';
			}

			if ( ip->attributes & WN_CGI )
				cgi_env( ip, WN_FULL_CGI_SET);
			else
				cgi_env( ip, WN_SMALL_CGI_SET);

			if ((fp = WN_popen( authcmd, "r"))  == (FILE *) NULL ) {
				senderr( SERV_ERR, err_m[14], authcmd);
				wn_exit( 2);   /* senderr: SERV_ERR */
			}

			authheadp = inheadp->authorization;
			/* For digest compare the URI and auth header URI */
			if ( ( cp = strstr( authheadp, "uri=\"")) ||
					(cp = strstr( authheadp, "URI=\""))) {
				cp += 5;
				mystrncpy( auth_uri, cp, MIDLEN);
				if ( (cp = strchr( auth_uri, '"')) != NULL ) 
					*cp = '\0';
				if ( !streq( auth_uri, inheadp->auth_url_path))
					result = AUTH_DENIED;
			}
		}
		else {
			mystrncpy( buf, inheadp->authorization, SMALLLEN);
			cp = buf;
			while( *cp && !isspace( *cp))
				cp++;
			*cp = '\0';
			senderr( SERV_ERR, autherr_m[9], buf);
			wn_exit( 2);   /* senderr: SERV_ERR */
		}

		bzero( buf, sizeof( buf));
		bzero( inheadp->authorization, sizeof(inheadp->authorization));

		if ( authheadp == NULL) {
			sendauth( ip, "-s false", autherr_m[10]);
			return FALSE;
		}


		if ( (result == AUTH_UNTESTED) && (fp != NULL)) {
			status = pclose( fp);

#ifdef NEXT
			if ( (status != 0) && WIFEXITED( (union wait) status))
				result = ((status >> 8) & 0377);
#else
			if ( (status != 0) && WIFEXITED( status))
				result = WEXITSTATUS( status);
#endif
			else
				result = status;
		}

		switch (result) {
		case (-1):
			senderr( SERV_ERR, autherr_m[11], "");
			return FALSE;
		case AUTH_GRANTED:
			return TRUE;
		case AUTH_DENIED:
			sendauth( ip, "-s false", autherr_m[13]);
			return FALSE;
		case AUTH_EXPIRED:
			sendauth( ip, "-s true", autherr_m[14]);
			return FALSE;
		case (3):
		case (9):
		case (12):
		case (15):
			senderr( "406", autherr_m[result], "");
			return FALSE;
		case (4):
		case (5):
		case (6):
		case (7):
		case (8):
		case (10):
		case (11):
		case (17):
		case (18):
			senderr( SERV_ERR, autherr_m[result], "");
			return FALSE;
		case (13):
			logerr( autherr_m[result], "");
			sendauth( ip, "-s false", autherr_m[13]);
			return FALSE;
		case (14):
			logerr( autherr_m[result], "");
			sendauth( ip, "-s false", autherr_m[14]);
			return FALSE;
		case (16):
		case (19):
			logerr( autherr_m[result], "");
			wn_exit( 2);  /* auth error */
		case (21):
			Snprintf1( buf, 40, autherr_m[result], pam_auth_err);
			senderr( SERV_ERR, buf, "");
			wn_exit( 2);  /* auth error */
		default:
			Snprintf2( buf, MIDLEN,  "%.100s %d", 
				   autherr_m[0], result);
			senderr( SERV_ERR, err_m[42], buf);
			return FALSE;
		}
	}
	sendauth( ip, "-s false", "");
	return FALSE;
}


static void
sendauth( ip, noncearg, logmsg)
Request	*ip;
char	*noncearg,
	*logmsg;
{
	char	*authtype,
		*authrealm,
		buf[MIDLEN];

	if ( (inheadp->method == PUT) || (inheadp->method == POST) ) {
		this_conp->keepalive = FALSE;
	}

	if ( (inheadp->method == PUT) || (inheadp->method == DELETE) ||
		     				(inheadp->method == MOVE)) {
		authtype = dir_p->pauthtype;
		authrealm = dir_p->pauthrealm;
	}
	else {
		authtype = dir_p->authtype;
		authrealm = dir_p->authrealm;
	}


	mystrncpy( outheadp->status, "401 Unauthorized", SMALLLEN);
	if ( strcasecmp( authtype, "Certificate") == 0)
		mystrncpy( outheadp->status, "403 Forbidden", SMALLLEN);
	else if ( strcasecmp( authtype, "basic") == 0) {
		fmt3( outheadp->list, MIDLEN,
				"WWW-Authenticate: Basic realm=\"",
				authrealm, "\"\r\n");
	}
	else if ( DIGEST_AUTHENTICATION && (strcasecmp( authtype, "Digest") == 0) ) {
		char	authcmd[MIDLEN];
		FILE	*fp;

		if ( ip->attributes & WN_CGI )
			cgi_env( ip, WN_FULL_CGI_SET);
		else
			cgi_env( ip, WN_SMALL_CGI_SET);

		fmt3( authcmd, MIDLEN, 
		      dir_p->authmodule, " -r ",  authrealm);
		fmt3( authcmd, MIDLEN, authcmd, " ", noncearg);
		if ((fp = WN_popen( authcmd, "r"))  == (FILE *) NULL ) {
			senderr( SERV_ERR, err_m[14], authcmd);
			wn_exit( 2);   /* senderr: SERV_ERR */
		}
		if ( fgets( outheadp->list, MIDLEN, fp) == NULL) {
			senderr( SERV_ERR, err_m[50], authcmd);
			pclose( fp);
			wn_exit( 2);   /* senderr: SERV_ERR */
		}
		pclose( fp);
	}
	else {
		senderr( SERV_ERR, autherr_m[19], "");
		wn_exit( 2);   /* senderr: SERV_ERR */
	}

	ip->encoding =  NULL;
	ip->mod_time = 0;
	ip->content_type = BUILTIN_CONTENT_TYPE;

	if ( *(dir_p->authdenied_file) ) {
		if ( send_noauth( ) ) {
			writelog( ip, log_m[1], logmsg);
			return;
		}
	}
		
	fmt3( buf, MIDLEN, "<head>\n<title>", autherr_m[1],
			"</title>\n</head>\n<body>\n<h2>");
	fmt3( buf, MIDLEN, buf, autherr_m[1], "</h2>\n");

	fmt3( buf, MIDLEN, buf, logmsg, "\n");
	fmt3( buf, MIDLEN, buf,  SERVER_LOGO, "\n </body>\n");

	ip->datalen = (unsigned long) strlen( buf);
	Snprintf1( ip->length, TINYLEN, "%lu", ip->datalen);
	ip->status |= WN_HAS_BODY;
	http_prolog( );
	send_text_line(buf);

	writelog( ip, log_m[1], logmsg);
	return;
}


static int
send_noauth( )
{
	FILE	*fp;
	char	buf[MIDLEN];
	struct stat stat_buf;

	if ( getfpath2( buf, dir_p->authdenied_file,
						this_rp->cachepath) == FALSE) {
		logerr( err_m[86], dir_p->authdenied_file);
		return FALSE;
	}
	if ( stat( buf, &stat_buf) != 0 ) {
		logerr( err_m[12], buf);
		return FALSE;
	}
	if ( (fp = fopen( buf, "r")) == (FILE *) NULL ) {
		logerr( err_m[1], buf);
		return FALSE;
	}

	this_rp->datalen = (unsigned long) stat_buf.st_size;

	Snprintf1( this_rp->length, TINYLEN, "%lu",  this_rp->datalen);
	set_etag( &stat_buf);

	http_prolog();
	while ( fgets( buf, MIDLEN, fp)) {
		send_text_line( buf);
	}
	return TRUE;
}


static int
check_pam( authdata, data)
char	*authdata,
	*data;
{
#if WN_PAM_ENABLED
	pam_handle_t *pamh=NULL;
	int	retval,
		result = AUTH_DENIED;
	char	service[SMALLLEN],
		*user,
		*cp;


	wnconv.appdata_ptr = data;
	user = this_rp->authuser;
	if ( (pam_pword = strchr( authdata, ':')) == NULL)
		pam_pword = wn_empty;
	else 
		pam_pword++;

	if ( (cp = strstr( wnconv.appdata_ptr, "-s")) == NULL) {
		mystrncpy( service, WN_DEFAULT_PAM_SERVICE, SMALLLEN);
	}
	else if ( isspace( *(cp - 1)) && isspace( *(cp + 2))) {
		cp += 2;
		while ( *cp && isspace( *cp))
			cp++;
		mystrncpy( service, cp, SMALLLEN);
		cp = service;
		while ( *cp && !isspace( *cp))
			cp++;
		*cp = '\0';
	}
	else {
		mystrncpy( service, WN_DEFAULT_PAM_SERVICE, SMALLLEN);
	}

	retval = pam_start( service, user, &wnconv, &pamh);
	if (retval == PAM_SUCCESS) {
		retval = pam_authenticate(pamh, TRUE);
	}
	if (retval == PAM_SUCCESS) {
		retval = pam_acct_mgmt(pamh, TRUE);
	}
	switch ( retval) {
	case PAM_SUCCESS:
		result = AUTH_GRANTED;
		break;
	case PAM_AUTH_ERR:
	case PAM_USER_UNKNOWN:
		result = AUTH_DENIED;
		break;
	case PAM_OPEN_ERR:
		logerr( autherr_m[22], service);
		break;
	case PAM_AUTHINFO_UNAVAIL:
		logerr( autherr_m[23], "");
		break;
	default:
		pam_auth_err = retval;
		result = PAM_AUTH_FAILED;
	}
	
	if ( pam_end( pamh, retval) != PAM_SUCCESS) {
		pamh = NULL;
		logerr( autherr_m[20], service);
	}
	return (result);
#else
	return AUTH_DENIED;
#endif /* WN_PAM_ENABLED */
}


#if WN_PAM_ENABLED
int wn_conv( num_msg, msgm, response, appdata_ptr)
int num_msg;
const struct pam_message **msgm;
struct pam_response **response;
void *appdata_ptr;
{
	int	i;

	struct pam_response	*reply;
	const struct pam_message *msg_arr;
	
	reply = (struct pam_response *) calloc( num_msg,
				sizeof(struct pam_response));

	if (reply == NULL) {
		return PAM_CONV_ERR;
	}

	msg_arr = *msgm;
	
	for ( i = 0; i < num_msg; i++ ) {

		if ( strncasecmp( msg_arr[i].msg, "password", 8 ) == 0) {
			reply[i].resp = strdup( pam_pword);
			reply[i].resp_retcode = 0;
		}
		else {
			reply[i].resp = NULL;
			reply[i].resp_retcode = 0;
		}
	}
	pam_pword = NULL;
	*response = reply;
	return (PAM_SUCCESS);
}
#endif /* WN_PAM_ENABLED */
