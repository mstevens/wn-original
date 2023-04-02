/*  

    WN: A Server for the HTTP File: authwn/wn_pamauth.c Version 2.4.3
    
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

#define WNAUTH_DEBUG_FILE ""		/* put filename here for debugging */
#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <stdlib.h>
#include <stdio.h>

#define WN_REALM_DESIGNATOR	"wndigest_realm:"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <malloc.h>
#include <sys/signal.h>
#include <pwd.h>
#include <sys/types.h>

#ifdef DBM_AUTH
#include <ndbm.h>
#endif /* DBM_AUTH */

#define AUTHWN_TIMEOUT	(60)
#define GROUPLEN	(8192)
#define MAXGROUPS	(10)
#define WN_PAM_MAXARGS	(64)

#include "../config.h"
#include "wnauth.h"

extern char *optarg;
extern int optind;

extern char	*crypt(),
		*getenv();

static char	*encode();

static void	chop(),
		authwn_timeout(),
		log_auth(),
		mkdigest(),
		getpath();

static int	checkpw( ),
		mystrncpy( ),
		mystrncat( ),
		ingroup( );

#ifdef DBM_AUTH
extern datum	dbm_fetch();
extern DBM	*dbm_open();
#endif

static char	auth_logfile[2*SMALLLEN];

int		isdbm = FALSE;
int		nis_id = FALSE;
int		nis_pw = FALSE;

struct passwd	*passwd;

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc
		     ,const char **argv)
{
	return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_authenticate( pamh, flags, argc, argv)
pam_handle_t *pamh;
int flags; 
int argc;
const char  **argv;
{
	register char	*cp;


	char	*user,
		*password,
		*wn_argv[WN_PAM_MAXARGS],
		*group_list[MAXGROUPS + 1],
		argdata[SMALLLEN],
		pwfile[2*SMALLLEN],
		grpfile[2*SMALLLEN],
		buf[SMALLLEN];

	int	wn_argc,
		retval = 0,
		numgrps = 0,
		i,
		c;

	struct pam_response *response_p;
	struct pam_message 	*msgp,
				mymsg;

	int (*myconv)() = NULL;
	struct pam_conv *xconv;


	mystrncpy( auth_logfile, WNAUTH_DEBUG_FILE, SMALLLEN);
	group_list[0] = NULL;
	signal( SIGALRM, authwn_timeout);
	alarm( AUTHWN_TIMEOUT);
	mymsg.msg = "Password: ";
	mymsg.msg_style = PAM_PROMPT_ECHO_OFF;
	msgp = &mymsg;

	retval = pam_get_item(pamh, PAM_USER, (const void **)&user );
	if ( retval != PAM_SUCCESS)
		return ( PAM_AUTHINFO_UNAVAIL);

	retval = pam_get_item(pamh, PAM_CONV, (const void **)&xconv );
	if ( retval != PAM_SUCCESS)
		return ( PAM_AUTHINFO_UNAVAIL);

	myconv = xconv->conv;

	/* skip first arg for argdata */
	cp = xconv->appdata_ptr;
	while( *cp && isspace( *cp))
		cp++;
	while( *cp && !isspace( *cp))
		cp++;
	while( *cp && isspace( *cp))
		cp++;

	mystrncpy( argdata, cp, SMALLLEN);

	/* I don't understand this; very suspicious */
	wn_argc = 0;
	while ( wn_argc < 4)
		wn_argv[wn_argc++] = "";
	
	for ( i = 0; (i < argc) && ( i < SMALLLEN); i++ ) {
		wn_argv[wn_argc++] = (char *)argv[i];
	}

	cp = argdata;

	while ( *cp && (wn_argc < SMALLLEN)) {
		char *cp2;
		while( *cp && isspace( *cp))
			cp++;
		cp2 = cp;
		while( *cp && !isspace( *cp))
			cp++;
		if ( *cp)
			*cp++ = '\0';
		wn_argv[ wn_argc++] = strdup( cp2);
	}

	grpfile[0] = pwfile[0] = '\0';
	while ((c = getopt( wn_argc, wn_argv, "Dg:G:l:nNP:")) != -1) {
		switch ((char) c) {
			char *group;

		case 'D':
			isdbm = TRUE;
			break;
		case 'l':
			mystrncpy( auth_logfile, optarg, SMALLLEN);
			break;

		case 'g':
			group = strdup( optarg);
			cp = group;
			while ( *cp && (numgrps < MAXGROUPS)) {
				char *cp2;
				while ( isspace( *cp))
					cp++;
				cp2 = cp;
				while ( *cp && !isspace( *cp))
					cp++;
				if ( *cp)
					*cp++ = '\0';
				group_list[numgrps++] = strdup( cp2);
			}
			group_list[i] = NULL;
			if ( group)
				free( group);
			break;
		case 'G':
			mystrncpy( grpfile, optarg, SMALLLEN);
			break;
		case 'n':
			nis_pw = TRUE;
			break;
		case 'N':
			nis_pw = TRUE;
			nis_id = TRUE;
			break;
		case 'P':
			mystrncpy( pwfile, optarg, SMALLLEN);
			break;
		case 's':
			/* ignore "-s service" option */
			break;
		default:
			log_auth( authlog_m[20], c);
		}
	}

	if ( !*pwfile && !nis_id) {
		log_auth( authlog_m[7], NULL);
		return ( PAM_AUTHINFO_UNAVAIL);
	}

	if ( *pwfile)
		getpath( pwfile, pwfile);
	if ( *grpfile)
		getpath( grpfile, grpfile);

	retval = (*myconv)( 1, &msgp, &response_p, NULL);
	if ( retval != PAM_SUCCESS)
		return ( PAM_AUTHINFO_UNAVAIL);

	password = response_p->resp;


	retval = checkpw( user, password, pwfile, grpfile, buf, group_list);
	for ( i = 0; group_list[i] != NULL; i++)
		free( group_list[i]);

	if ( retval == PAM_SUCCESS ) {
		log_auth( authlog_m[0], buf);
		return PAM_SUCCESS;
	}
	else {
		log_auth( authlog_m[1], buf);
		return (retval);
	}
}

static int
checkpw( user, pw, pwpath, grppath, rbuf, glist)
char	*user,
	*pw,
	*pwpath,
	*grppath,
	*rbuf,
	**glist;
{
	register char	*cp,
			*cp2;
	char		*salt,
			codedpw[SMALLLEN],
			realm[SMALLLEN],
			cbuf[SMALLLEN],
			linebuf[GROUPLEN];

	int		found;
	FILE		*pwfp,
			*grfp;

#ifdef DBM_AUTH
	datum		content,
			key;
	DBM		*mydb;
#endif


	codedpw[0] = '\0';
	mystrncpy( rbuf, user, SMALLLEN);
	mystrncat( rbuf, ":", SMALLLEN);

	if ( !isdbm) {
		int n = (sizeof( WN_REALM_DESIGNATOR) - 1);

		if (nis_id) {
			passwd = getpwnam (user);
			if (passwd == 0)
				return ( PAM_AUTHINFO_UNAVAIL);

			mystrncpy (codedpw, passwd->pw_passwd, SMALLLEN);
			chop (passwd);
			goto check;
		}


		if ( ( pwfp = fopen( pwpath, "r")) == (FILE *)NULL) {
			log_auth( authlog_m[4], pwpath);
			return ( PAM_AUTHINFO_UNAVAIL);
		}

		fgets( linebuf, SMALLLEN, pwfp);
		if ( strncasecmp( WN_REALM_DESIGNATOR, linebuf, n) == 0 ) {
			mystrncpy( realm, linebuf + n, SMALLLEN);
			if ( (cp = strchr( realm, ':')) != NULL ) {
				*cp ='\0';
			}
			mystrncat( rbuf, realm, SMALLLEN);
			linebuf[0] = '\0';
		}
		do {
			if ( (cp = strchr( linebuf, ':')) == NULL )
				continue;
			*cp++ = '\0';
			if ( streq( linebuf, user)) {
				if (nis_pw) {
					passwd = getpwnam (user);
					if (passwd == 0)
						return ( PAM_AUTHINFO_UNAVAIL);
					mystrncpy (codedpw, passwd->pw_passwd,
								SMALLLEN);
					chop (codedpw);
					break;
				}

				if ( (cp2 = strchr( cp, ':')) != NULL )
					*cp2 = '\0';
				mystrncpy( codedpw, cp, SMALLLEN);
				chop( codedpw);
				break;
			}
		} while ( fgets( linebuf, SMALLLEN, pwfp));

	}
	else {
#ifdef DBM_AUTH
		key.dptr = user;
		key.dsize = strlen(user);


		if ( (mydb = dbm_open( pwpath, DBM_RDONLY, 0)) <= 0 ) {
			log_auth( authlog_m[5], pwpath);
			return ( PAM_AUTHINFO_UNAVAIL);
		}

		content = dbm_fetch( mydb, key);
		if ( (content.dptr != (char *)NULL) && (content.dsize < SMALLLEN)) {
			strncpy( codedpw, content.dptr, content.dsize);
			codedpw[content.dsize] = '\0';
		}
		else {
			log_auth( authlog_m[18], NULL);
			return ( PAM_AUTHINFO_UNAVAIL);
		}
		dbm_close( mydb);
#else
		log_auth( authlog_m[8], NULL);
		return ( PAM_AUTHINFO_UNAVAIL);
#endif
	}

	if ( *grppath ) {
		int i;

		if ( (grfp = fopen( grppath, "r")) == (FILE *)NULL) {
			log_auth( authlog_m[6], grppath);
			return ( PAM_AUTHINFO_UNAVAIL);
		}

		found = FALSE;

		while ( fgets( linebuf, GROUPLEN, grfp)) {
			if ( (cp = strchr( linebuf, ':')) == NULL )
				continue;
			*cp++ = '\0';
			i = 0;
			while ( glist[i] ) {
				if ( streq( linebuf, glist[i])) {
					chop( cp);
					if ( (cp2 = strchr( cp, ':')) == NULL ) {
					/* no second colon -- it's apache format */
					/* use space as separtor		 */
						found = 
						     ingroup( cp, user, (char) ' ');
						if ( found)
							break;
					}
					*cp2++ = '\0';  /* skip second colon */
					if ( (cp2 = strchr( cp2, ':')) == NULL )
						continue;
					*cp2++ = '\0';
					/* skip third colon */
					found = ingroup( cp2, user, (char) ',');
					if ( found)
						break;
				}
				i++;
			}
			if ( found)
				break;
		}
		if ( !found) {
			return PAM_AUTH_ERR;
		}
	}
  check:
	/* If len of codedpw < 20 or it starts with $, it's made with crypt */
	/* Use salt in that case */

	if ( (strlen( codedpw) < 20) || (*codedpw == '$'))
		salt = codedpw;
	else
		salt = NULL;

	if ( *codedpw &&
	strcmp( codedpw, encode( cbuf, user, pw, salt, realm)) == 0)
		return PAM_SUCCESS;
	else
		return PAM_AUTH_ERR;

}

/*
 * mkdigest( in, out) takes the string "in" and calculates the MD5
 * digest placing the result in "out"
 */

static void 
mkdigest (in, out)
char	*in,
	*out;
{
	unsigned i;
	MD5_CTX context;
	unsigned char digest[16];

	MD5_Init (&context);
	MD5_Update (&context, in, strlen( in));
	MD5_Final (digest, &context);

	for ( i = 0; i < 16; i++) {
		sprintf( out, "%02x", digest[i]);
		out += 2;
	}
}

/*
 * static char  *encode( char *buf, char *pw, char *salt, char *realm)
 * Encode pw with either MD5 or crypt().  Use salt with crypt().
 * Place result in buf[SMALLLEN] and return &buf[0].
 */

static char *
encode(  buf, user, pw, salt, realm)
char	*buf,
	*user,
	*pw,
	*salt,
	*realm;

{
	char lbuf[MIDLEN];

	if ( salt ) {
		mystrncpy( buf, (char *) crypt( pw, salt), SMALLLEN);
		return (buf);
	}

	mystrncpy( lbuf, user, SMALLLEN);
	mystrncat( lbuf, ":", MIDLEN);
	mystrncat( lbuf, realm, MIDLEN);
	mystrncat( lbuf, ":", MIDLEN);
	mystrncat( lbuf, pw, MIDLEN);
	mkdigest( lbuf, buf);
	return (buf);
}


/*
 * static int ingroup( list, user, separator)
 * Returns TRUE if "user" is in the "separator" separated line pointed
 * to by "list."
 */

static int
ingroup( list, user, separator)
char	*list,
	*user,
	separator;
{
		int		len;

		len = strlen( user);
		while ( *list ) {
			if ( *list == separator)
				list++;
			if ( strncmp( user, list, len) == 0 ) {
				list += len;
				if ( (!*list) || (*list == separator)) {
					return TRUE;
				}
			}
			else {
				while ( *list && (*list != separator))
					list++;
			}
		}
		return FALSE;
}

static void
chop( line)
char *line;
{
	register char	*cp;

	if ( *line == '\0')
		return;
	cp = line;
	while ( *cp )
		cp++;
	if ( *--cp == '\n') {
		*cp = '\0';
	}
}


static void
getpath( path, file)
char	*path,
	*file;
{
	char	*cp,
		buf[SMALLLEN];
	int	len;

	/* Make a copy so path == file is ok */
	mystrncpy( buf, file, SMALLLEN);
	if ( *file == '/') {
		mystrncpy( path, buf, SMALLLEN);
		return;
	}
	if ( *buf == '~' && *(buf + 1) == '/') {
		if ( (cp = getenv( "WN_ROOT")) != NULL ) {
			mystrncpy( path, cp, SMALLLEN);
		}
		else
			*path = '\0';
		mystrncat( path, buf + 1, 2*SMALLLEN);
		return;
	}

	if ( (cp = getenv( "WN_DIR_PATH")) != NULL ) {
		mystrncpy( path, cp, SMALLLEN);
		len = strlen( path);
		path[len] =  '/';
		mystrncpy( path + len + 1, buf, SMALLLEN - 2 );
		return;
	}
	else {
		mystrncpy( path, buf, SMALLLEN);
	}
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
authwn_timeout()
{
	signal( SIGALRM, SIG_DFL);
	log_auth( authlog_m[16], NULL);
	exit( 2);
}

static void
log_auth( msg, msg2)
char	*msg,
	*msg2;
{
	time_t	clock;
	struct tm *ltm;
	char date[TINYLEN];
	FILE	*logfp;

	if (! auth_logfile[0])
		return;

	if ( strcmp( auth_logfile, "-") == 0 )
		logfp = stdout;
	else {
		if ( (logfp = fopen( auth_logfile, "a")) == NULL) {
			fprintf( stderr, authlog_m[19], auth_logfile);
			logfp = stderr;
		}
	}

	time(&clock);
	ltm = (struct tm *) localtime(&clock);
	strftime( date, TINYLEN, "[%d/%h/%Y:%T] ", ltm);

	fputs( date, logfp);
	if ( msg2) 
		fprintf( logfp, msg, msg2);
	else
		fputs( msg, logfp);
	fputc( '\n', logfp);
	fclose( logfp);
}

