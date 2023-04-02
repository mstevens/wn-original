/*  

    WN: A Server for the HTTP File: authwn/authwn.c Version 2.3.12
    
    Copyright (C) 1996-1999  <by John Franks>

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

#define WN_REALM_DESIGNATOR	"wndigest_realm:"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/signal.h>
#include <pwd.h>
#include <sys/types.h>

#ifdef DBM_AUTH
#include <ndbm.h>
#endif /* DBM_AUTH */

#define AUTHWN_TIMEOUT	(60)
#define GROUPLEN	(8192)
#define MAXGROUPS	(10)

#include "../config.h"
#include "wnauth.h"

extern char *optarg;
extern int optind;

extern char	*crypt(),
		*getenv();

static char	group[MIDLEN],
		realm[SMALLLEN],
		*group_list[MAXGROUPS + 1];


static void	chopws(),
		authwn_timeout(),
		encode(),
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

int
main( argc, argv)
int	argc;
char	*argv[];

{
	register char	*cp;


	char	*user,
		*password,
		pwfile[2*SMALLLEN],
		grpfile[2*SMALLLEN],
		authdata[MIDLEN + 2*SMALLLEN],
		buf[SMALLLEN],
		*decoded;

	int	c,
		i;

	signal( SIGALRM, authwn_timeout);
	alarm( AUTHWN_TIMEOUT);

	grpfile[0] = pwfile[0] = auth_logfile[0] = '\0';
	while ((c = getopt(argc, argv, "Dg:G:l:nNP:")) != -1) {
		switch ((char) c) {
		case 'D':
			isdbm = TRUE;
			break;

		case 'l':
			mystrncpy( auth_logfile, optarg, SMALLLEN);
			break;

		case 'g':
			mystrncpy( group, optarg, MIDLEN);
			cp = group;
			i = 0;
			while ( *cp && (i < MAXGROUPS)) {
				while ( isspace( *cp))
					cp++;
				group_list[i++] = cp;
				while ( *cp && !isspace( *cp))
					cp++;
				if ( *cp)
					*cp++ = '\0';
			}
			group_list[i] = NULL;
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
		}
	}

	if ( argv[optind] && (!*pwfile)) {
		mystrncpy( pwfile, argv[optind], SMALLLEN);
	}

	if ( !*pwfile && !nis_id) {
		log_auth( authlog_m[7], NULL);
		exit( AUTHERR_NUM7);

	}

	if ( *pwfile)
		getpath( pwfile, pwfile);
	if ( *grpfile)
		getpath( grpfile, grpfile);

	if ( fgets( authdata, SMALLLEN, stdin) == NULL) {
		log_auth( authlog_m[10], NULL);
		exit( AUTHERR_NUM10);
	}

	chopws( authdata);
	/* should now contain "Basic user:password" */

	cp = authdata;
	while ( isspace( *cp))
		cp++;
	while ( *cp && !isspace( *cp))
		cp++;
	*cp++ = '\0';

	while ( isspace( *cp))
		cp++;

	decoded = cp;

	if ( (cp = strchr( decoded, ':')) == NULL ) {
		log_auth( authlog_m[3], decoded);
		exit( AUTHERR_NUM3);
	}

	*cp = '\0';
	user = decoded;
	password = ++cp;

	mystrncpy( buf, user, SMALLLEN);
	mystrncat( buf, ":", SMALLLEN);

	if ( checkpw( user, password, pwfile, grpfile) ) {
		mystrncat( buf, realm, SMALLLEN);
		bzero( authdata, sizeof( authdata));
		log_auth( authlog_m[0], buf);
		exit( AUTH_GRANTED);
	}
	else {
		mystrncat( buf, realm, SMALLLEN);
		bzero( authdata, sizeof( authdata));
		log_auth( authlog_m[1], buf);
		exit( AUTH_DENIED);
	}
}

static int
checkpw( user, pw, pwpath, grppath)
char	*user,
	*pw,
	*pwpath,
	*grppath;
{
	register char	*cp,
			*cp2;
	char		*salt,
			codedpw[SMALLLEN],
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

	if ( !isdbm) {
		int n = (sizeof( WN_REALM_DESIGNATOR) - 1);

		if (nis_id) {
			passwd = getpwnam (user);
			if (passwd == NULL)
				exit (AUTHERR_NUM4);

			mystrncpy (codedpw, passwd->pw_passwd, SMALLLEN);
			goto check;
		}


		if ( ( pwfp = fopen( pwpath, "r")) == (FILE *)NULL) {
			log_auth( authlog_m[4], pwpath);
			exit( AUTHERR_NUM4);
		}

		fgets( linebuf, SMALLLEN, pwfp);
		realm[0] = '\0';
		if ( strncasecmp( WN_REALM_DESIGNATOR, linebuf, n) == 0 ) {
			mystrncpy( realm, linebuf + n, SMALLLEN);
			if ( (cp = strchr( realm, ':')) != NULL )
				*cp ='\0';
			linebuf[0] = '\0';
		}
		do {
			if ( (cp = strchr( linebuf, ':')) == NULL )
				continue;
			*cp++ = '\0';
			if ( streq( linebuf, user)) {
				if (nis_pw) {
					passwd = getpwnam (user);
					if (passwd == NULL)
						exit (AUTHERR_NUM4);
					mystrncpy (codedpw, passwd->pw_passwd,
								SMALLLEN);
					break;
				}

				if ( (cp2 = strchr( cp, ':')) != NULL )
					*cp2 = '\0';
				mystrncpy( codedpw, cp, SMALLLEN);
				chopws( codedpw);
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
			exit( AUTHERR_NUM5);
		}

		content = dbm_fetch( mydb, key);
		if ( (content.dptr != (char *)NULL) && (content.dsize < SMALLLEN)) {
			strncpy( codedpw, content.dptr, content.dsize);
			codedpw[content.dsize] = '\0';
		}
		else {
			log_auth( authlog_m[18], NULL);
			exit( AUTHERR_NUM18);
		}
		dbm_close( mydb);
#else
		log_auth( authlog_m[8], NULL);
		exit( AUTHERR_NUM8);
#endif
	}

	if ( grppath && *grppath ) {
		int i;

		if ( (grfp = fopen( grppath, "r")) == (FILE *)NULL) {
			log_auth( authlog_m[6], grppath);
			exit( AUTHERR_NUM6);
		}

		found = FALSE;

		while ( fgets( linebuf, GROUPLEN, grfp)) {
			if ( (cp = strchr( linebuf, ':')) == NULL )
				continue;
			*cp++ = '\0';
			i = 0;
			while ( group_list[i] ) {
				if ( streq( linebuf, group_list[i])) {
					chopws( cp);
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
			return FALSE;
		}
	}
  check:
	/* If len of codedpw < 20 or it starts with $, it's made with crypt */
	/* Use salt in that case */

	if ( (strlen( codedpw) < 20) || (*codedpw == '$'))
		salt = codedpw;
	else
		salt = NULL;

	encode( cbuf, user, pw, salt);

	if ( *codedpw && strcmp( codedpw, cbuf) == 0 )
		return TRUE;
	else
		return FALSE;
}

/*
 * mkdigest( out, in, in_len) takes the string "in" and calculates the MD5
 * digest placing the result in "out"
 */

static void 
mkdigest (out, in, in_len)
char	*out,
	*in;
unsigned in_len;
{
	unsigned i;
	MD5_CTX context;
	unsigned char digest[16];
	char buf[MIDLEN];

	if ( in_len >= MIDLEN) {
		log_auth( authlog_m[15], NULL);
		exit( AUTHERR_NUM3);
	}

	for ( i = 0; i < in_len; i++) {
		buf[i] = in[i];
	}
	buf[in_len] = '\0';

	MD5_Init (&context);
	MD5_Update (&context, buf, in_len);
	MD5_Final (digest, &context);

	for ( i = 0; i < 16; i++) {
		sprintf( out, "%02x", digest[i]);
		out += 2;
	}
	bzero( buf, in_len);
}


/*
 * static encode( char *buf, char *user, char *pw, char *salt)
 * Encode pw with either MD5 or crypt().  Use salt with crypt().
 * Place result in buf[SMALLLEN].
 */

static void
encode(  buf, user, pw, salt)
char	*buf,
	*user,
	*pw,
	*salt;

{
	int len;
	char lbuf[MIDLEN];

	if ( salt ) {
		mystrncpy( buf, (char *) crypt( pw, salt), SMALLLEN);
		return;
	}


	mystrncpy( lbuf, user, SMALLLEN);
	mystrncat( lbuf, ":", MIDLEN);
	mystrncat( lbuf, realm, MIDLEN);
	mystrncat( lbuf, ":", MIDLEN);
	mystrncat( lbuf, pw, MIDLEN);
	len = strlen( lbuf);
	mkdigest( buf, lbuf, len);
	bzero( lbuf, len);
	return ;
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

/* 
 * static void chopws( char *line) 
 * Removes any trailing white space or \n from the end of a line 
 */

static void
chopws( line)
char *line;
{
	register char	*cp;

	if ( *line == '\0')
		return;
	cp = line;
	while ( *cp )
		cp++;
	cp--;
	while ( isspace( *cp ) ) {
		*cp-- = '\0';
		if ( cp < line)
			break;
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
 * static int mystrncpy( s1, s2, n) is a strncpy() which guarantees a null
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
	exit( AUTHERR_NUM16);
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
