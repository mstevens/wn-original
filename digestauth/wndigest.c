/*
    WNDigest
    File digestauth/wndigest.c
    Version 1.3
    
    Usage: wndigest [-r realm] [-d domain] [-t time] [-D] [-p pwfile]
           [-s true|false] [-x debugfile]

    If run with the "-s" option this program produces a valid 
    "WWW-Authenticate: Digest..." header and writes it to stdout.
    The value of the "stale" field in this header is the value of the
    -s option.  

    If run without the -s option this program expects to read a
    valid digest "Authorization:" header on standard input.  It
    checks the validity of the response based on entries in the
    password file "pwfile" and exits with status AUTH_GRANTED,
    AUTH_DENIED, AUTH_EXPIRED, or a status indicating an error 
    condition.  The numeric values of these constants are listed
    in wndidest.h

    This program is free software; you can redistribute it and/or modify
    it in any way you choose.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#define VERSION		"WNDigest/1.2c"
#define WNDIGEST_TIMEOUT	(60)
#define QOP_VALUE	"auth"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/signal.h>
#include <time.h>


#ifdef DBM_AUTH
#include <ndbm.h>
#endif /* DBM_AUTH */

#include "../config.h"
#include "global.h"
#include "md5.h"
#include "wndigest.h"
#include "random.h"


#ifdef DBM_AUTH
extern datum	dbm_fetch();
extern DBM	*dbm_open();
#endif


static char	*acopy(),
		*mystrncpy(),
		*mystrncat(),
		domain[MIDLEN],
		pwfile_name[SMALLLEN],
		debugfile[SMALLLEN],
		method[TINYLEN],
		base64md5[TINYLEN],
		myrealm[SMALLLEN];

static time_t	curtime;

static void	*passwd_fp,
		chop(),
		getpath(),
		authwn_timeout(),
		send_auth(),
		parse_auth(),
		mkdigest(),
		get_user_pw(),
		mknonce();

static int	checkresponse(),
		checknonce();

static long	tsvalid = 10;

extern int optind;

extern char	*optarg,
		*getenv();

extern time_t	time();
extern long	atol();

static char	authstr[MIDLEN];


int		isdbm = FALSE;

#ifdef DEBUG
int		debug = TRUE;
time_t		wnclock;
FILE		*efp;
#endif

int
main( argc, argv)
int	argc;
char	*argv[];

{
	int	c,
		errflg = 0,
		stale = FALSE,
		do_send = FALSE;

	AuthData	authdata;

	signal( SIGALRM, authwn_timeout);
	alarm( WNDIGEST_TIMEOUT);

	*authstr = '\0';

	domain[0] = myrealm[0] = '\0';

	while ((c = getopt(argc, argv, "Dd:p:r:s:t:x:")) != -1) {
		switch ( c) {
			case 'D':
				isdbm =  TRUE;
				break;
			case 'd':
				mystrncpy( domain, optarg, MIDLEN);
				break;
			case 'p':
				getpath( pwfile_name, optarg);
				break;
			case 'r':
				mystrncpy( myrealm, optarg, SMALLLEN);
				break;
			case 's':
				do_send = TRUE;
				stale = (tolower(*optarg) == 't' 
						? TRUE : FALSE);
				break;
			case 't':
				tsvalid = atol( optarg);
				if ( tsvalid < 0 )
					tsvalid = 0;
				break;

#ifdef DEBUG
			case 'x':
				mystrncpy( debugfile, optarg, SMALLLEN);
				debugfile[SMALLLEN-1] = '\0';
				debug = TRUE;
				umask( 0);
				if ( streq( debugfile, ""))
					efp = stderr;
				else if ( (efp = fopen( debugfile, "a"))
							== (FILE *)NULL)
					efp = stderr;
				time( &wnclock);
				fprintf( efp, "\n**** %s****\n",
						asctime( localtime(&wnclock)));
				break;
#endif
			default:
				errflg++;
		}
	}

	if (errflg ) {
		exit ( AUTHERR_NUM12);
	}

	if ( do_send) { 
		/* Send WWW-Authenticate header line to stdout */
		send_auth( stale);
		exit( 0);
	}
	else {
		parse_auth( &authdata);
		if ( !checknonce( &authdata)) {
			if ( checkresponse( &authdata, pwfile_name) )
				exit( AUTH_EXPIRED);
			else
				exit( AUTH_DENIED);
		}	
	}

	if ( checkresponse( &authdata, pwfile_name) ) {
		exit( AUTH_GRANTED);
	}
	else {
		exit( AUTH_DENIED);
	}
}

static void
parse_auth( aptr)
AuthData	*aptr;
{
	char	*cp;

	bzero( (char *) aptr, sizeof( AuthData));
	base64md5[0] = '\0';

	if ( (cp = getenv( "REQUEST_METHOD")) == NULL)
		exit( AUTHERR_NUM13);
	
	mystrncpy( method, cp, TINYLEN);

	if ( (cp = getenv( "HTTP_AUTHORIZATION")) == NULL)
		exit( AUTHERR_NUM10);
	
	mystrncpy( authstr, cp, MIDLEN);
	if ( (cp = getenv( "CONTENT_MD5")) != NULL) {
		mystrncpy( base64md5, cp, TINYLEN);
	}

#ifdef DEBUG
	if ( debug) {
		if ( (cp = getenv( "REMOTE_ADDR")) != NULL)
			fprintf( efp, "Remote Address = %s\n", cp);
		fprintf( efp, "Remote Auth header = %s\n", authstr);
		fprintf( efp, "Base 64 MD5 = %s\n", base64md5);
		fflush( efp);
	}
#endif

	if ( strncasecmp( authstr, "Digest", 6)) {
		exit( AUTHERR_NUM9);
	}
	cp = authstr;

	while ( *cp && !isspace(*cp))
		cp++;

	while ( *cp ) {
		while ( isspace( *cp) || (*cp == ','))
			cp++;
		if ( strncasecmp( cp, "realm", 5) == 0 ) {
			cp = acopy( aptr->realm, cp, SMALLLEN);
			continue;
		}
		if ( strncasecmp( cp, "nonce", 5) == 0 ) {
			cp = acopy( aptr->nonce, cp, SMALLLEN);
			continue;
		}
		if ( strncasecmp( cp, "cnonce", 6) == 0 ) {
			cp = acopy( aptr->cnonce, cp, SMALLLEN);
			continue;
		}
		if ( strncasecmp( cp, "qop", 3) == 0 ) {
			cp = acopy( aptr->qop, cp, SMALLLEN);
			continue;
		}
		if ( strncasecmp( cp, "nc", 2 ) == 0 ) {
			cp = acopy( aptr->nonce_count, cp, TINYLEN);
			continue;
		}
		if ( strncasecmp( cp, "uri", 3) == 0 ) {
			cp = acopy( aptr->uri, cp, MIDLEN);
			continue;
		}
		if ( strncasecmp( cp, "username", 8) == 0 ) {
			cp = acopy( aptr->username, cp, SMALLLEN);
			continue;
		}
		if ( strncasecmp( cp, "algorithm", 9) == 0 ) {
			cp = acopy( aptr->algorithm, cp, SMALLLEN);
			continue;
		}
		if ( strncasecmp( cp, "message", 7) == 0 ) {
			cp = acopy( aptr->message, cp, SMALLLEN);
			continue;
		}
		if ( strncasecmp( cp, "response", 8) == 0 ) {
			cp = acopy( aptr->response, cp, SMALLLEN);
			continue;
		}
		if ( strncasecmp( cp, "opaque", 6) == 0 ) {
			cp = acopy( aptr->opaque, cp, SMALLLEN);
			continue;
		}
		cp++;
	}
	if ( (*aptr->algorithm) && 
			(strcasecmp( aptr->algorithm, "MD5") != 0) ) {
#ifdef DEBUG
		if ( debug) {
			fprintf( efp, "Unknown algorithm = %s\n",
					aptr->algorithm);
			fflush( efp);
		}
#endif
		exit( AUTHERR_NUM15);
	}	
}

static char
*acopy( s1, ptr, len)
char	*s1,
	*ptr;
int	len;
{
	register char	*cp,
			*cp2;

	if ( (cp = strchr( ptr, '=')) == NULL)
		exit( AUTHERR_NUM3);

	cp++;
	while ( isspace( *cp))
		cp++;
	if ( *cp == '\"') {		/* A quoted string */
		if ( (cp2 = strchr( ++cp, '\"')) == NULL)
			exit( AUTHERR_NUM3);
		*cp2 = '\0';
		mystrncpy( s1, cp, len);
		return (++cp2);
	}
	else {
		len--;
		while ( *cp && !isspace( *cp) && (*cp != ',') && (len > 0) ) {
			len--;
			*s1++ = *cp++;
		}
		*s1 = '\0';
		if ( *cp )
			*cp++ = '\0';
		return ( cp);
	}
}
	
		

static void
send_auth( stale )
int	stale;
{
	unsigned long	ts,
			rem;
	int		percent;

	char		timestamp[SMALLLEN],
			nonce[SMALLLEN];

#ifdef DEBUG
	if ( debug) {
		fprintf( efp, "Sending WWW-Authenticate header\n");
		fflush( efp);
	}
#endif
	time( &curtime);
	if ( tsvalid == 0) {
		strcpy( timestamp, "forever");
		percent = 0;
	}
	else {
		ts = ((unsigned long) curtime)/ tsvalid;
		rem = ((unsigned long) curtime) % tsvalid;
		percent = (int) (256 * rem)/tsvalid;
		sprintf( timestamp, "%ld", ts);
	}

	mknonce( timestamp, nonce, percent);

	printf( "WWW-Authenticate: Digest realm=\"%s\", ", myrealm);
	printf( "domain=\"%s\", ", domain);
	printf( "nonce=\"%s\", ", nonce);
	printf( "qop=\"%s\", ", QOP_VALUE);
	printf( "opaque=\"%s\", ", VERSION);
	printf( "algorithm=\"%s\", ", "MD5");
	printf( "stale=\"%s\"\r\n", ( stale ? "TRUE" : "FALSE"));
#ifdef DEBUG
	if ( debug) {
		fprintf( efp, "WWW-Authenticate: Digest realm=\"%s\", ",
				myrealm);
		fprintf( efp, "domain=\"%s\", ", domain);
		fprintf( efp, "nonce=\"%s\", ", nonce);
		fprintf( efp, "qop=\"%s\", ", QOP_VALUE);
		fprintf( efp, "algorithm=\"%s\", ", "MD5");
		fprintf( efp, "stale=\"%s\"\r\n", ( stale ? "TRUE" : "FALSE"));
		fprintf( efp, "Finished authorization request\n\n");
		fflush( efp);
	}
#endif
}

/* 
 *
 * Here is the idea of how nonce timestamps work.  The nonce sent to the
 * client is really not an MD5 digest, but an MD5 digest with two
 * additional bytes tacked on.  The last two bytes indicate the fraction
 * (in 256ths) of a time stamp period that has passed.  Let me give an
 * example in decimal rather than hex (in fact originally I did this in
 * decimal and then it really was "percent").  Suppose the period of
 * validity is 100 seconds and the Unix date in seconds was 12345.  Then
 * we use only the 123 as the timestamp and calculate the nonce which is
 * a hash of the timestamp plus other stuff -- say it is "abab".  Then we
 * append the 45 to get "abab45" and this is what we will send to the
 * client. (That's why there are 34 bytes, not 32 which MD5 produces).
 * 
 * When we get the request from the client including our nonce we again
 * check the time and we have to decide if 100 seconds has passed.  For
 * example, it is fine if the time is 12377 or 12422, but 12455 is no
 * good.  So we look at the last two digits of this current time and see
 * how they compare to 45 which was the last two digits of the original
 * issuing time.  If the new two-digit end is > 45 we know that if we are
 * still in the 100 sec time frame the original timestamp had to be the
 * same as the first n-2 digits of the current time.  And if the last two
 * digits of the orig are < the last two digits of the current time then
 * the orignial timestamp must have been one less than the first n-2
 * digits of the current time.
 * 
 * Thus if we get the request at 12377 we know the timestamp (if valid)
 * was 123 and that is what we test.  Likewise if we get 12422, since
 * 22 < 45 the timestamp must have been 124-1 = 123.  If we get 12455 then
 * we assume the timestamp was 124 (since 55 > 45) but testing that (by
 * recalculating the nonce using this value as timestamp) will fail so we
 * conclude the time has expired. (Or it could be that someone tampered with
 * the nonce.)
 * 
 * Of course, the time period doesn't have to be 100 seconds, we just
 * calculate the percentage of the time period which has passed and use
 * that (using 256 not 100).  The calculation from wndigest.c is
 * 
 * 		ts = ((unsigned long) curtime)/ tsvalid;
 * 		rem = ((unsigned long) curtime) % tsvalid;
 * 		percent = (int) (256 * rem)/tsvalid;
 * 
 * where ts = timestamp (in units of tsvalid seconds), 
 *       tsvalid = period of validity (in seconds)
 *       rem = remainder of ts/tsvalid
 *       percent = fraction of the current period which has passed (in 256ths).
 *
 */





static int
checknonce( aptr )
AuthData	*aptr;
{
	unsigned long	ts,
			rem;
	int		percent,
			rempercent;

	int		len;
	char		timestamp[SMALLLEN],
			nonce_chk[SMALLLEN];

	if ( tsvalid == 0) {
		strcpy( timestamp, "forever");
		rempercent = percent = 0;
	}
	else {
		time( &curtime);
		ts = ((unsigned long) curtime)/ tsvalid;
		rem = ((unsigned long) curtime) % tsvalid;
		percent = (int) (256 * rem)/tsvalid;

		len = strlen( aptr->nonce);

		if ( len < 2 )
			exit( AUTHERR_NUM3);

		rempercent = strtol( aptr->nonce + len - 2, NULL, 16);

		if ( rempercent > percent )
			ts--;
		sprintf( timestamp, "%ld", ts);
	}

	mknonce( timestamp,  nonce_chk, rempercent);
#ifdef DEBUG
	if ( debug) {
		fprintf( efp, "Remote nonce = %s\n", aptr->nonce);
		fprintf( efp, "Calculated nonce = %s\n\n", nonce_chk);
		fflush( efp);
	}
#endif

	return  streq( nonce_chk, aptr->nonce);
}


/*
 * mknonce() composes the string "RANDOMKEY:tstamp:percent:myrealm" and 
 * calculates the MD5 digest placing it in output.  If tsvalid > 0
 * (i.e. we are using a timestamp) the two HEX digits of "percent"
 * are appended to the end of the digest string pointed to by op.
 */
static void
mknonce( tstamp,  output, percent)
char	*tstamp,
	*output;
int	percent;
{
	char	*cp,
		*randkey,
		buf[SMALLLEN],
		srealm[SMALLLEN],
		prenonce[MIDLEN];

	randkey = RANDOMKEY;
	if ( myrealm[0] == '\0') {
		get_user_pw( WN_REALM_NAME, buf);
		if ( ( cp = strchr( buf, ':')) == NULL) 
			exit( AUTHERR_NUM17);
		*cp = '\0';
		randkey = ++cp;
		mystrncpy( srealm, buf, SMALLLEN);
		mystrncpy( myrealm, buf, SMALLLEN);
	}
	else {
		mystrncpy( srealm, myrealm, SMALLLEN);  /* chop a really long realm */
	}
	sprintf( prenonce, "%s:%s:%02x:%s", randkey, tstamp, percent, srealm);
	mkdigest( prenonce, output);

	if ( tsvalid != 0 )
		sprintf( output + strlen(output), "%02x", percent);

#ifdef DEBUG
	if ( debug) {
		fprintf( efp, "prenonce = %s\n", prenonce);
		fflush( efp);
	}
#endif
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

	MD5Init (&context);
	MD5Update (&context, in, strlen( in));
	MD5Final (digest, &context);

	for ( i = 0; i < 16; i++) {
		sprintf( out, "%02x", digest[i]);
		out += 2;
	}
}


/*
 * checkresponse( aptr, pwfile)  gets the client supplied auth data
 * from the struct pointed to by "aptr" and checks its validity using
 * the password file whose path is pointed to by "pwfile".
 */
static int
checkresponse( aptr, pwfile)
AuthData	*aptr;
char		*pwfile;
{
	char		*user,
			coded_a2[SMALLLEN],
			buf[MIDLEN],
			codedpw[SMALLLEN],
			our_response[SMALLLEN];


#ifdef DEBUG
	if ( debug) {
		fprintf( efp, "Checking response\n");
		fflush( efp);
	}
#endif
	user = aptr->username;
	get_user_pw( user, codedpw);

#ifdef DEBUG
	if ( debug) {
		fprintf( efp, "user = %s\nH(A1) = %s\n", user, codedpw);
		fflush( efp);
	}
#endif

	sprintf( buf, "%s:%s", method, aptr->uri);
	mkdigest( buf, coded_a2);

#ifdef DEBUG
	if ( debug) {
		fprintf( efp, "A2 = %s\nH(A2) = %s\n", buf, coded_a2);
		fflush( efp);
	}
#endif
	if ( !*aptr->qop) {
		sprintf( buf, "%s:%s:%s", codedpw, aptr->nonce, coded_a2);
	}
	else {
		sprintf( buf, "%s:%s:%s:%s:%s:%s",
			codedpw, aptr->nonce, aptr->nonce_count,
			aptr->cnonce, aptr->qop, coded_a2);
	}
	mkdigest( buf, our_response);

#ifdef DEBUG
	if ( debug) {
		fprintf( efp, "H(A1):N:NC:CN:QOP:H(A2) = %s\n", buf);
		fprintf( efp, "Calculated digest = %s\n", our_response );
		fprintf( efp, "Client's   digest = %s\n", aptr->response );
		fflush( efp);
	}
#endif

	if (  streq( aptr->response, our_response))
		return TRUE;
	else
		return FALSE;
}




/* 
 * get_user_pw( user, pwp) opens password file pwfile_name,
 * looks for user and copies the corresponding password to 
 * the array pointed to by pwp.  This array must have size 
 * SMALLLEN.  If user is not found then the empty string is 
 * returned.
 */

static void
get_user_pw( user, pwp)
char		*user,
		*pwp;
{
	register char	*cptr;

	char		linebuf[SMALLLEN];

	FILE		*pwfp;


#ifdef DBM_AUTH
	DBM		*dbmp;
	datum		content,
			key;
#endif

	*pwp = '\0';

	if ( !isdbm) {
		if ( passwd_fp != NULL) 
			pwfp = (FILE *)passwd_fp;
		else if ( ( pwfp = fopen( pwfile_name, "r")) == (FILE *)NULL)
			exit( AUTHERR_NUM4);
		passwd_fp = (void *) pwfp;

		while ( fgets( linebuf, SMALLLEN, pwfp)) {
			if ( (cptr = strchr( linebuf, ':')) != NULL ) {
				*cptr++ = '\0';
			}
			else {
				continue;
			}
			if ( strcmp( linebuf, user) == 0) {
				mystrncpy( pwp, cptr, SMALLLEN);
				chop( pwp);
				break;
			}
		}
	}
	else {
#ifdef DBM_AUTH

		key.dptr = user;
		key.dsize = strlen(user);

		if ( passwd_fp != NULL) 
			dbmp = ( DBM *) passwd_fp;
		if ( dbmp = dbm_open( pwfile_name, O_RDONLY, 0) <= 0 )
			exit(AUTHERR_NUM5);
		passwd_fp = (void *) dbmp;

		content = dbm_fetch( dbmp, key);
		if ( content.dptr != NULL) {
			mystrncpy( pwp, content.dptr, SMALLLEN);
			codedpw[content.dsize] = '\0';
		}
#else
		exit( AUTHERR_NUM8);
#endif
	}
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
	char	*cp;

	if ( *file == '/') {
		mystrncpy( path, file, SMALLLEN);
		return;
	}
	if ( *file == '~' && *(file + 1) == '/') {
		mystrncpy( path, ROOT_DIR, 3*SMALLLEN/4 );
		mystrncat( path, ++file, SMALLLEN/4);
		return;
	}
	if ( (cp = getenv( "WN_DIR_PATH")) == NULL ) {
		mystrncpy( path, file, SMALLLEN);
		return;
	}
		
	mystrncpy( path, cp, 3*SMALLLEN/4 );
	strcat( path, "/");
	mystrncat( path, file, (SMALLLEN/4) - 1);
}

/*
 * mystrncpy( s1, s2, n) is an strncpy() which guarantees a null
 * terminated string in s1.  At most (n-1) chars are copied.
 */

static char *
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
	return s1;
}


/*
 * mystrncat( s1, s2, n) is an strncat() which guarantees a null
 * terminated string in s1.  At most (n-1) chars are appended.
 */

static char *
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

	while ( *cp1)
		cp1++;

	while ( *cp2 && (n > 0)) {
		n--;
		*cp1++ = *cp2++;
	}
	*cp1 = '\0';
	return s1;
}

static void
authwn_timeout()
{
	signal( SIGALRM, SIG_DFL);
	exit( AUTHERR_NUM16);
}
