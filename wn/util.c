/*
    Wn: A Server for the HTTP
    File: wn/util.c
    Version 2.4.6

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
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <grp.h>
#include <errno.h>
#include "wn.h"
#include "../md5/md5.h"

extern	char	*inet_ntoa();

extern void	www_unescape();

static struct in_addr		ip_address;

#ifdef RFC931_TIMEOUT
extern void		rfc931();

static struct WN_SOCKADDR_TYPE	*mysin,
				*remsin;
#endif

#if WN_SU_EXEC
static void mk_md5digest ();
char suexec_key[SUEXEC_KEYLEN + 1];
#endif /* WN_SU_EXEC */

/*
 * get_remote_ip() gets IP address of client via getpeername call and
 * puts it in  this_conp->remaddr.
 */

void
get_remote_ip( )
{
	static struct sockaddr_in	saddr;
	int			size;

	size = sizeof(saddr);
	if ( getpeername(fileno(stdin), (struct sockaddr *) &saddr, &size)< 0){
		*this_conp->remaddr = '\0';
		*this_conp->remport = '\0';
		*this_conp->remotehost = '\0';
		if (!isatty(fileno(stdin)))
			logerr(  err_m[48], "");
		return;
	}

	ip_address = saddr.sin_addr;
	mystrncpy(this_conp->remaddr, inet_ntoa(ip_address), 20);
	Snprintf1(this_conp->remport, 16, "%hu", ntohs(saddr.sin_port));

#ifdef RFC931_TIMEOUT
	remsin = (struct WN_SOCKADDR_TYPE *)&saddr;
#endif
}



/*
 * get_remote_info() does DNS lookup of remotehost and places host name
 * in this_conp->remotehost. If possible the call to this function
 * happens after the entire transaction is complete so the user
 * doesn't have to wait for these lookups to happen.  This delay
 * is not possible for CGI or when doing authentication. 
 * 
 */

void
get_remote_info( )
{
	char    dot_name[2*SMALLLEN];
	struct hostent	*hostentp = NULL;
	unsigned	llogtype;

	if ( *this_conp->remotehost )
		return;
	if ( !*this_conp->remaddr ) {
		mystrncpy( this_conp->remotehost, "unknown", MAXHOSTNAMELEN);
		return;
	}
	
	/* if (*this_conp->remotehost) we have already got info;
	   if (!*this_conp->remaddr) then there is no hope
	    -- we can't even get IP address */

	llogtype = ( dir_p->logtype ? dir_p->logtype : default_logtype);

	if ( llogtype & NO_DNS_LOG) {
		mystrncpy( this_conp->remotehost, this_conp->remaddr, 
						MAXHOSTNAMELEN);
		return;
	}

	hostentp = gethostbyaddr((char *) &ip_address.s_addr,
			sizeof (ip_address.s_addr), AF_INET);
	if (hostentp) {
		mystrncpy( this_conp->remotehost, hostentp->h_name, MAXHOSTNAMELEN);

		/* Check that the name has this address listed. */
			/* Assume ok unless unless REV_DNS_LOG requested */
		if ( !(llogtype & REV_DNS_LOG) ) {
			strlower( this_conp->remotehost);
			return;
		}


		if (strlen( this_conp->remotehost) >= MAXHOSTNAMELEN) {
			hostentp = gethostbyname( this_conp->remotehost);
		} else {
			fmt2(dot_name, (MAXHOSTNAMELEN + 2),
					this_conp->remotehost, ".");
			hostentp = gethostbyname( dot_name);
		}

		if (hostentp) {
			register char **ap;
			for (ap = hostentp->h_addr_list; *ap; ap++) {
				if (!memcmp( (char *) &ip_address.s_addr,
						*ap, hostentp->h_length)) {
					/*  this_conp->remotehost is ok.*/
					strlower( this_conp->remotehost);
					return;
				}
			}
		}
		/* No good name found */
		*this_conp->remotehost = '\0';
	}

	if ( !*this_conp->remotehost )
		mystrncpy( this_conp->remotehost, this_conp->remaddr, 
						MAXHOSTNAMELEN);
}


#ifdef RFC931_TIMEOUT
void
get_rfc931()
{
	if ( this_conp->con_status & WN_CON_TIMEDOUT)
		return;
	if ( *this_conp->rfc931name != '\0')
		return;
	if ( remsin && mysin )
		rfc931(remsin, mysin, this_conp->rfc931name);
}
#endif


/*
 * mystrncpy( s1, s2, n) is an strncpy() which guarantees a null
 * terminated string in s1.  At most (n-1) chars are copied.
 * Returns -1 if truncation occurred and (n-1) minus number of
 * bytes copied otherwise.
 */

int
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
		logerr( err_m[128], s1);
		return (-1);
	}
	return (n);
}

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
mystrncat( char *s1, char *s2, int len)
char	*s1,
	*s2;
int	len;

   mystrncat has been replaced by the macro fmt3( s1, len, s1, s2, NULL)

*/


/* Just like mystrncat, but no errors logged */
int
mystrncat2( s1, s2, n)
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

/*
 * fmt3( buf, maxlen, s1, s2, s3) concatenates s1, s2, s3 in buf and
 * guarantees a null terminated string.  At most (maxlen-1) chars TOTAL are
 * in the concatenated string.  Returns -1 if truncation occurred and
 * (maxlen-1) minus number of bytes in new buf otherwise.  It will do the
 * right thing if buf == s1, i.e. append s2 and s3.  If any of 
 * s1, s2, or s3 are NULL they are skipped.
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
		logerr( err_m[128], buf);
		return (-1);
	}
	else
		return (maxlen);

}

/*
 * fmt2( buf, maxlen, s1, s2) concatenates s1, s2 in buf and
 * guarantees a null terminated string.  At most (n-1) chars TOTAL are
 * in the concatenated string.  Returns -1 if truncation occurred and
 * (n-1) minus number of bytes in new buf otherwise.  It will do the
 * right thing if buf == s1.
 */

/*
int
fmt2( buf, maxlen, s1, s2)
char *buf;
int maxlen;
char	*s1,
	*s2;
   replaced by macro fmt3( buf, maxlen, s1, s2, NULL)
*/

char *
mymemcpy( p1, p2, n)
char	*p1,
	*p2;
int	n;
{
	if ( p1 == p2)
		return (p1);
	while ( n > 0 ) {
		n--;
		*p1++ = *p2++;
	}
	return (p1);
}

/*
 * chop( line)  Cut out CRLF at end of line, or just LF.  Return TRUE
 * if there is a LF at end, otherwise FALSE.
 */

int
chop( line)
char *line;
{
	register char	*cp;

	if ( *line == '\0')
		return FALSE;
	cp = line;
	while ( *cp )
		cp++;
	if ( *--cp == '\n') {
		*cp = '\0';
		if ( (cp > line) && *--cp == '\r')
			*cp = '\0';
		return TRUE;
	}
	return FALSE;
}


/*
 * safer_popen( command, args) calls popen after checking that "args"
 * are safe to pass to a shell.  First the URL escapes in args are decoded.
 * To pass muster decoded args must contain only alphanumerics or SPACE,
 * '/', '.', '%', '@' or '_'.  If '\r' or '\n' are encountered then args is
 * truncated at that point.  If args fails to pass the test then NULL
 * returned.  Otherwise a FILE* for the popened command is returned.
 */

FILE *
safer_popen( command, args)
char	*command,
	*args;
{
	register char	*cp,
			*cp2;

	char		*argptr,
			buf[2*MIDLEN],
			buf2[MIDLEN];

	mystrncpy( buf, command, MIDLEN);
	argptr = buf + strlen( buf);

	if ( ! WN_SU_EXEC) {
		if ( (cp = strrchr( buf, '/')) != NULL)  {
			*cp = '\0';
			if ( chdir( buf) != 0  ) {
				logerr( err_m[106], buf);
			}
			*cp = '/';
		}
	}

	mystrncpy( buf2, args, MIDLEN);

	www_unescape( buf2, ' '); /* Change '+' to space and */
					  /* handle URL escapes */


	cp = buf2;
	if ( *cp) {
		cp2 = argptr;
		*cp2++ = ' ';
		while ( *cp != '\0') {
			switch (*cp) {
				case	'\n':
				case	'\r':
					*cp = *cp2 = '\0';
					break;

				case '/':
				case ' ':
				case '_':
				case '@':
				case '.':
				case '%':
					*cp2++ = *cp++;
					break;
				default:
				/* Anything else should be alphanumeric */
					if ( !isalnum( *cp)) {
						Snprintf1( buf, SMALLLEN,
								err_m[96], *cp);
						logerr( buf, this_rp->request);
						return (NULL);
					}

					*cp2++ = *cp++;
					break;
			}
		}
		*cp2 = '\0';
	}
	else
		mystrncpy( buf, command, MIDLEN);

	return (WN_popen( buf, "r"));
}

/*
 * void sanitize( p1, p2, maxlen)  Copy p2 to p1 until p2 is
 * exhausted or (at most) maxlen - 1 characters are transfered.
 * Change all suspect characters to ' ',  Suspect means anthing
 * except alphanumeric, '.', '@', '/', ':',  or '-'.
 */

void
sanitize( p1, p2, maxlen)
char	*p1,
	*p2;
long	maxlen;
{
	register char *cp;

	mystrncpy( p1, p2, maxlen);
	
	cp = p1;
	while ( *cp ) {
		if ( myisalnum( *cp)) {
			cp++;
			continue;
		}
		switch ( *cp) {
		case '.':
		case '-':
		case ':':
		case '/':
		case '@':
			cp++;
			break;
		default:
			*cp++ = ' ';
		}
	}
}

/*
 * int amperline( p1, p2, maxlen)  Copy p2 to p1 until p2 is
 * exhausted or (at most) maxlen - 1 characters are transfered.
 * Encode '<', '>', and & as "&lt;", etc.  Return TRUE if any
 * of these characters are found, otherwise FALSE
 */

int
amperline ( p1, p2, maxlen)
char	*p1,
	*p2;
long	maxlen;
{
	register char *cp;
	int found = FALSE;

	maxlen--;
	while ( *p2 ) {
		if ( --maxlen < 5 ) {
			logerr( err_m[130], "");
			break;
		}
		switch( *p2) {
		case '<':
			found = TRUE;
			strcpy( p1, "&lt;");
			maxlen -= 3;
			p1 += 4;
			p2++;
			break;
		case '>':
			found = TRUE;
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
				found = TRUE;
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
	return found;
}


/*
 * get_local_info() fills in hostname and port from the connected socket.
 */

void
get_local_info( sockdes)
int	sockdes;
{
	int size;
	static struct sockaddr_in      saddr;
	struct hostent  *hostentp;

	size = sizeof(saddr);
	/*  sockdes is our our descriptor for the socket. */
	if ( getsockname( sockdes, (struct sockaddr *) &saddr, &size) < 0 ) {
		daemon_logerr( err_m[73], "", errno);
		errno = 0;
		return;
	}

		/* Remember our port number */
	port = ntohs(saddr.sin_port);
#ifdef RFC931_TIMEOUT
	mysin = (struct WN_SOCKADDR_TYPE *)&saddr;
#endif
	/* Remember our hostname (or at least dotted quad) */
	if ( *hostname) 
		return;

	if ( *listen_ip && !streq( listen_ip, "all") ) 
		mystrncpy( hostname, listen_ip, MAXHOSTNAMELEN);
	else
		mystrncpy( hostname, inet_ntoa(saddr.sin_addr), MAXHOSTNAMELEN);

	/* Try for domain name */
	if ( (hostentp = gethostbyaddr((char *)  &saddr.sin_addr,
			sizeof (saddr.sin_addr.s_addr), AF_INET)) ) {
		mystrncpy(hostname, hostentp->h_name, MAXHOSTNAMELEN);
		strlower(hostname);
	}
}


#if WN_SU_EXEC

FILE *
WN_popen( cmd, type)
char	*cmd,
	*type;
{
	FILE	*popen_ret;

	char	*cp,
		*basename,
		*hashp,
		hash[SMALLLEN],
		cmdname[MIDLEN],
		buf[2*MIDLEN];



	mystrncpy( cmdname, cmd, MIDLEN);
	cp = cmdname;
	basename = NULL;
	while ( *cp && isspace( *cp))
		cp++;

	while ( *cp && !isspace( *cp)) {
		if ( *cp == '/')
			basename = cp;
		cp++;
	}
	if ( basename) {
		*basename++ = '\0';
		if ( chdir( cmdname) != 0  ) {
			senderr( SERV_ERR, err_m[106], cmdname);
			wn_exit( 2);  /* senderr WN_popen( ) */
		}
	}
	else
		basename = cmdname;


	hashp = hash;
	mystrncpy( hashp, "WN", SMALLLEN);
	hashp += 2;
	/*
	 * The first arg to SUEXEC_HANDLER will be of the form
	 * "WNXXXXXX" where XXXXXX is the MD5 hash of 
	 * "suexec_key:usr_name:group_num" perhaps with one or two 
	 * leading characters.  These characters are 'x' indicating
	 * a filter is used or '~' indicating a tilde_user, or both
	 * e.g. WNx~0123456789abcd.
	 */

	if ( this_rp->tilde_user_group) {
		fmt3( buf, MIDLEN, suexec_key, ":", this_rp->tilde_user_group);
		if ( this_rp->attributes & WN_FILTERED ) {
			mystrncat( hashp, "x~", SMALLLEN);
			hashp += 2;
		}
		else
			*hashp++ = '~';

		mk_md5digest (buf, hashp);

		fmt3( buf, MIDLEN, SUEXEC_HANDLER, " ", hash);
		fmt3( buf, MIDLEN, buf, " ", this_rp->tilde_user_group);
		if ( (cp = strrchr( buf, ':')) != NULL)
		     *cp = ' ';
		fmt3( buf, MIDLEN, buf, " ", basename);
		free( this_rp->tilde_user_group);
		this_rp->tilde_user_group = NULL;
		if ( (popen_ret = popen( buf, type)) == NULL) {
			logerr( err_m[150], SUEXEC_HANDLER);
			logerr( err_m[150], strerror( errno));
		}
		return (popen_ret);
	}
	else if ( this_rp->vhost_user && this_rp->vhost_group) {
		if ( this_rp->attributes & WN_FILTERED )
			*hashp++ = 'x';

		fmt3( buf, MIDLEN, suexec_key, ":", this_rp->vhost_user);
		fmt3( buf, MIDLEN, buf, ":", this_rp->vhost_group);
		mk_md5digest (buf, hashp);

		fmt3( buf, MIDLEN, SUEXEC_HANDLER, " ", hash);
		fmt3( buf, MIDLEN, buf, " ", this_rp->vhost_user);
		fmt3( buf, MIDLEN, buf, " ", this_rp->vhost_group);
		fmt3( buf, MIDLEN, buf, " ", basename);
		if ( (popen_ret = popen( buf, type)) == NULL) {
			logerr( err_m[150], SUEXEC_HANDLER);
			logerr( err_m[150], strerror( errno));
		}
		return (popen_ret);
	}
	else {
		senderr( SERV_ERR, err_m[146], "");
		wn_exit( 2);  /* senderr WN_popen( ) */
		return NULL;  /* never get here */
	}
}

/*
 * mk_md5digest( in, out) takes the string "in" and calculates the MD5
 * digest placing the result in "out"
 */

static void 
mk_md5digest (in, out)
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


#endif /* WN_SU_EXEC */


#if NEED_INITGROUPS  && STANDALONE
#ifndef NGROUPS_MAX
#define NGROUPS_MAX	(16)
#endif

int
initgroups(gp_name, group_id)
char	*gp_name;
gid_t	group_id;

{
	gid_t		groups[NGROUPS_MAX];
	struct group	*g;
	int		i;
	char		**names;

	groups[0] = group_id;

	for ( i = 1; i < NGROUPS_MAX; i++) {
		if ((g = getgrent()) == NULL)
			break;
		if (g->gr_gid == group_id)
			continue;

		for (names = g->gr_mem; *names != NULL; names++) {
		        if (!strcmp(*names, gp_name))
				groups[i] = g->gr_gid;
		}
	}

	return setgroups(i, groups);
}
#endif /* NEED_INITGROUPS && STANDALONE */
