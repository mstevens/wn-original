/*
    Wn: A Server for the HTTP
    File: wn/standalone.c
    Version 2.4.7
    
    Copyright (C) 1996-2004  <by John Franks>

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




#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <grp.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#ifdef	ISC
#include <net/errno.h>
#endif
#include <pwd.h>
#include <string.h>
#include <unistd.h>
#include "wn.h"


#define QUEBACKLOG	(1024)

extern char	**environ;

extern		char suexec_key[];

extern int	daemon_init(),
		needsuffix();

extern FILE	*logfp;

static int	need_mime();

static void	timehack(),
		set_suexec_key( );


static char 	*nullenviron = NULL;

static char	*mtypebase = NULL;

static void	zombie();

void
do_standalone()
{
	FILE	*pid_fp;

	char	mbuf[2*SMALLLEN];

int		sockdes,
		sd,
		len,
		pid,
		kav = 1,
		nagle = 1,
		on = TRUE;
	
	struct linger ling;
	struct sockaddr_in	sa_server,
				sa_client;

	umask( 077);

	timehack( );

	if ((sd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) == -1) {
		daemon_logerr( err_m[22], "", errno);
		exit(2);
	}

	ling.l_onoff = ling.l_linger = 0;


#ifndef NO_LINGER
	if ( setsockopt( sd, SOL_SOCKET, SO_LINGER, (char *) &ling,
					    sizeof (ling)) == -1) {
		daemon_logerr( err_m[23], "", errno);
		exit(2);
	}
#endif

	if ( (setsockopt( sd, SOL_SOCKET, SO_REUSEADDR,
					(char *) &on, sizeof( on))) == -1) {
		daemon_logerr( err_m[24], "", errno);
		exit(2);
	}


#ifndef DO_NAGLE
	if ( setsockopt(sd, IPPROTO_TCP, TCP_NODELAY,
				(char*)&nagle, sizeof(nagle))) {
		daemon_logerr( err_m[105], "", errno);
		/* Not fatal */
	}
#endif /* DO_NAGLE */

	if ( (setsockopt( sd, SOL_SOCKET, SO_KEEPALIVE,
					(char *) &kav, sizeof( kav))) == -1) {
		daemon_logerr( err_m[98], "", errno);
		exit(2);
	}

        signal( _WN_SIGCHLD, (void (*)())zombie );

	bzero((char *)&sa_server, sizeof( sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_port = htons( port);

	if ( *listen_ip && streq( listen_ip , "all")) {
		sa_server.sin_addr.s_addr = htonl( INADDR_ANY);
	}
	else {
		struct hostent *hptr;

		if ( *listen_ip && 
				((hptr = gethostbyname(listen_ip)) != NULL)) {
			bcopy(hptr->h_addr,
			(char *) &(sa_server.sin_addr.s_addr), hptr->h_length);
		}
		else if ( *hostname && 
			((hptr = gethostbyname(hostname)) != NULL)) {
			bcopy(hptr->h_addr,
			(char *) &(sa_server.sin_addr.s_addr), hptr->h_length);
		}
		else {
			if ( *hostname || *listen_ip ) {
				Snprintf1( mbuf, 2*SMALLLEN, err_m[91], 
					(*listen_ip ? listen_ip : hostname));
				mystrncat( mbuf, err_m[92], 2*SMALLLEN);
				daemon_logerr( mbuf, "", errno);
			}
			sa_server.sin_addr.s_addr = htonl( INADDR_ANY);
		}
	}

	if ( bind( sd, (struct sockaddr *) &sa_server,
			sizeof(sa_server)) == -1) {
		perror( err_m[25]);
		daemon_logerr( err_m[25], "",  errno);
	        exit(2);
	}

	listen( sd, QUEBACKLOG);

	set_suexec_key( );

	if ( *pid_file) {
		if ( (pid_fp = fopen( pid_file, "w")) != NULL) {
			fprintf( pid_fp, "%d\n", getpid());
			fclose( pid_fp);
			fchmod( fileno( pid_fp), (S_IRUSR | S_IWUSR |
						 S_IRGRP | S_IROTH));
		}
		else
			daemon_logerr(  err_m[97], "", errno);
	}
	else {
		Snprintf1( mbuf, TINYLEN,  "%d\n", getpid());
		write( 1, mbuf, strlen( mbuf));
	}

	if ( getuid() == 0 ) {  /* Running as root */
		struct passwd	*pw;

		if ( (pw = getpwuid( (uid_t) user_id)) == (struct passwd *)NULL
			|| initgroups( pw->pw_name, group_id) == -1
			|| setgid( (gid_t) group_id) == -1) {
			daemon_logerr(  err_m[26], "", errno);
			exit( 2);
		}

		if (setuid( (uid_t)user_id) == -1) {
			daemon_logerr(  err_m[27], "", errno);
			exit( 2);
		}
	}


	if ( wnlogfile[0]) {		/* We are logging to this file */
		open_wnlog( wnlogfile, errlogfile);
			/* We delayed openning it until after setuid */
	}


        len = sizeof(sa_client);
        if ( (sockdes = accept( sd, (struct sockaddr *) &sa_client, &len)) == -1 ) {
		daemon_logerr( err_m[28], "", errno);
		exit( 2);
	}


	get_local_info( sockdes);

	environ = &nullenviron;

	putenv( "IFS= \t");

	while ( TRUE) {
        	if((pid = fork()) == -1) {
			daemon_logerr( err_m[29], "", errno);
		}

		if ( pid == 0 ) { 		/* Child process */
			close(0);
			if ( dup2( sockdes, 0) == -1)
				daemon_logerr( err_m[148], "stdin", errno);

			close(1);
			if ( dup2( sockdes, 1) == -1)
				daemon_logerr( err_m[148], "stdout", errno);

			signal( SIGHUP, SIG_DFL);
			signal( SIGQUIT, SIG_DFL);
			signal( SIGINT, SIG_DFL);
			close(sd);
			close(sockdes);
			do_connection();
			exit (0);
		}

		close(sockdes);

	        while ( (sockdes = accept( sd,
				(struct sockaddr *) &sa_client, &len)) < 0 ) {
			switch ( errno) {
			case EINTR:
			case ECONNABORTED:
			case ECONNRESET:
			case ETIMEDOUT:
			case EHOSTUNREACH:
				break;
			default:
				daemon_logerr( err_m[28], "", errno);
			}
		}
		errno = 0;
	}
}

static void
zombie()
{
#ifndef NEXT
	int status;
#else
	union wait status;
#endif
	pid_t	pid;

	bzero( &status, sizeof( status));
	while( (pid = waitpid( -1, &status, WNOHANG)) > 0)
		;
}


/*
 * The following function adapted from Stevens, "Advanced Programming in the
 * Unix Environment", p. 418,  initializes the the standalone daemon.
 */

int
daemon_init()
{
	int	open_max,
		i;

	pid_t	pid,
		procgp;

	if (nofork == FALSE) {
		if ( (pid = fork()) < 0 )
			return (-1);
		else if ( pid != 0 ) {
			if ( admin_mode)
				fprintf( stdout, "%d\n", pid);
			exit( 0);
		}
	}


	if ( nofork || NO_SETSID) {
		if ( ( procgp = setpgid( getpid( ), 0) ) == -1) {
			daemon_logerr( err_m[31], "", errno);
			perror("setpgrp");
			exit( 2);
		}
	}
	else {
		if ( (procgp = setsid()) == -1 ) {
			daemon_logerr( err_m[30], "", errno);
			perror("setsid");
			exit( 2);
		}
	}
	chdir( "/");

#ifdef NEXT
	open_max = 32;
#else
	open_max = getdtablesize ();
#endif

	i = ( (default_logtype & WN_LOG_SYSLOG ) ? 4 : 3);
	for ( ; i < open_max; i++) {
		close( i);
	}
	return (0);
}



static void
timehack()
{
	char 		buf[TINYLEN];
	time_t		clock;
	struct tm 	*dummy;

	time(&clock);
	dummy = localtime (&clock);
	dummy = gmtime (&clock);

	strftime (buf, TINYLEN, "%d/%b/%Y:%H:%M:%S", dummy);
	gethostbyname( "localhost");
}



/*
 * void init_mime( )
 * Create an array  suflist[i] of suffixes and an array mtypelist[i]
 * of mime types.  suffix i corresponds to mime type mtypelist[i].
 * Items are read from MIME_TYPE_FILE and only those with suffixes not
 * already in mimelist[] are used.
 */

void
init_mime( )
{
#define UNIT_SIZE	(1024)

	register char	*cp, *cp2;
	char	*mtypefile,
		buf[2*UNIT_SIZE];

	FILE	*mimefp;
	int	i,
		item_count = 0,
		size = 0,
		curr_size = 0,
		num_units = 1;

	mtypefile = MIME_TYPE_FILE;
	if ( (mimefp = fopen( mtypefile, "r")) == (FILE *) NULL) {
		daemon_logerr( err_m[1], mtypefile, 0);
		return;
	}

	if ( suflist != NULL) {		/* we are restarting */
		free( suflist);
		suflist = NULL;
	}

	if ( mtypebase != NULL) {	/* we are restarting */
		free( mtypebase);
		mtypebase = NULL;
	}

	if ( (mtypebase = (char *) malloc( UNIT_SIZE)) == NULL) {
		daemon_logerr( err_m[114], "", 0);
		fclose( mimefp);
		return;
	}

	while ( fgets( buf, 2*UNIT_SIZE, mimefp)) {
		int	n;

		n = need_mime( buf);
		if ( n > 0 ) {
			int	size1,
				size2;

			item_count += n;
			size1 = strlen( buf) + 1;
			cp = buf + size1;
			size2 = strlen( cp) + 1;
			while ( size1 + size2 + curr_size >= 
						num_units * UNIT_SIZE) {
				num_units++;
				mtypebase = (char *) realloc( mtypebase, 
						num_units * UNIT_SIZE);
				if ( mtypebase == NULL) {
					daemon_logerr( err_m[114], "", 0);
					return;
				}
			}
			mystrncpy( mtypebase + curr_size, buf, num_units * UNIT_SIZE - curr_size );
			curr_size += size1;
			mystrncpy( mtypebase + curr_size, cp, num_units * UNIT_SIZE - curr_size);
			curr_size += size2;
		}
	}

	fclose( mimefp);

	if ( (item_count == 0) && ( mtypebase != NULL) ) {
		free( mtypebase);
		mtypebase = NULL;
		return;
	}

	item_count += 2;

	if ( (suflist = (char **) malloc( 2 * (sizeof( char *)) * item_count))
								== NULL) {
		daemon_logerr( err_m[114], "",  0);
		return;
	}

	mtypelist = suflist + item_count;

	cp = mtypebase;
	i = 0;
	size = 0;

	while ( size < curr_size ) {
		char	*tmp_mtype;

		tmp_mtype = mtypebase + size;
		size += strlen( tmp_mtype) + 1;;
		cp = mtypebase + size;		
		while ( *cp) {
			if (!*cp)
				break;
			suflist[i] = cp;
			mtypelist[i] = tmp_mtype;
			if ( (cp2 = strchr( cp, '.')) != NULL) {
				*cp2++ = '\0';
				size += strlen( cp) + 1;
				cp = cp2;
				if ( !*cp2 ) {  /* trailing '.' */
					size++;
				}
				i++;
			}
			else {
				size += strlen( cp) + 1;
				i++;
				break;
			}
		}		
	}
	suflist[i] = mtypelist[i] = NULL;
}


/*
 * static int need_mime( line)
 * takes the line and reformats it to the form 
 * "mime_type\0suf1.suf2.suf3\0".  I.e. mime_type null terminated
 * followed by suffixes separated by '.'.  Only suffixes not in
 * mime list are used.  Returns the the number of suffixes found.
 * The size of line is 2*UNIT_SIZE.  Use needsuffix() to decide if
 * this suffix is already in mimelist, in which case we don't need
 * to add it.
 */

static int
need_mime( line)
char	*line;
{
	int	itemcount = 0,
		typelen;

	char	*cp,
		*cp2;

	if ( (cp = strchr( line, '#')) != NULL)
		*cp = '\0';

	cp = line;
	while ( isspace( *cp))
		cp++;

	if ( cp > line)
		mystrncpy( line, cp, 2*UNIT_SIZE);

	if ( !*line )		/* empty line */
		return (0);

	cp = line;
	typelen = strlen( line);

	while ( *cp && !isspace( *cp))
		cp++;

	if ( *cp) 
		*cp++ = '\0';
	else
		return (0);
		/* There is no suffix */

	if ( strchr( line, '/') == NULL) {
		daemon_logerr( err_m[112], line, 0);
		return (0);
	}


	while ( *cp ) {
		cp2 = cp;
		while ( *cp2 && isspace( *cp2))
			cp2++;
		if ( !*cp2) {
			*cp = '\0';
			break;
		}
		if ( cp2 > cp) {
			strcpy( cp, cp2);  /* substring copied to front */
			cp2 = cp;
		}
		 /* leading space has been skipped  */

		while ( *cp2 && !isspace( *cp2))
			cp2++;
		if ( *cp2 ) {
			*cp2 = '\0';
			if ( needsuffix( cp)) {
				itemcount++;
				*cp2++ = '.';
				cp = cp2;
				continue;
			}
			else {
				strcpy( cp, cp2);    /* substring copied to front */
			}
		}
		else { /* last suffix */
			if ( !needsuffix( cp))
				*cp = '\0';
			else
				itemcount++;
			
			break;
		}
	}
	return (itemcount);
}


static void
set_suexec_key( )
{
#if WN_SU_EXEC
	FILE	*key_fp;

	unsigned	i;
	unsigned char	cc;
	int	fd;

	if ( (fd = open( RANDOM_DATA_FILE, O_RDONLY)) == -1 ) {
		daemon_logerr(  err_m[1], RANDOM_DATA_FILE, errno);
		wn_exit( 2);
	}
	for ( i = 0; i < (SUEXEC_KEYLEN)/2; i++) {
		if ( read( fd, &cc, 1) != 1) {
			daemon_logerr(  err_m[49], RANDOM_DATA_FILE, errno);
			wn_exit( 2);
		}
		sprintf( &suexec_key[2*i], "%02x", cc );
	}
	suexec_key[2*i] = '\0';
	close( fd);
	if ( (key_fp = fopen( SUEXEC_KEY_FILE, "w")) != NULL) {
		fprintf( key_fp, "%s\n", suexec_key);
		if (( fchown( fileno( key_fp), 0, 0) == -1 ) ||
    			( fchmod( fileno( key_fp), (S_IRUSR |S_IWUSR)) == -1 ))
			daemon_logerr(  err_m[147], SUEXEC_KEY_FILE, errno);
		fclose( key_fp);
	}
	else
		daemon_logerr(  err_m[147], SUEXEC_KEY_FILE, errno);
#endif
}

