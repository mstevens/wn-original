/*

    File: wn/init.c
    Version 2.4.6
    
    Copyright (C) 1995-2003  <by John Franks>

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
#include <sys/signal.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

#ifndef NO_UNISTD_H
#include <unistd.h>
#endif

#include <syslog.h>

#include <fcntl.h>
#include "wn.h"
#include "version.h"
#include "err.h"
#include "content.h"


#if MAKE_WNSSL
#include "wnssl.h"
static char	wn_ssl_key_file[SMALLLEN],
		wn_ssl_cert_file[SMALLLEN],
		wn_ssl_chain_file[SMALLLEN];
#endif

static void wnssl_opts( );
static void wnssl_init( );

#if USE_VIRTUAL_HOSTS
extern char	*vhostlist[][7];
#endif

/* this may be needed if unistd.h isn't included... */
#ifndef SEEK_SET
#define SEEK_SET 0
#endif

#ifdef RFC931_TIMEOUT
extern void	get_rfc931();
#endif

#if STANDALONE
#define PRINT_ERROR( x, y)	fprintf( stderr, x, y);
#define PRINT1_ERROR( x)	fprintf( stderr, x);
#else
#define PRINT_ERROR( x, y)	printf( x, y);
#define PRINT1_ERROR( x)	printf( x);
#endif

#ifndef BSD_LIKE
extern long	timezone;
#endif

extern void	end_chunking();

extern char	*optarg;

extern int	optind;

static void	add2_logbuf(),
		dump_log();

static unsigned	set_logtype( );

#if MAKE_WNSSL
static RSA *TmpRSACallback( );
#endif


char	rootdir[SMALLLEN],
	wn_tmpdir[sizeof(WN_TEMPDIR) + TINYLEN] = {WN_TEMPDIR},
	wn_empty[] = { "" },	/* safe place to park pointers */
	wnlogfile[SMALLLEN],
	errlogfile[SMALLLEN],
	pid_file[SMALLLEN],
	cfname[SMALLLEN],
	hostname[MAXHOSTNAMELEN],
	listen_ip[TINYLEN],
	**mtypelist = NULL,
	**suflist = NULL;


int	admin_mode = FALSE,
	debug_log = FALSE,
	nofork = FALSE;


unsigned	serv_perm = 0,
		interface_num,
		default_logtype = WN_COMMON_LOG,
		acache_id,
		cache_id;

uid_t	user_id = USERID;
gid_t	group_id = GROUPID;


#ifndef NO_FLOCK
static void	locklog(),
		unlocklog();
#endif

static void	start_log(),
		restart(),
		log_logfile();

static FILE	*logfp = NULL,
		*errlogfp = NULL;

static void	log_syslog ();

static void	append_gmtoff();





void
wn_init( argc, argv)
int	argc;
char	*argv[];
{
	char	*cp;

	int	c,
		errflg = 0;

	if ( MAKE_WNSSL)
		port = DEFAULT_SSL_PORT;
	else
		port = DEFAULT_PORT;

	mystrncpy( rootdir, ROOT_DIR, SMALLLEN);

	default_logtype = set_logtype( );


	if ( strlen( SWN_PID_FILE) > 0)
		mystrncpy( pid_file, SWN_PID_FILE, SMALLLEN);
	else
		*pid_file = '\0';

	mystrncpy( cfname, CACHEFNAME, SMALLLEN);
	mystrncpy( hostname, WN_HOSTNAME, MAXHOSTNAMELEN);
	listen_ip[0] = '\0';

	if ( FORBID_CGI)
		serv_perm |= WN_FORBID_EXEC;

	while ((c = getopt(argc, argv, 
			"a:A:deEh:i:L:l:n:N:p:Pq:St:T:Fuv:V:w:xz:")) != -1) {

		switch ((char) c) {
			case 'a':
				acache_id = (unsigned) atoi( optarg);
				serv_perm |= WN_ATRUSTED_UID;
				break;
			case 'A':
				acache_id = (unsigned) atoi( optarg);
				serv_perm |= WN_ATRUSTED_GID;
				break;
			case 'e':
				serv_perm |= WN_FORBID_EXEC;
				break;
			case 'E':
				serv_perm |= WN_RESTRICT_EXEC;
				break;
			case 'h':
				mystrncpy( hostname, optarg, MAXHOSTNAMELEN);
				break;
			case 'i':
				mystrncpy( listen_ip, optarg, TINYLEN);
				strlower( listen_ip);
				break;
			case 'L':
				mystrncpy( wnlogfile, optarg, SMALLLEN);
				break;
			case 'l':
				mystrncpy( errlogfile, optarg, SMALLLEN);
				break;
#if STANDALONE
			case 'n':
				user_id = (uid_t) atoi( optarg);
				break;
			case 'N':
				group_id = (gid_t) atoi( optarg);
				break;
			case 'p':
				port = atoi( optarg);
				break;
			case 'P':
				serv_perm |= WN_PERMIT_PUT;
				break;
			case 'q':
				mystrncpy( pid_file, optarg, SMALLLEN);
				break;
			case 'F':
				nofork = TRUE;
				break;
#endif /* STANDALONE */

			case 'S':
				default_logtype = WN_LOG_SYSLOG;
				break;
			case 't':
				cache_id = (unsigned) atoi( optarg);
				serv_perm |= WN_TRUSTED_UID;
				break;
			case 'T':
				cache_id = (unsigned) atoi( optarg);
				serv_perm |= WN_TRUSTED_GID;
				break;
			case 'u':
				serv_perm |= WN_COMP_UID;
				break;
			case 'v':
				default_logtype = 0;
				strlower( optarg);
				if ( (cp = strchr(optarg, ':')) != NULL) {
					if ( streq( cp, ":nodns")) {
						default_logtype = NO_DNS_LOG;
						*cp = '\0';
					}
					else if ( streq( cp, ":revdns")) {
						default_logtype = REV_DNS_LOG;
						*cp = '\0';
					}
				}
				if ( strcasecmp( optarg, "nolog") == 0) {
					default_logtype = WN_NO_LOG+NO_DNS_LOG;
					break;
				}
				if ( strcasecmp( optarg, "common") == 0) {
					default_logtype |= WN_COMMON_LOG;
					break;
				}
				if ( strcasecmp( optarg, "verbose") == 0) {
					default_logtype |= WN_VERBOSE_LOG;
					break;
				}
				if ( strcasecmp( optarg, "ncsa") == 0) {
					default_logtype |= WN_NCSA_LOG;
					break;
				}

				if ( strcasecmp( optarg, "syslog") == 0) {
					default_logtype |= WN_LOG_SYSLOG;
					break;
				}
				if ( strcasecmp( optarg, "vsyslog") == 0) {
					default_logtype |= WN_VERBOSE_SYSLOG;
					break;
				}

				PRINT_ERROR( err_m[135], optarg);
				exit( 2);
#if USE_VIRTUAL_HOSTS
#ifdef VIRTUAL_HOSTS_FILE
			case 'V':
				mystrncpy( vhostfile, optarg, SMALLLEN);
				break;
#endif
#endif
			case 'w':
				mystrncpy( wnlogfile, optarg, SMALLLEN);
				mystrncpy( errlogfile, optarg, SMALLLEN);
				mystrncpy( pid_file, "", SMALLLEN);
				break;

			case 'd':
				/*should only be used for logging to file*/
				debug_log = TRUE;
				default_logtype = WN_VERBOSE_LOG;
				break;

			case 'z':
				if ( MAKE_WNSSL)
					wnssl_opts( optarg);
				else
					errflg++;
				break;

			case '?':
				errflg++;
		}
	}
	if (errflg) {
		if ( STANDALONE) {
			PRINT1_ERROR("Usage: wn [-L logfile | -S] [-a uid |-A gid]\n");
			PRINT1_ERROR( "[-F] [-e | -E] [-p port] [-t uid | -T gid ] ");
			PRINT1_ERROR( "[-v log_type] [-V virtual host file]\n");
			PRINT1_ERROR( "[-u] [-q pid_file] [-h host] [topdir]\n");
		}
		else
			PRINT1_ERROR( "Unknown option given to server");

		exit (2);
	}

	if ( *wnlogfile && !*errlogfile) {
		mystrncpy( errlogfile, wnlogfile, SMALLLEN);
	}

	if ( argv[optind] )
		mystrncpy( rootdir, argv[optind], SMALLLEN);


	if ( default_logtype & (WN_LOG_SYSLOG + WN_VERBOSE_SYSLOG)) {

#ifdef LOG_DAEMON
		/* 4.3 style */
		openlog ("wn", LOG_PID | LOG_NDELAY, LOGFACILITY);
#else
		/* 4.2 style */
		openlog ("wn", LOG_PID);
#endif
	}


	if ( ! STANDALONE )
		open_wnlog( wnlogfile, errlogfile);


#if USE_VIRTUAL_HOSTS
#ifdef VIRTUAL_HOSTS_FILE
	load_virtual();
#endif
#endif

#if STANDALONE
		init_mime();
#endif

	if ( STANDALONE )
		signal( SIGHUP, restart);
	if ( MAKE_WNSSL)
		wnssl_init( errlogfp);
}


/*
 * void open_wnlog( logfile, errlog) is called once on startup to 
 * open the logfile, the error log file and to create a sub temp directory.
 * The point of the sub temp directory is to make temp files more 
 * secure.  If the server can't create this temp directory with 
 * mode 0711 or if there isn't already one there owned by the server
 * uid, then the server won't run for security reasons.  Unfortunately,
 * this tmp directory never gets removed when the server is shut down.
 */

void
open_wnlog( logfile, errlog)
char	*logfile,
	*errlog;
{

#if (! FORBID_CGI)
	char		buf[TINYLEN];
	struct stat	stat_buf;
	uid_t		my_id;

	my_id = getuid();
	Snprintf1( buf, TINYLEN, "/wn_tmp%d", my_id);
	mystrncat( wn_tmpdir, buf, sizeof(WN_TEMPDIR) + TINYLEN);
	if ( lstat( wn_tmpdir, &stat_buf) == -1) {
		if ( (errno != ENOENT) || (mkdir( wn_tmpdir, 0711) != 0) ) {
			PRINT_ERROR( err_m[122], wn_tmpdir);
			exit( 2);
		}
	}
	else if ( (!S_ISDIR(stat_buf.st_mode))
				|| (stat_buf.st_uid != my_id)
				|| (chmod( wn_tmpdir, 0711) != 0) ) {
		PRINT_ERROR( err_m[122], wn_tmpdir);
		PRINT_ERROR( "errno=%d:", errno);
		PRINT_ERROR( " %s\n", strerror( errno));
		exit( 2);
	}
#endif

	if ( *logfile != '\0')
		if ( (logfp = fopen( logfile, "a")) == NULL ) {
			PRINT_ERROR( err_m[0], logfile);
			PRINT_ERROR( "errno=%d:", errno);
			PRINT_ERROR( " %s\n", strerror( errno));
			if ( errno == ENOENT || errno == EACCES )
				PRINT_ERROR( " %s\n", err_m[152]);
			exit( 2);
		}
	if ( *errlog != '\0') {
		if ( streq( errlog, logfile))
			errlogfp = logfp;

		else if ( (errlogfp = fopen( errlog, "a")) == NULL ) {
			PRINT_ERROR( err_m[0], errlog);
			PRINT_ERROR( "errno=%d:", errno);
			PRINT_ERROR( " %s\n", strerror( errno));
			if ( errno == ENOENT || errno == EACCES )
				PRINT_ERROR( " %s\n", err_m[152]);

			exit( 2);
		}
	}
	if ( STANDALONE) {
		start_log( FALSE);
	}
}


static void
restart( )
{
#if  STANDALONE

	signal( SIGHUP, SIG_IGN);

#ifdef VIRTUAL_HOSTS_FILE
#if USE_VIRTUAL_HOSTS
		load_virtual();
#endif
#endif

	if ( *wnlogfile) {
		if ( logfp) 
			fclose( logfp);
		if ( (logfp = fopen( wnlogfile, "a")) == NULL ) {
			PRINT_ERROR( err_m[0], wnlogfile);
			PRINT_ERROR( "restart errno=%d:", errno);
			PRINT_ERROR( " %s\n", strerror( errno));
			if ( errno == ENOENT || errno == EACCES )
				PRINT_ERROR( " %s\n", err_m[152]);
			exit( 2);
		}
	}

	if ( *errlogfile) {
		if ( streq( errlogfile, wnlogfile))
			errlogfp = logfp;
		else {
			if ( errlogfp)
				fclose( errlogfp);
			if ( (errlogfp = fopen( errlogfile, "a")) == NULL ){
				PRINT_ERROR( err_m[0], errlogfile);
				PRINT_ERROR( "restart errno=%d:", errno);
				PRINT_ERROR( " %s\n", strerror( errno));
				if ( errno == ENOENT || errno == EACCES )
					PRINT_ERROR( " %s\n", err_m[152]);
				exit( 2);
			}
		}
	}

	start_log( TRUE);
	init_mime();
	signal( SIGHUP, restart);
#endif
}


void
logerr(  msg, msg2)
char	*msg,
	*msg2;
{

#ifndef NO_FLOCK
	struct flock	lck;
#endif

	time_t	clock;
	struct tm *ltm;

	char	status[TINYLEN],
		date[TINYLEN],
		xmsg2[SMALLLEN + 2];

	unsigned llogtype;

	if ( (!dir_p) || !dir_p->logtype)
		llogtype = default_logtype;
	else 
		llogtype = dir_p->logtype;

	xmsg2[0] = '\0';
	if ( msg2 != NULL) {
		mystrncat2( xmsg2, msg2, SMALLLEN);
	}

	if ( llogtype & WN_NO_LOG)
		return;

	get_remote_info( );

 	if ( llogtype & (WN_LOG_SYSLOG + WN_VERBOSE_SYSLOG)) {
		log_syslog( ERRLOG_PRIORITY, this_rp, msg, xmsg2);
		return;
	}

	time(&clock);
	ltm = (struct tm *) localtime(&clock);
	strftime( date, TINYLEN, "%d/%h/%Y:%T", ltm);
	append_gmtoff( date, ltm);

#ifndef NO_FLOCK
	locklog( &lck, fileno( errlogfp) );
#endif

	if ( outheadp && (*outheadp->status)) {
		strncpy( status, outheadp->status, 4);
		status[4] = '\0';
		/* don't use mystrncpy as it may call us */
	}
	else
		strcpy( status, "500");

	fseek( errlogfp, 0L, 2);
	fprintf( errlogfp, "%.400s - - [%.64s] \"%.300s\" %.64s -",
		 this_conp->remotehost,	date, this_rp->request, status);
	fprintf( errlogfp, " <(%d/%d) %.400s: %.400s>",
			this_conp->pid, this_conp->trans_cnt, msg, xmsg2);

	fprintf( errlogfp, "\n");
	(void) fflush( errlogfp);


#ifndef NO_FLOCK
	unlocklog( &lck, fileno( errlogfp) );   
#endif

}

void
daemon_logerr(  msg, msg2, error)
char	*msg,
	*msg2;
int	error;
{

	FILE		*errfp;
#ifndef NO_FLOCK
	struct flock	lck;
#endif
	time_t	clock;
	struct tm *ltm;

	char	buf[2*SMALLLEN],
		date[TINYLEN];

	if ( default_logtype & WN_NO_LOG)
		return;

	if ( strlen( msg2) > SMALLLEN )  /* don't log too much */
		msg2[SMALLLEN-1] = '\0';

 	if ( default_logtype & (WN_LOG_SYSLOG + WN_VERBOSE_SYSLOG)) {
		mystrncpy( buf, 
		"none - - [] \"none\" 500 0  <%.100s: %.100s : %.100s> ");

	 	if ( default_logtype & WN_VERBOSE_SYSLOG) {
#if USE_VIRTUAL_HOSTS
			mystrncat2( buf, "<> <> <> <0>\n", SMALLLEN);
#else
			mystrncat2( buf, "<> <> <>\n", SMALLLEN);
#endif
		}
		else
			mystrncat( buf, "\n", SMALLLEN);

		syslog( ERRLOG_PRIORITY, buf, msg, msg2, strerror( error));
		return;
	}

	if ( errlogfp)
		errfp = errlogfp;
	else
		errfp = stderr;

	time(&clock);
	ltm = (struct tm *) localtime(&clock);
	strftime( date, TINYLEN, "%d/%h/%Y:%T", ltm);
	append_gmtoff( date, ltm);

#ifndef NO_FLOCK
	if ( errlogfp)
		locklog( &lck, fileno( errlogfp) );
#endif

	fseek( errfp, 0L, 2);   
	fprintf(errfp, "none - - [%.64s] \"none\" 500 0",  date);
	if ( default_logtype & WN_VERBOSE_LOG ) {
		fprintf( errfp, " <%.200s %.200s: %s> <> <> <>",
					msg, msg2, strerror(error));
#if USE_VIRTUAL_HOSTS
		fprintf( errfp, " <0>");
#endif
	}

	fprintf( errfp, "\n");
	(void) fflush( errfp);

#ifndef NO_FLOCK
	if ( errlogfp)
		unlocklog( &lck, fileno( errlogfp) );   
#endif
}


void
writelog( ip, msg, msg2)
Request	*ip;
char	*msg,
	*msg2;
{
	char	xmsg2[SMALLLEN];
	unsigned llogtype;

	if ( (!dir_p) || !dir_p->logtype)
		llogtype = default_logtype;
	else 
		llogtype = dir_p->logtype;

 	if ( llogtype & WN_NO_LOG)
		return;

	xmsg2[0] = '\0';
	if ( msg2 != NULL)
		mystrncat2( xmsg2, msg2, SMALLLEN);

 	if ( llogtype & (WN_LOG_SYSLOG + WN_VERBOSE_SYSLOG))
		log_syslog( LOG_PRIORITY, ip, msg, xmsg2);
	else
		log_logfile( ip, msg, xmsg2);
}


/* Write debug messages into the log file. */

void
write_debug(n, msg, msg2)
int	n; /*ignored for now, could become the debug level later*/
char	*msg, *msg2;
{
	unsigned llogtype;

	if ( (!dir_p) || !dir_p->logtype)
		llogtype = default_logtype;
	else 
		llogtype = dir_p->logtype;

	if ( llogtype & WN_NO_LOG)
		return;
	if ( llogtype & (WN_LOG_SYSLOG + WN_VERBOSE_SYSLOG)) {
		if ( strlen( msg) > 128 )
			msg[127] = '\0';
		if ( strlen( msg2) > 128 )
			msg2[127] = '\0';
		log_syslog( LOG_PRIORITY, this_rp, msg, msg2);
		return;
	}
	if ( llogtype & (WN_COMMON_LOG + WN_VERBOSE_LOG + WN_NCSA_LOG)) {
		fprintf(logfp, "%.300s %.300s\n", msg, msg2);
		(void) fflush( logfp);
	}
}


static void
log_logfile( ip, msg, msg2)
Request	*ip;
char	*msg,
	*msg2;
{
	time_t	clock;
	struct tm *ltm;

	char	*authname,
		bytes[TINYLEN],
		status[TINYLEN],
		date[TINYLEN],
		lbuf[2*SMALLLEN];

	unsigned llogtype;

	if ( (!dir_p) || !dir_p->logtype)
		llogtype = default_logtype;
	else 
		llogtype = dir_p->logtype;

	if ( outheadp && (*outheadp->status)) {
		char *cp;

		status[0] = '\0';
		mystrncat2( status, outheadp->status, TINYLEN);
		cp = status;
		while ( *cp && !isspace(*cp))
			cp++;
		*cp = '\0';
	}
	else
		mystrncpy( status, "200", TINYLEN);

	Snprintf1( bytes, TINYLEN, "%lu", ip->logcount);

	time(&clock);
	ltm = (struct tm *) localtime(&clock);
	strftime( date, TINYLEN, "%d/%h/%Y:%T", ltm);
	append_gmtoff( date, ltm);

	authname = ( *this_rp->authuser ? this_rp->authuser : "-");
	fmt3( lbuf, 2*SMALLLEN, authname, " [", date);
	fmt3( lbuf, 2*SMALLLEN, lbuf, "] \"", ip->request);
	fmt3( lbuf, 2*SMALLLEN, lbuf, "\" ", status);
	fmt3( lbuf, 2*SMALLLEN, lbuf, " ", bytes);

	add2_logbuf( lbuf);

	if ( llogtype & WN_VERBOSE_LOG ) {
		if ( streq( status, "206")) {
			char *rangep;

			rangep = outheadp->range;
			if ( !*rangep)
				rangep = "multipart";

			Snprintf5( lbuf, 2*SMALLLEN, 
				" <(%d/%d) %.100s (%.100s): %.200s>",
				this_conp->pid, this_conp->trans_cnt, 
				log_m[23], rangep, msg2);
		}
		else {
			Snprintf4( lbuf, 2*SMALLLEN, " <(%d/%d) %.200s: %.200s>",
			this_conp->pid, this_conp->trans_cnt, msg, msg2);
		}
		add2_logbuf( lbuf);

		fmt3( lbuf, 2*SMALLLEN, " <", inheadp->ua, ">");
		add2_logbuf( lbuf);

		fmt3( lbuf, 2*SMALLLEN, " <", inheadp->referrer, ">");
		add2_logbuf( lbuf);

		fmt3( lbuf, 2*SMALLLEN, " <", inheadp->cookie, ">");
		add2_logbuf( lbuf);

		fmt3( lbuf, 2*SMALLLEN, " <", inheadp->xforwardedfor, ">");
		add2_logbuf( lbuf);

#if USE_VIRTUAL_HOSTS
		if ( (interface_num > 0) && vhostlist[interface_num - 1][3] &&
						*vhostlist[interface_num - 1][3] )
			fmt3( lbuf, SMALLLEN, " <",
					vhostlist[interface_num - 1][3], ">" );
		else
			Snprintf1( lbuf, SMALLLEN, " <%d>", interface_num);

		add2_logbuf( lbuf);
#endif
	}
	else if ( llogtype & WN_NCSA_LOG) {
		fmt3( lbuf, SMALLLEN, " \"", inheadp->referrer, "\"");
		add2_logbuf( lbuf);

		fmt3( lbuf, SMALLLEN, " \"", inheadp->ua, "\"");
		add2_logbuf( lbuf);
	}
	mystrncat2( this_conp->logbuf, "\n", LOGBUFLEN);
}

static void
add2_logbuf( xlbuf)
char	*xlbuf;
{

	if ( strlen( xlbuf) + strlen( this_conp->logbuf) >= LOGBUFLEN) {
		dump_log( );
	}
	mystrncat2( this_conp->logbuf, xlbuf, LOGBUFLEN);
	xlbuf[0] = '\0';
}

#ifndef NO_FLOCK
static void
locklog(lck, fd)
struct flock	*lck;
int	fd;
{
	lck->l_type = F_WRLCK;
	lck->l_whence = SEEK_SET;
	lck->l_start = 0L;
	lck->l_len = 0L;
	fcntl(fd, F_SETLKW, lck);
}

static void
unlocklog( lck, fd)
struct flock	*lck;
int	fd;
{
	lck->l_type = F_UNLCK;
	fcntl( fd, F_SETLKW, lck);
}
#endif


static void
log_syslog( priority, ip, msg, msg2)
int	priority;
Request	*ip;
char	*msg,
	*msg2;
{
	char	*authname,
		*rfc931p,
		bytes[TINYLEN],
		status[TINYLEN];

	unsigned llogtype;

	if ( (!dir_p) || !dir_p->logtype)
		llogtype = default_logtype;
	else 
		llogtype = dir_p->logtype;

	if ( *outheadp->status) {
		strncpy( status, outheadp->status, 4);
		/* don't use mystrncpy as it may call us */
		status[3] = '\0';
	}
	else {
		strcpy( status, "200");
	}

	Snprintf1( bytes, TINYLEN, "%lu", ip->logcount);

	rfc931p = ( *this_conp->rfc931name ? this_conp->rfc931name : "-");
	authname = ( *ip->authuser ? ip->authuser : "-");
	get_remote_info();

	if ( llogtype & WN_VERBOSE_SYSLOG ) {
		char 	xlbuf[SMALLLEN];
#if USE_VIRTUAL_HOSTS
		char	label[SMALLLEN];

		fmt3( xlbuf, SMALLLEN, " <", inheadp->xforwardedfor, ">");

		if ( (interface_num > 0) && vhostlist[interface_num - 1][3] &&
						*vhostlist[interface_num - 1][3] )
			fmt3( label, SMALLLEN, " <", 
					vhostlist[interface_num - 1][3], ">");
		else
			Snprintf1( label, TINYLEN, " <%d>", interface_num );

		mystrncat2( xlbuf, label, SMALLLEN);
#else
		fmt3( xlbuf, SMALLLEN, " <", inheadp->xforwardedfor, ">");
#endif
		syslog( priority,
		"%.100s %.32s %.32s \"%.100s\" %.10s %.10s  <%.100s: %.100s> <%.100s> <%.100s> <%.100s>%s\n", 
		this_conp->remotehost, rfc931p, authname, ip->request, status, 
		bytes, msg, msg2, inheadp->ua, inheadp->referrer,
		inheadp->cookie, xlbuf);
	}
	else {
		syslog( priority,
		"%.100s %.32s %.32s \"%.100s\" %.10s %.10s  <%.100s: %.100s>\n", 
		this_conp->remotehost, rfc931p, authname, ip->request, status, 
		bytes, msg, msg2);
	}
}



static void
append_gmtoff( date, ltm)
char	*date;
struct tm *ltm;
{
	register char	*cp;
	long		tz;
	char 		sign;

#ifdef BSD_LIKE
	tz = ltm->tm_gmtoff;
#else
	tz = - timezone;
	if( ltm->tm_isdst)
		tz += 3600;
#endif
	sign = ( tz > 0 ? '+' : '-');
	tz = ( tz > 0 ? tz :  -tz);
	cp = date;
	while ( *cp)
		cp++;
	
	Snprintf3( cp, 7, " %c%02ld%02ld", sign, tz/3600, tz % 3600);
}


/*
 * static void start_log( restarting) prints the opening message to a 
 * new log file with time, version, port and pid.  It says "Restarting"
 * if restarting is TRUE and "Starting" otherwise.
 */

static void
start_log( restarting)
int	restarting;
{
#if STANDALONE
	time_t	clock;
	struct tm *ltm;
	char	*cp,
		startdate[TINYLEN];
	if ( default_logtype & (WN_NO_LOG+WN_LOG_SYSLOG+WN_VERBOSE_SYSLOG))
		return;
	time(&clock);
	ltm = (struct tm *) localtime(&clock);
	strftime( startdate, TINYLEN, "%d/%h/%Y:%T", ltm);
	cp = ( restarting ? "Restarting" : "Starting");
	fprintf(logfp, "\n%.64s: %s %.64s at port %d with pid %d\n", 
			startdate, cp, VERSION, port, getpid() );
	(void) fflush(logfp);
#endif
}


void
wn_abort( )
{

	this_conp->keepalive = FALSE;
	this_rp->type = RTYPE_FINISHED;
	this_rp->status |= (WN_ABORTED + WN_ERROR);
	
}

void
wn_exit( status)
int	status;
{
	int	n;
	char	buf[MIDLEN];

	if ( this_conp && (this_conp->chunk_status & WN_USE_CHUNK))
		end_chunking();
	flush_outbuf();
	if ( inheadp->tmpfile_name && *inheadp->tmpfile_name) {
		unlink( inheadp->tmpfile_name);
		*inheadp->tmpfile_name = '\0';
	}

	shutdown( fileno( stdin), 1);
	dump_log();

	if ( status != 0) {
		/* error condition */
		signal( SIGALRM, SIG_DFL);
		alarm( 3);  	
		/* Give ourselves at most 3 seconds to shutdown */
		while ( (n = WN_read( (fileno( stdin)), buf, MIDLEN)) > 0 ) {
			; /* Collect stuff from client and throw it away */
		}
	}

	close( fileno( stdin));
	exit( status);
}


static void
dump_log()
{
	register char	*cp,
			*cp2;

	char		*rfc931p;
	static int	looping = FALSE;

#ifndef NO_FLOCK
	struct flock	lck;
#endif

	if ( (! this_conp) || *(this_conp->logbuf) == '\0') {
		return;
	}
	get_remote_info( );


#ifndef NO_FLOCK
	locklog( &lck, fileno( logfp) );
#endif

#ifdef RFC931_TIMEOUT
	get_rfc931();
#endif
	rfc931p = ( *this_conp->rfc931name ? this_conp->rfc931name : "-");
	fseek( logfp, 0L, 2);

	cp = this_conp->logbuf;

	while ( (cp2 = strchr( cp, '\n')) ) {
		char save_ch;

		save_ch = *++cp2;
		*cp2 = '\0';
		fprintf( logfp, "%.255s %.100s %.1000s", 
			 this_conp->remotehost, rfc931p, cp);
		cp = cp2;
		*cp = save_ch;
		looping = FALSE;
	}
	if ( *cp && cp > this_conp->logbuf ) 
		mystrncpy( this_conp->logbuf, cp, LOGBUFLEN);
	if ( !*cp || looping ) {
		*(this_conp->logbuf) = '\0';
		looping = FALSE;
	}
	else if ( cp == this_conp->logbuf  )
		looping = TRUE;

	(void) fflush( logfp);


#ifndef NO_FLOCK
	unlocklog( &lck, fileno( logfp) );   
#endif

}
void
get_mtype( suffix )
char	*suffix;
{
	int	i,
		unknown_mime = TRUE;

	for ( i = 0; mimelist[i][0] != NULL; i++) {
		if ( streq( mimelist[i][0], suffix)) {
			mystrncpy( this_rp->contype, mimelist[i][1], SMALLLEN);
			this_rp->content_type = this_rp->contype;
			unknown_mime = FALSE;
			break;
		}
	}

	if ( STANDALONE && unknown_mime && (suflist != NULL)) {
		for ( i = 0; suflist[i] != NULL; i++) {
			if ( streq( suflist[i], suffix)) {
				mystrncpy( this_rp->contype, 
						mtypelist[i], SMALLLEN);
				this_rp->content_type = this_rp->contype;
				break;
			}
		}
	}
}

#if STANDALONE
int
needsuffix( suf)
char	*suf;

{
	int	i;

	for ( i = 0; mimelist[i][0] != NULL; i++) {
		if ( streq( suf, mimelist[i][0]))
			return FALSE;
	}
	return TRUE;
}
#endif  /* STANDALONE */

static unsigned
set_logtype( )
{
	unsigned logtype = 0;

	if ( USE_NO_LOG)
		logtype = WN_NO_LOG;

	else if ( USE_SYSLOGD )
		logtype = WN_LOG_SYSLOG;

	else if ( USE_FILE_LOG)
		logtype = WN_COMMON_LOG;

	if ( VERBOSELOG && (logtype == WN_COMMON_LOG))
		logtype = WN_VERBOSE_LOG;
	if ( VERBOSELOG && (logtype == WN_LOG_SYSLOG))
		logtype = WN_VERBOSE_SYSLOG;

	if ( NO_DNS_HOSTNAMES)
		logtype |= NO_DNS_LOG;

	if ( CHECK_DNS_HOSTNAMES)
		logtype |= REV_DNS_LOG;

	if ( logtype == 0)
		logtype = WN_NO_LOG;

	if ( logtype == WN_NO_LOG)
		logtype |= NO_DNS_LOG;

	mystrncpy (wnlogfile, WN_LOGFILE, SMALLLEN);
	mystrncpy (errlogfile, WN_ERRLOGFILE, SMALLLEN);

	return (logtype);
}


static void wnssl_init( errlogfp)
FILE *errlogfp;
{
#if MAKE_WNSSL
	FILE *fp;
	char *filename;

	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();

	ssl_ctx = (SSL_CTX *)SSL_CTX_new( SSLv23_server_method());

	if ( !SSL_CTX_set_default_verify_paths( ssl_ctx)) {
		daemon_logerr(  err_m[144], "", errno);
		wn_exit( 2);
	}

	if ( !*wn_ssl_cert_file) {
		const char *cp;

		if ( (cp = X509_get_default_cert_dir()) == NULL) {
			daemon_logerr(  err_m[138], "no_cert_directory", ERR_get_error());
			exit( 2);
		}
		fmt3(wn_ssl_cert_file, SMALLLEN, cp, "/", DEFAULT_CERT_FILENAME);
	}
	filename = wn_ssl_cert_file;
	fp = fopen(filename,"r");
	if (fp == NULL)  {
		daemon_logerr(  err_m[138], filename, ERR_get_error());
		exit( 2);
	}
	ssl_public_cert = X509_new();

	if ( wnPEM_read_X509( fp, &ssl_public_cert, NULL) == 0)  {
		daemon_logerr(  err_m[141],
				ERR_error_string(ERR_get_error(), NULL),
				ERR_get_error());
		exit( 2);
	}
	fclose(fp);

	filename = (*wn_ssl_key_file ?  wn_ssl_key_file : wn_ssl_cert_file );
	fp = fopen( filename, "r");

	if ( fp == NULL)  {
		daemon_logerr(  err_m[139], filename, ERR_get_error());
		exit( 2);
	}
	ssl_private_key = RSA_new();
	if (wnPEM_read_RSAPrivateKey( fp, &ssl_private_key, NULL) == 0)  {
		daemon_logerr(  err_m[140],
				ERR_error_string(ERR_get_error(), NULL),
				ERR_get_error());
		exit( 2);
	}
	if ( *wn_ssl_chain_file ) {
		if (!SSL_CTX_use_certificate_chain_file( ssl_ctx,
						wn_ssl_chain_file)) {
			daemon_logerr(  err_m[151], 
					wn_ssl_chain_file, ERR_get_error());
			exit( 2);
		}
	}
	fclose(fp);

	SSL_CTX_set_tmp_rsa_callback( ssl_ctx, TmpRSACallback);
#endif
}

static void wnssl_opts( optarg)
char *optarg;
{
#if MAKE_WNSSL
           if (strcmp( optarg, "debug") == 0 )  {
		   ssl_debug_flag = TRUE;
           }
           if (strcmp(optarg, "standalone") == 0 )  {
		   standalone_debug = TRUE;
           }
           if (strncmp(optarg, "verify=", sizeof("verify=")) == 0 )  {
		   ssl_verify_flag = atoi( optarg + sizeof( "verify="));
           }
           if (strncmp(optarg, "cert=", 5) == 0 )  {
		   mystrncpy( wn_ssl_cert_file, optarg + 5, SMALLLEN);
           }
           if (strncmp(optarg, "chain=", 6) == 0 )  {
		   mystrncpy( wn_ssl_chain_file, optarg + 6, SMALLLEN);
	   }
           if (strncmp(optarg, "key=", 4) == 0 )  {
		   mystrncpy( wn_ssl_key_file, optarg + 4, SMALLLEN);
           }
#endif
}

#if MAKE_WNSSL
static RSA *
TmpRSACallback( pSSL, nExport, nKeyLength)
SSL	*pSSL;
int	nExport,
	nKeyLength;
{
	static RSA *pRSA512 = NULL; 
	static RSA *pRSA1024 = NULL;

	if ( !nExport) {
		daemon_logerr(  err_m[142], "", errno);
		wn_exit( 2);
	/* Otherwise it was a sign-only key and we should set our keylength */
	}
	
	if ( !((nKeyLength == 512 || nKeyLength == 1024))) {
		daemon_logerr(  err_m[143], "", errno);
		wn_exit( 2);
	}

	if (pRSA512 == NULL && nKeyLength == 512)
		pRSA512 = RSA_generate_key( 512, RSA_F4, NULL, NULL);

	if (pRSA1024 == NULL && nKeyLength == 1024)
		pRSA1024= RSA_generate_key(1024, RSA_F4, NULL, NULL);
    
	return nKeyLength == 512 ? pRSA512 : pRSA1024;
} 
#endif /* MAKE_WNSSL */
