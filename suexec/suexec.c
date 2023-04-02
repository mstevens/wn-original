/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

/*
 * suexec.c -- "Wrapper" support program for suEXEC behaviour for Apache
 *
 ***********************************************************************
 *
 * NOTE! : DO NOT edit this code!!!  Unless you know what you are doing,
 *         editing this code might open up your system in unexpected 
 *         ways to would-be crackers.  Every precaution has been taken 
 *         to make this code as safe as possible; alter it at your own
 *         risk.
 *
 ***********************************************************************
 *
 *
 */


/* The code is slightly editted by Pim van Riezen en Sander Schippers
 * for some handy features.
 *
 * Added is a separate directory structure, in which shared applications 
 * can be placed. This is especialy usefull for the WN server for e.g.
 * cgi-handlers and filters.
 *
 * It was futher modified by John Franks for use with WN.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <stdarg.h>

#include "suexec.h"

#include "../config.h"
#include "../md5/md5.h"

#define AP_MAXPATH 8192

#define AP_ENVBUF 256

#define WN_SMALLLEN 256

extern char **environ;
static FILE *log = NULL;

static int 	fmt3( );
static void 	mk_md5digest( );

char *safe_env_lst[] =
{
	"AUTH_TYPE",
	"CONTENT_LENGTH",
	"CONTENT_TYPE",
	"DATE_GMT",
	"DATE_LOCAL",
	"DOCUMENT_NAME",
	"DOCUMENT_PATH_INFO",
	"DOCUMENT_ROOT",
	"DOCUMENT_URI",
	"FILEPATH_INFO",
	"GATEWAY_INTERFACE",
	"LAST_MODIFIED",
	"PATH_INFO",
	"PATH_TRANSLATED",
	"QUERY_STRING",
	"QUERY_STRING_UNESCAPED",
	"REMOTE_ADDR",
	"REMOTE_HOST",
	"REMOTE_IDENT",
	"REMOTE_PORT",
	"REMOTE_USER",
	"REDIRECT_QUERY_STRING",
	"REDIRECT_STATUS",
	"REDIRECT_URL",
	"REQUEST_METHOD",
	"REQUEST_URI",
	"SCRIPT_FILENAME",
	"SCRIPT_NAME",
	"SCRIPT_URI",
	"SCRIPT_URL",
	"SERVER_ADMIN",
	"SERVER_NAME",
	"SERVER_ADDR",
	"SERVER_PORT",
	"SERVER_PROTOCOL",
	"SERVER_SOFTWARE",
	"UNIQUE_ID",
	"URL_SCHEME",
	"USER_NAME",
	"TZ",
	"WN_ROOT",
	"WN_DIR_PATH",
	"WN_KEY",
	"HTTP_POST_FILE",
	"HTTP_PUT_FILE",
	NULL
};


static void err_output(const char *fmt, va_list ap)
{
#ifdef LOG_EXEC
	time_t timevar;
	struct tm *lt;

	if (!log) {
		if ((log = fopen(LOG_EXEC, "a")) == NULL) {
			time(&timevar);
			lt = localtime(&timevar);
			//fprintf(stderr, "failed to open log file\n");
			fprintf(stderr, "[%d-%.2d-%.2d %.2d:%.2d:%.2d]: ",
				lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
				lt->tm_hour, lt->tm_min, lt->tm_sec);
			vfprintf (stderr, fmt, ap);
			fflush (stderr);
			perror("fopen");
			exit(1);
		}
	}

	time(&timevar);
	lt = localtime(&timevar);

	fprintf(log, "[%d-%.2d-%.2d %.2d:%.2d:%.2d]: ",
		lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday,
		lt->tm_hour, lt->tm_min, lt->tm_sec);

	vfprintf(log, fmt, ap);

	fflush(log);
#endif /* LOG_EXEC */
	return;
}

static void log_err(const char *fmt,...)
{
#ifdef LOG_EXEC
	va_list ap;

	va_start(ap, fmt);
	err_output(fmt, ap);
	va_end(ap);
#endif /* LOG_EXEC */
	return;
}

static void clean_env( )
{
	char pathbuf[512];
	char **cleanenv;
	char **ep;
	int cidx = 0;
	int idx;


	if ((cleanenv = (char **) calloc(AP_ENVBUF, sizeof(char *))) == NULL) {
		log_err("failed to malloc memory for environment\n");
		exit(120);
	}

	sprintf(pathbuf, "PATH=%s", SAFE_PATH);
	cleanenv[cidx] = strdup(pathbuf);
	cidx++;

	for (ep = environ; *ep && cidx < AP_ENVBUF-1; ep++) {
		if (!strncmp(*ep, "HTTP_", 5)) {
			cleanenv[cidx] = *ep;
			cidx++;
		}
		else {
			for (idx = 0; safe_env_lst[idx]; idx++) {
				if (!strncmp(*ep, safe_env_lst[idx],
					     strlen(safe_env_lst[idx]))) {
					cleanenv[cidx] = *ep;
					cidx++;
					break;
				}
			}
		}
	}

	cleanenv[cidx] = NULL;
	environ = cleanenv;
}


int main(int argc, char *argv[])
{
    int userdir = FALSE;		/* ~userdir flag             */
    int wn_is_filter = FALSE;		/* filter flag             */
    int exemptdir = FALSE;		/* exempt path               */
    uid_t uid;				/* user information          */
    gid_t gid;				/* target group placeholder  */
    char *target_uname;		/* target user name          */
    char *target_gname;		/* target group name         */
    char *target_homedir;	/* target home directory     */
    char *wn_hash;		/* MD5 of secret:usr:group   */
    char *actual_uname;		/* actual user name          */
    char *actual_gname;		/* actual group name         */
    char *prog;			/* name of this program      */
    char *cmd;			/* command to be executed    */
    char cwd[AP_MAXPATH];	/* current working directory */
    char dwd[AP_MAXPATH];	/* docroot working directory */
    struct passwd *pw;		/* password entry holder     */
    struct group *gr;		/* group entry holder        */
    struct passwd *expw;	/* exemption pwd entry holdr */
    struct group *exgr;		/* exemption grp entry holdr */
    struct stat dir_info;	/* directory info holder     */
    struct stat prg_info;	/* program info holder       */

    /*
     * If there are a proper number of arguments, set
     * all of them to variables.  Otherwise, error out.
     */

    prog = argv[0];
    if (argc < 5) {
	log_err("too few arguments\n");
	exit( 2);
    }
    wn_hash = argv[1];
    target_uname = argv[2];
    target_gname = argv[3];
    cmd = argv[4];

    /*
     * Check existence/validity of the UID of the user
     * running this program.  Error out if invalid.
     * For WN also check we were execed by the WN server. 
     * This is done below by reading the server's secret key and
     * comparing the wn_hash value in argv[3] with the value
     * we calculate of MD5( "secret:user:group")
     */
    uid = getuid();
    if ((pw = getpwuid(uid)) == NULL) {
	log_err("invalid uid: (%ld)\n", uid);
	exit(102);
    }

    /*
     * Check to see if the user running this program
     * is the user allowed to do so as defined in
     * suexec.h.  If not the allowed user, error out.
     */
#ifdef _OSD_POSIX
    /* User name comparisons are case insensitive on BS2000/OSD */
    if (strcasecmp(HTTPD_USER, pw->pw_name)) {
        log_err("user mismatch (%s instead of %s)\n", pw->pw_name, HTTPD_USER);
	exit(103);
    }
#else  /*_OSD_POSIX*/
    if (strcmp(HTTPD_USER, pw->pw_name)) {
        log_err("user mismatch (%s instead of %s)\n", pw->pw_name, HTTPD_USER);
	exit(103);
    }
#endif /*_OSD_POSIX*/

    /*
     * For WN also check we were execed by the WN server. 
     * This is done by reading the server's secret key and
     * comparing the wn_hash value in argv[3] with the value
     * we calculate of MD5( "secret:user:group")
     */

    {
	    FILE	*kp;
	    char	*hashp,
		    	secret[WN_SMALLLEN],
			calc_hash[WN_SMALLLEN],
			buf[WN_SMALLLEN];

	    if ((kp = fopen( SUEXEC_KEY_FILE, "r")) == NULL) {
		    log_err("Can't open suexec key file %s\n", SUEXEC_KEY_FILE);
		    exit( 2);
	    }

	    if ( fgets( secret, WN_SMALLLEN - 1, kp) == NULL) {
		    log_err("Can't read suexec key file %s\n", SUEXEC_KEY_FILE);
		    exit( 2);
	    }

	    secret[strlen( secret) -1] = '\0';  /* remove \n at end */

	    fmt3( buf, WN_SMALLLEN, secret, ":", target_uname);
	    fmt3( buf, WN_SMALLLEN, buf, ":", target_gname);

	    mk_md5digest( buf, calc_hash);

	    hashp = wn_hash;
	    if ( strncmp( hashp, "WN", 2) == 0 )
		    hashp += 2;
	    else {
		    log_err("Invalid hash %s)\n", wn_hash);
		    exit( 2);
	    }

    /*
     * Check to see if this is a filtered request or a ~userdir request.  If
     * so, set the flag, and remove the 'x' and/or '~' from the hash
     */
	    if ( *hashp == 'x' ) {  /* it's a filtered item */
		    wn_is_filter = TRUE;
		    hashp++;
	    }

	    if ( *hashp == '~' ) {
		    userdir = TRUE;
		    hashp++;
	    }

	    if ( strcmp( calc_hash, hashp) != 0 ) {
		    log_err("hash mismatch (read %s, calculated %s)\n",
					hashp, calc_hash);
		    exit( 2);
	    }


           /* Check for a '/' in the command; there should be none. */
	    if ( strchr( cmd, '/') != NULL ) {
		    log_err("invalid command (%s) contains a '/'\n", cmd);
		    exit(2);
	    }
    }
	 
    if ( *target_uname == '~')		/* This shouldn't happen */
	target_uname++;


    /*
     * Error out if the target username is invalid.
     */
    if ((pw = getpwnam(target_uname)) == NULL) {
	log_err("invalid target user name: (%s)\n", target_uname);
	exit(105);
    }

    /*
     * Error out if the target group name is invalid.
     */
    if (strspn(target_gname, "1234567890") != strlen(target_gname)) {
	if ((gr = getgrnam(target_gname)) == NULL) {
	    log_err("invalid target group name: (%s)\n", target_gname);
	    exit(106);
	}
	gid = gr->gr_gid;
	actual_gname = strdup(gr->gr_name);
    }
    else {
	gid = atoi(target_gname);
	actual_gname = strdup(target_gname);
    }


    /*
     * Save these for later since initgroups will hose the struct
     */
    uid = pw->pw_uid;
    actual_uname = strdup(pw->pw_name);
    target_homedir = strdup(pw->pw_dir);

    /*
     * Log the transaction here to be sure we have an open log 
     * before we setuid().
     */
    log_err("uid: (%s/%s) gid: (%s/%s) cmd: %s\n",
	    target_uname, actual_uname,
	    target_gname, actual_gname,
	    cmd);

    /*
     * Error out if attempt is made to execute as root or as
     * a UID less than UID_MIN.  Tsk tsk.
     */
    if ((uid == 0) || (uid < UID_MIN)) {
	log_err("Cannot run as forbidden uid (%ld/%s)\n", uid, cmd);
	exit(107);
    }

    /*
     * Error out if attempt is made to execute as root group
     * or as a GID less than GID_MIN.  Tsk tsk.
     */
    if ((gid == 0) || (gid < GID_MIN)) {
	log_err("Cannot run as forbidden gid (%ld/%s)\n", gid, cmd);
	exit(108);
    }

    /* first attempt to getcwd as root to figure out if it's an exempt path */
    if (getcwd( cwd, AP_MAXPATH) == NULL) {
	log_err("Cannot get current working directory\n");
	exit(111);
    }

    /* Check if we are using the exempt path and remember if we are */
    if ( (strcmp( cwd, EXEMPT_PATH) == 0 ) && (strchr( cmd, '/') == NULL )) {
	    exemptdir = TRUE;
    }
	

    if (userdir) {
	if (((chdir(target_homedir)) != 0) ||
	    ((chdir(USERDIR_SUFFIX)) != 0) ||
	    ((getcwd(dwd, AP_MAXPATH)) == NULL) ||
	    ((chdir(cwd)) != 0)) {
	    log_err("Cannot get docroot information (%s) or (%s/%s)\n",
		    target_homedir, target_homedir, USERDIR_SUFFIX);
	    exit(112);
	}
    }
    else {
	if (((chdir(ROOT_DIR)) != 0) ||
	    ((getcwd(dwd, AP_MAXPATH)) == NULL) ||
	    ((chdir(cwd)) != 0)) {
	    log_err("Cannot get docroot information (%s)\n", ROOT_DIR);
	    exit(113);
	}
    }


    /* 
     * For WN change ownership of any temp file.
     */

    {
	    struct stat	stat_buf;
	    int		tdlen,
			cplen;
	    char	wn_tmpdir[sizeof(WN_TEMPDIR) + 20] = {WN_TEMPDIR},
			buf[20],
			*cp;

	    sprintf( buf, "/wn_tmp%ld", getuid( ));
	    fmt3( wn_tmpdir, (sizeof(WN_TEMPDIR) + 20), wn_tmpdir, buf, NULL );
	    tdlen = strlen( wn_tmpdir);

	    /*
	     * Check that HTTP_PUT/POST_FILEs are legitimate and exit
	     * if they aren't.
	     * If they are ok then we change their ownership and permissions.
	     */

	    if ( (cp = getenv( "HTTP_PUT_FILE")) != NULL ) {
		    cplen = strlen( cp);
		    if ( (strncmp( wn_tmpdir, cp, tdlen) != 0)
						|| ( cplen < tdlen + 2 )
						|| ( strchr( cp + tdlen + 1, '/') != NULL)
						|| ( strstr( cp, "/../") != NULL)) {
			    log_err("invalid HTTP_PUT_FILE (%s)\n", cp);
			    exit( 2);
		    }
		    if ( (lstat( cp, &stat_buf) != 0 ) || S_ISLNK( stat_buf.st_mode)) {
			    log_err("HTTP_PUT_FILE is missing or a symbolic link (%s)\n", cp);
			    exit( 2);
		    }
		    if (chown( cp, uid, gid) != 0)
			    log_err("Can't chown HTTP_PUT_FILE (%s)\n", cp);
		    if ( chmod( cp, (S_IRUSR | S_IRGRP)))
			    log_err("Can't chmod HTTP_PUT_FILE (%s)\n", cp);
	    }

	    if ( (cp = getenv( "HTTP_POST_FILE")) != NULL ) {
		    cplen = strlen( cp);
		    if ( (strncmp( wn_tmpdir, cp, tdlen) != 0)
						|| ( cplen < tdlen + 2 )
						|| ( strchr( cp + tdlen + 1, '/') != NULL)
						|| ( strstr( cp, "/../") != NULL)) {
			    log_err("invalid HTTP_POST_FILE (%s)\n", cp);
			    exit( 2);
		    }
		    if ( (lstat( cp, &stat_buf) != 0 ) || S_ISLNK( stat_buf.st_mode)) {
			    log_err("HTTP_POST_FILE is missing or a symbolic link (%s)\n", cp);
			    exit( 2);
		    }
		    if (chown( cp, uid, gid) != 0)
			    log_err("Can't chown HTTP_TEMP__FILE (%s)\n", cp);
		    if ( chmod( cp, (S_IRUSR | S_IRGRP)))
			    log_err("Can't chmod HTTP_PUT_FILE (%s)\n", cp);
	    }
	    if ( chmod( wn_tmpdir, 0711))
		    log_err("Can't chmod temp dir  (%s)\n", wn_tmpdir);
    }

    /*
     * Change UID/GID here so that the following tests work over NFS.
     *
     * Initialize the group access list for the target user,
     * and setgid() to the target group. If unsuccessful, error out.
     */
    if (((setgid(gid)) != 0) || (initgroups(actual_uname, gid) != 0)) {
	log_err("failed to setgid (%ld: %s)\n", gid, cmd);
	exit(109);
    }
    /*
     * setuid() to the target user.  Error out on fail.
     */
    if ((setuid(uid)) != 0) {
	log_err("failed to setuid (%ld: %s)\n", uid, cmd);
	exit(110);
    }

    /*
     * Get the current working directory, as well as the proper
     * document root (dependant upon whether or not it is a
     * ~userdir request).  Error out if we cannot get either one,
     * or if the current working directory is not in the docroot.
     * Use chdir()s and getcwd()s to avoid problems with symlinked
     * directories.  Yuck.
     */
    if (getcwd(cwd, AP_MAXPATH) == NULL) {
	log_err("Cannot get current working directory\n");
	exit(111);
    }

    if (userdir) {
	if (((chdir(target_homedir)) != 0) ||
	    ((chdir(USERDIR_SUFFIX)) != 0) ||
	    ((getcwd(dwd, AP_MAXPATH)) == NULL) ||
	    ((chdir(cwd)) != 0)) {
	    log_err("Cannot get docroot information (%s)\n", target_homedir);
	    exit(112);
	}
    }
    else {
	if (((chdir(ROOT_DIR)) != 0) ||
	    ((getcwd(dwd, AP_MAXPATH)) == NULL) ||
	    ((chdir(cwd)) != 0)) {
	    log_err("Cannot get docroot information (%s)\n", ROOT_DIR);
	    exit(113);
	}
    }


    if ( (strncmp(cwd, dwd, strlen(dwd)) != 0) &&
				(strncmp( cwd, EXEMPT_PATH, strlen( EXEMPT_PATH)) != 0) ) {
	log_err("Command (%s) not in docroot (%s != %s or %s)\n", cmd, cwd, dwd, EXEMPT_PATH);
	exit(114);
    }

    /*
     * Stat the cwd and verify it is a directory, or error out.
     */
    if (((lstat(cwd, &dir_info)) != 0) || !(S_ISDIR(dir_info.st_mode))) {
	log_err("Cannot stat directory: (%s)\n", cwd);
	exit(115);
    }

    /*
     * Error out if cwd is writable by others.
     */
    if ((dir_info.st_mode & S_IWOTH) || (dir_info.st_mode & S_IWGRP)) {
	log_err("directory is writable by others: (%s)\n", cwd);
	exit(116);
    }

    /*
     * Error out if we Cannot stat the program.
     */
    if (((lstat(cmd, &prg_info)) != 0) || (S_ISLNK(prg_info.st_mode))) {
	log_err("Cannot stat program: (%s)\n", cmd);
	exit(117);
    }

    /*
     * Error out if the program is writable by others.
     */
    if ((prg_info.st_mode & S_IWOTH) || (prg_info.st_mode & S_IWGRP)) {
	log_err("file is writable by others: (%s/%s)\n", cwd, cmd);
	exit(118);
    }

    /*
     * Error out if the file is setuid or setgid.
     */
    if ((prg_info.st_mode & S_ISUID) || (prg_info.st_mode & S_ISGID)) {
	log_err("file is either setuid or setgid: (%s/%s)\n", cwd, cmd);
	exit(119);
    }
    /*
     * Error out if the target name/group is different from
     * the name/group of the cwd or the program.
     */
       /*
        * Error out if the target username is invalid.
        */
    /* Code slightly modifyed for the added exempt group and user */
    if (exemptdir) {
	    if ((expw = getpwnam(EXEMPT_USER)) == NULL) {
		    log_err("invalid exempt user name: (%s)\n", EXEMPT_USER);
		    exit(120);
	    }
      /* printf ("Exempt User: %ld/%ld\n",expw->pw_uid,expw->pw_gid); */
	    if ((expw->pw_uid != dir_info.st_uid) ||
		(expw->pw_gid != dir_info.st_gid) ||
		(expw->pw_uid != prg_info.st_uid) ||
		(expw->pw_gid != prg_info.st_gid)) {
		    log_err("target exemptuid (%ld/%ld) mismatch "
			    "with directory %s (%ld/%ld) or program (%ld/%ld)\n",
			    expw->pw_uid,expw->pw_gid,
			    cwd,
			    dir_info.st_uid, dir_info.st_gid,
			    prg_info.st_uid, prg_info.st_gid);
		    exit (120);
	    }
    } else {
      if ((uid != dir_info.st_uid) ||
          (gid!= dir_info.st_gid) ||
	  (uid != prg_info.st_uid) ||
	  (gid != prg_info.st_gid)) {
	 log_err("target uid/gid (%ld/%ld) mismatch "
			"with directory %s (%ld/%ld) or program (%ld/%ld)\n",
			uid, gid,
 			cwd,
			dir_info.st_uid, dir_info.st_gid,
			prg_info.st_uid, prg_info.st_gid);
	exit(120);
      }
    }
    /*
     * Error out if the program is not executable for the user.
     * Otherwise, she won't find any error in the logs except for
     * "[error] Premature end of script headers: ..."
     */
    if (!(prg_info.st_mode & S_IXUSR)) {
	log_err("file has no execute permission: (%s/%s)\n", cwd, cmd);
	exit(121);
    }

    /* 
     * For WN, if we have a filtered doc, we must execute the 
     * filter with stdin set to the true doc.  We open the
     * true doc for reading and use dup2 to set it to stdin.
     */

    if ( wn_is_filter) {
	    int ffd;
	    char *cpx;

	    if ( (cpx = getenv( "WN_FILEPATH_INFO")) == NULL ) {
		    log_err( "Environment var WN_FILEPATH_INFO not set.\n");
		    exit( 2);
	    }
	    else if ( (ffd = open( cpx, O_RDONLY)) <= -1) {
		    log_err("Can't open filtered file %s: %s\n",
			    cpx, strerror( errno));
		    exit( 2);
	    }
	    close( 0);
	    if ( dup2( ffd, 0) == -1) {
		    log_err("Can't dup fd 0: %s\n", strerror( errno));
		    exit( 2);
	    }
	    close( ffd);
    }

    clean_env();

    /* 
     * Be sure to close the log file so the CGI can't
     * mess with it.  If the exec fails, it will be reopened 
     * automatically when log_err is called.  Note that the log
     * might not actually be open if LOG_EXEC isn't defined.
     * However, the "log" cell isn't ifdef'd so let's be defensive
     * and assume someone might have done something with it
     * outside an ifdef'd LOG_EXEC block.
     */

    if (log != NULL) {
	fclose(log);
	log = NULL;
    }

    /*
     * Execute the command, replacing our image with its own.
     */

    execv(cmd, &argv[4]);


    /*
     * (I can't help myself...sorry.)
     *
     * Uh oh.  Still here.  Where's the kaboom?  There was supposed to be an
     * EARTH-shattering kaboom!
     *
     * Oh well, log the failure and error out.
     */
    log_err("(%d)%s: exec failed (%s)\n", errno, strerror(errno), cmd);
    exit(255);
}


/*
 * mk_md5digest( in, out) takes the string "in" and calculates the MD5
 * digest placing the result in "out"
 */

static void 
mk_md5digest( in, out)
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
 * fmt3( buf, maxlen, s1, s2, s3) concatenates s1, s2, s3 in buf and
 * guarantees a null terminated string.  At most (n-1) chars TOTAL are
 * in the concatenated string.  Returns -1 if truncation occurred and
 * (n-1) minus number of bytes in new buf otherwise.  It will do the
 * right thing if buf == s1, i.e. append s2 and s3.  If any of 
 * s1, s2, or s3 are NULL they are skipped.
 */

static int
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
		log_err("Truncated string: %s\n", buf);
		return (-1);
	}
	else
		return (maxlen);

}
