/*
    Wn: A Server for the HTTP
    File: wn/prequest.c
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


#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include "wn.h"

extern char	*inet_ntoa();

#if USE_VIRTUAL_HOSTS
extern char	*vhostlist[][7];
#endif

#ifndef S_IROTH
#define		S_IROTH	0000004	/* read permission, other */
#endif

extern void	tilde(),
		www_unescape();

static int	dedot();

static	void	parse_cgi(),
		parse_param(),
		set_param(),
		path_security();

static time_t	max_mtime_includes();



/*

 * Fill in the fields basename, filepath, cachepath, query, pathinfo,
 * type, length and mod_date of the struct pointed by ip and corresponding
 * to the requested item whose header is pointed to by ih.  Note that
 * cachepath and filepath are strings while relpath and basename are
 * only pointers into filepath.

 */

void
parse_request( ip, url_path)
Request	*ip;
char	*url_path;
{
	int		trailslash = FALSE;
	register char	*cp;

	char		redirect[MIDLEN],
			path[MIDLEN];

	ip->type = RTYPE_UNCHECKED; /* we don't know type yet */

	if ( inheadp->method ==  TRACE) {
		/* nothing to do */
		ip->type = RTYPE_FINISHED;
		return;
	}

	if ( inheadp->method ==  OPTIONS) {
		if ( *url_path == '*') {
			ip->status &= ~(WN_HAS_BODY);
			mystrncpy( outheadp->list, "Content-length: 0\r\n",30);
			mystrncat( outheadp->list,
				"Allow: GET, HEAD, TRACE, OPTIONS\r\n", BIGLEN); 
			http_prolog( );
			writelog( ip, log_m[22], "");
			ip->type = RTYPE_FINISHED;
			return;
		}
	}

	if ( (inheadp->protocol ==  HTTP1_1) &&	(!*inheadp->host_head) ) {
		/* Missing Host: header in 1.1 request is an error */
		senderr(CLIENT_ERR, err_m[15], "");
		return;
	}

	/*
	 * Here are the initial steps in correct order:
	 *
	 * 1. Get hostname from "http://host/..." if it is there
	 *  and remove this part of url_path.  Call set_interface_root().
	 * 2. Find first ? and put everything after it in ip->query
	 * 3. Copy remainder to path
	 * 4. If path is only "/" make it DEFAULT_URI
	 * 4. Undo URL escapes on path ( www_unescsape)
	 * 6. Check if ip->rootdir should be changed and do it (tilde)
	 * 7. Parse for CGI setting PATH_INFO (parse_cgi)
	 * 8. Check for last ; or = and parse parameters
	 * 9. Dedot
	 * 10. Check path security (path_security)
	 * 11. Remove trailing slash if there.
	 * 12. Fill in filepath, and pointers relpath and basename
	 * 13. If it's an nph-CGI set ip->type = RTYPE_NPH_CGI
	 */

	if ( (strncasecmp( url_path, "http://", 7) == 0 ) ||
			(strncasecmp( url_path, "https://", 8) == 0 )) {
		cp = strchr( url_path, ':');
		url_path = cp + 3;

		cp = strchr( url_path, '/');
		if ( cp != NULL)
			*cp = '\0';
		mystrncpy( inheadp->host_head, url_path, MAXHOSTNAMELEN);
		if ( cp != NULL) {
			*cp = '/';
			url_path = cp;
		}
		else
			url_path = "/";
	}

	set_interface_root( );

	if ( ( cp = strchr( url_path, '?')) != NULL) {
		*cp++  = '\0';
		mystrncpy( ip->query, cp, MIDLEN);
		/* Decoding happens in cgi.c and csearch.c/check_query() */
		mystrncpy( path, url_path, MIDLEN);
		*--cp = '?'; 
	}
	else
		mystrncpy( path, url_path, MIDLEN);


	www_unescape( path, '+');

	if ( path[1] == '\0') {
		/* path = "/"" */
		mystrncpy( path , DEFAULT_URI, MIDLEN);
		ip->filetype |= WN_DEFAULT_DOC;
	}

	if ( path[1] ==  ';') {
		/* path =  "/;something" */
		mystrncpy( path , DEFAULT_URI, MIDLEN);
		ip->filetype |= WN_DEFAULT_DOC;
		mystrncat( path, &url_path[1], MIDLEN );
	}

	tilde( ip, path);

	if ( ip->type == RTYPE_FINISHED)
		return;

	parse_cgi( ip, path);

	parse_param( ip, path);

	while (dedot( ip, path))
		;

	path_security( ip, path, FALSE);

	if ( ip->type == RTYPE_FINISHED)
		return;

	cp = path;
	/* move cp to end of path */
	while ( *cp)
		cp++;
	cp--;

	if ( *cp == '/') {
			/* Remove trailing '/'  if there */
		*cp = '\0';
		trailslash = TRUE;
	}


	/* Fill in filepath, and pointers relpath and basename */

	mystrncpy( ip->filepath, ip->rootdir, MAXDIRLEN);
	cp = ip->filepath;
	while ( *cp)
		cp++;
	ip->relpath = cp;
	mystrncpy( ip->relpath, path, MIDLEN - (MAXDIRLEN + TINYLEN + 4));

	cp = strrchr( ip->filepath, '/');
	ip->basename = ++cp;

	if ( (ip->type == RTYPE_CGI) && 
				( strncmp( ip->basename, "nph-", 4) == 0) )
		ip->type = RTYPE_NPH_CGI;
	if ( inheadp->range && *inheadp->range ) {
		if ( (cp = strchr( inheadp->range, '=')) != NULL) {
			cp++;
			while ( *cp && isspace( *cp))
				cp++;
			if ( strncasecmp( inheadp->range, "bytes", 5) != 0 ) {
				senderr(CLIENT_ERR, err_m[103],
							inheadp->range);
				return;
			}
			mystrncpy( ip->range, cp, RANGELEN);
			ip->filetype |= (WN_BYTERANGE + WN_RFC_BYTERANGE);
		}
		else {
			senderr( CLIENT_ERR, err_m[95], inheadp->range);
			return;
		}
	}

	set_param( ip);

	if ( ip->type == RTYPE_FINISHED)
		return;
	if (ip->type == RTYPE_DENIED) {
		logerr( err_m[85], ip->param_field);
		return;
	}

	get_stat( ip);

	if ( iswndir( ip) ) {
	/*
	 * Directory: if not a search change to file "index.html"
	 * in that directory unless it didn't end in a '/' in which
	 * case we must send a redirect to get relative URLs to work.
	 */
		switch ( ip->type) {
		case RTYPE_CGI:
		case RTYPE_NPH_CGI:
			senderr( SERV_ERR, err_m[102], url_path);
			return;
		default:
			break;
		}
		if ( !trailslash) {
			char	*lhost;

			lhost = ( *(inheadp->host_head) ?
				(inheadp->host_head) : hostname );

			if ( strchr( url_path, ';') || 	strchr( url_path, '?')
					 || strchr( url_path, '=') ) {
				senderr( CLIENT_ERR, err_m[59], path);
				return;
			}
			if ( (port == STANDARD_PORT) ||
					( strchr( lhost, ':') != NULL) )
				Snprintf3( redirect, MIDLEN, 
					"%.32s://%.100s%.1536s/", 
					this_conp->scheme, lhost, url_path);
			else
				Snprintf4( redirect, MIDLEN, 
						"%.32s://%.100s:%d%.1536s/",
						this_conp->scheme, lhost,
						port, url_path);
			sendredirect( ip, "301 Moved Permanently", redirect);
			ip->type = RTYPE_FINISHED;
			return;
		}
		switch ( ip->type) {
		case RTYPE_UNCHECKED:
		case RTYPE_INFO:
			cp = ip->filepath;
			mystrncat ( ip->filepath, "/", MIDLEN);
			mystrncat ( ip->filepath, INDEXFILE_NAME, MIDLEN);
			ip->filetype &= ~(WN_DIR);
			ip->filetype |= WN_DEFAULT_DOC;
			get_stat( ip);
			ip->basename = strrchr( ip->filepath, '/') + 1;
			break;
		default:
			break;
		}
	}
	else if ( trailslash) {
			/* iswndir( ip) is false; it's not a directory */
			/* put slash back on path for DENYHANDLER --ckd */
			mystrncat ( ip->filepath, "/", MIDLEN);  
			ip->type = RTYPE_DENIED;
			return;
	}

	mystrncpy( ip->cachepath, ip->filepath, MIDLEN); /* both have size MIDLEN */

	if ( iswndir( ip) )
		mystrncat( ip->cachepath, "/", MIDLEN);
	if ( (cp = strrchr( ip->cachepath, '/')) == NULL) {
		mystrncpy( ip->cachepath, "/", MIDLEN);
	}
	else {
		*++cp = '\0';
	}
	mystrncat( ip->cachepath, cfname,  MIDLEN);
}

/*
 * set_param( ip) takes the param field and param value (already set up
 * by parse_param() ) and does the appropriate thing.  E. g. enter
 * the range or set ip->type.
 */

static void
set_param( ip)
Request	*ip;
{
	register char	c,
			*cp;

	c = *ip->param_field;
	c = (isupper (c) ? tolower (c) : c);
	switch( c) {
	case '\0':
			break;

		/* Byte or line range */
	case 'b':	
		mystrncpy( ip->range, ip->param_value, RANGELEN);
		ip->filetype |= WN_BYTERANGE;
		break;
	case 'l':
		mystrncpy( ip->range, ip->param_value, RANGELEN);
		ip->filetype |= WN_LINERANGE;
		break;

	case 'i':	/* info */
			ip->type = RTYPE_INFO;
			break;

	case 'm':				/* meta or markline */
		if ( streq( ip->param_field, "meta")) {
			ip->type = RTYPE_INFO;
			break;
		}
		if ( strncmp( ip->param_field, "mark", 4) == 0) {
			ip->type = RTYPE_MARKLINE;
			ip->attributes |= WN_PARSE;
			break;
		}
		ip->type = RTYPE_DENIED;
		break;
	case 's':	/* Search */
		if ( (cp = strstr( ip->query, "mode=")) != NULL) {
			mystrncpy( ip->param_field, cp + 5, SMALLLEN);
			ip->param_value = ip->param_field;
			if ( (cp = strchr( ip->param_value, '&')) != NULL)
				*cp = '\0';
		}

		if ( (cp = strstr( ip->query, "query=")) != NULL) {
			mystrncpy( ip->query, cp + 6, MIDLEN);
			if ( (cp = strchr( ip->query, '&')) != NULL)
				*cp = '\0';
		}
		
		c = *ip->param_value;
		c = (isupper (c) ? tolower (c) : c);
		switch( c) {
		case 'c':
			ip->type = RTYPE_CONTEXTSEARCH;
			break;
		case 'f':
			if ( strncasecmp( ip->param_value, "field", 5) == 0)
				ip->type = RTYPE_FIELDSEARCH;
			else {
				senderr( SERV_ERR, err_m[58], ip->param_value);
				return;
			}
			break;
		case 'g':
			ip->type = RTYPE_GSEARCH;	/* grep */
			break;
		case 'i':
			ip->type = RTYPE_ISEARCH;	/* index search */
			break;
		case 'k':
			ip->type = RTYPE_KSEARCH;	/* keyword */
			break;
		case 'l':
			if ( strncasecmp( ip->param_value, "line", 4) == 0) {
				ip->type = RTYPE_LINESSEARCH;
				break;
			}
			ip->type = RTYPE_LISTSEARCH;	/* list search */
			break;
		case 't':
			ip->type = RTYPE_TSEARCH;	/* title */
			break;
		case 's':
			ip->type = RTYPE_TKSEARCH;	/* title and keyword */
			break;
		}
		break;
	default: 
		ip->type = RTYPE_DENIED;
	}
}


/*
 * get_stat( ip)
 * Stats the file pointed to by ip->filepath.  If it fails assume file
 * does not exist.  If it is a directory set WN_DIR bit in ip->filetype
 * unless this is the default document, in which case log an error and
 * deny access. If not a directory make sure it is a regular file and
 * if so, get length and modification time and set the etag.
 */

void
get_stat( ip)
Request	*ip;
{
	struct stat	stat_buf;


#ifndef S_ISREG
#define	S_ISREG(m)	(((m)&S_IFMT) == S_IFREG)
#endif
	if ( lstat( ip->filepath, &stat_buf) != 0 ) {
		/* Might be redirect, or defdoc, just continue */
		*ip->length = '\0';
		ip->mod_time = 0;
		ip->status |= WN_CANT_STAT;
		return;
	}

	if ( (!S_ISREG(stat_buf.st_mode)) && (!S_ISDIR(stat_buf.st_mode))) { 
		/* probably a symlink */
		if ( stat( ip->filepath, &stat_buf) != 0 ) {
			*ip->length = '\0';
			ip->mod_time = 0;
			ip->status |= WN_CANT_STAT;
			return;
		}
		ip->filetype |= WN_NOT_REG_FILE;
	}


	if ( stat_buf.st_mode & S_IWOTH)
		ip->filetype |= WN_WORLD_WRITABLE;

	if ( !(stat_buf.st_mode & S_IROTH))
		ip->filetype |= WN_NOT_WORLD_READ;

	if ( S_ISDIR( stat_buf.st_mode)) {
		if ( ip->filetype & WN_DEFAULT_DOC) {
			logerr( err_m[88], ip->filepath);
			ip->type = RTYPE_DENIED;
		}
		else
			ip->filetype |= WN_DIR;
		return;
	}


	if ( !(S_ISREG(stat_buf.st_mode))) {
		logerr( err_m[115], ip->filepath);
		ip->type = RTYPE_DENIED;
		return;
	}

	ip->mod_time = stat_buf.st_mtime;
	ip->datalen = (unsigned long) stat_buf.st_size;
	Snprintf1( ip->length, TINYLEN, "%lu", ip->datalen);
	set_etag( &stat_buf);
}

void
set_etag( sbp)
struct stat *sbp;
{
	Snprintf3( this_rp->etag, 2*TINYLEN, "%lx=%lx=%lx", (long) sbp->st_mtime,
				(long) sbp->st_ino, (long) sbp->st_size);
}

static void
parse_cgi( ip, path)
Request	*ip;
char	*path;
{
	register char	*fnd = NULL,
			*cp,
			*extp;

	char	buf[SMALLLEN];

	if ( ip->type == RTYPE_FINISHED)
		return;

	mystrncpy( buf, CGI_EXT_LIST, SMALLLEN);
	extp = buf;
	while ( extp ) {
		if ((cp = strchr( extp, ',')) != NULL) 
			*cp = '\0';
		if ( (fnd = strstr( path, extp)) != NULL)
			break;
		if ( cp != NULL ) {
			extp = ++cp;
		}
		else {
			extp = NULL;
		}
	}
			
	*(ip->pathinfo) = '\0';
	
	if ( (extp != NULL) && (fnd != NULL)) {
		/* extp points to extension, fnd points to occurence in path */
		fnd += strlen( extp);
		if ( (*fnd == '/') || (*fnd == '\0')) {
			ip->type = RTYPE_CGI;
			ip->attributes |= WN_NOSEARCH;
			ip->allowed |= WN_M_POST;
			mystrncpy( ip->pathinfo, fnd, MIDLEN);
			*fnd = '\0';
			path_security( ip, ip->pathinfo, TRUE);
			return;
		}
		if ( *fnd == ';' ) {  /* .cgi; is an error */
			senderr( CLIENT_ERR, err_m[129], fnd);
			return;
		}
	}

#ifdef CGI_BIN
	if ( (cp = strstr( path, CGI_BIN)) != NULL) {
		cp--;
		if ( (cp < path) || (*cp != '/'))
			return;
		cp += sizeof( CGI_BIN);
		if ( *cp == '/') {
			cp++;
			ip->attrib2 |= WN_ISACGIBIN;
			ip->type = RTYPE_CGI;
			ip->attributes |= WN_NOSEARCH;
			ip->allowed |= WN_M_POST;
			if ( (cp = strchr( cp, '/')) != NULL) {
				mystrncpy( ip->pathinfo, cp, MIDLEN);
				*cp = '\0';
				path_security( ip, ip->pathinfo, TRUE);
			}
			return;
		}
		if ( !*cp )
			ip->attrib2 |= WN_ISACGIBIN;
	}
#endif
	/* not CGI so no POST */
	ip->allowed &= ~WN_M_POST;
}

static void
parse_param( ip, path)
Request	*ip;
char	*path;
{
	register char	*cp;

	if ( ip->type == RTYPE_FINISHED)
		return;

	/* First handle ';' delimiter (for files) */
	if ( ( cp = strrchr( path, ';')) != NULL) {
		if ( *(cp - 1) == '/' ) {  /* path with /; is error */
			senderr(CLIENT_ERR, err_m[59], path);
			return;
		}
		*cp++  = '\0';
	}
	/* Now handle '/' delimiter (for directories) */
	else if ( ( cp = strrchr( path, '=')) != NULL) {
		while ( (cp > path) && (*cp != '/'))
			cp--;
		++cp;
	}
	else
		return;
		
	mystrncpy( ip->param_field, cp, SMALLLEN);
	*cp = '\0';

	if ( (cp = strchr( ip->param_field, '=')) != NULL) {
		*cp = '\0';
		ip->param_value = ++cp;
	}
	else {
		cp = ip->param_field;
		while ( *cp)
			cp++;
		ip->param_value = cp;
	}
	return;
}


/*
 * path_security( ip, path, is_pathinfo) generates an error if any bad 
 * characters are found in the URI.  Allowable chars are any alpha-numeric or
 * '_', '-', '.', '+', '/', and '%'.  Also "../" is disallowed (the function
 * dedot() has already handled "/../" and "/./".  We also check that
 * path is either empty (referring to root) or begins with '/'.
 * Things are a little more lax for the PATHINFO part of a CGI URL.
 * At the moment this means that '=' and '@' are allowed.
 */

static void
path_security( ip, path, is_pathinfo)
Request	*ip;
char	*path;
int	is_pathinfo;
{
	register char	*cp;
	char		buf[SMALLLEN];

	/* Security check */
	cp = path;
	if ( *cp && (*cp != '/') ) {
		senderr( CLIENT_ERR, err_m[59], path);
		return;
	}

	while ( *cp ) {
		if ( myisalnum( *cp))
			cp++;
		else {
			switch( *cp) {
			case '.':
				if ( (cp[1] == '.') && (cp[2] == '/')) {
					logerr( err_m[21], ip->request);
					senderr( CLIENT_ERR, err_m[59], path);
					return;
				}
			case '/':
			case '-':
			case '+':
			case '_':
			case '%':
				cp++;
				break;
			/* Stuff allowed for pathinfo here */
			case '=':
			case '@':
				if ( is_pathinfo) {
					cp++;
					break;
				}
			default:
				Snprintf1( buf, SMALLLEN, err_m[20], *cp);
				logerr( buf, ip->request);
				senderr( CLIENT_ERR, err_m[59], path);
				return;
			}
		}
	}
}


/*
 * dedot( ip, path) replaces the first "//", "/./", and "/xxxx/../" 
 * in path with "/".  It returns TRUE if it found one of these
 * and FALSE if there were none of these in path.  path has size MIDLEN.
 */

static int
dedot( ip, path)
Request	*ip;
char	*path;
{
	register char	*cp,
			*cp2;

	if ( ip->type == RTYPE_FINISHED)
		return FALSE;

	cp = path;
	while ( (cp = strchr( cp, '/')) != NULL) {
		cp++;
		if ( *cp == '/') {
			cp2 = cp + 1;
			while ( *cp2 && *cp2 == '/')
				cp2++;
			mystrncpy( cp, cp2, MIDLEN);
			return TRUE;
		}
		if ( strncmp( cp, "./", 2) == 0 ) {
			mystrncpy( cp, cp + 2, MIDLEN);
			return TRUE;
		}
		if ( strncmp( cp, "../", 3) == 0 ) {
			*--cp = '\0';
			if ( (cp2 = strrchr( path, '/')) == NULL) {
				logerr( err_m[21], ip->request);
				senderr( CLIENT_ERR, err_m[59], path);
				return FALSE;
		}
			mystrncpy( cp2, cp + 3, MIDLEN);
			return TRUE;
		}
	}
	return FALSE;
}


/*
 * getfpath( path, fname, ip) takes filename in fname and translates
 * to complete path relative to system root.
 * If fname starts with '/' assume it is relative to system root,
 * if it starts with ~/ it is relative to WN root  otherwise
 * assume relative to current directory.  Assume path can hold MIDLEN chars.
 */

int
getfpath( path, fname, ip)
char	*path,
	*fname;
Request	*ip;
{

#ifdef LIMIT_2_HIERARCHY
	return getfpath2( path, fname, ip->cachepath);
#else
	register char	*cp;

	if ( *fname == '/') {
		mystrncpy( path, fname, MIDLEN);
	}
	else if ( *fname == '~' && *(fname + 1) == '/') {
		mystrncpy( path, ip->rootdir, MIDLEN);
		mystrncat( path, fname + 1, MIDLEN);
	}
	else {
		mystrncpy( path, ip->cachepath, MIDLEN);
		if ( (cp = strrchr( path, '/')) == NULL) {
			logerr( err_m[37], path);
			return FALSE;
		}
		else {
			*++cp = '\0';
			mystrncat( path, fname, MIDLEN);
		}
	}				
	return TRUE;
#endif
}


/*
 * getfpath2( path, fname, cachepath) is like getfpath except it restricts
 * to WN hierarchy.  If fname starts with either '/' or '~/' then
 * it is assumed relative to WN root  otherwise it is assumed 
 * relative to current directory.
 */

int
getfpath2( path, fname, cachepath)
char	*path,
	*fname,
	*cachepath;
{

	register char	*cp;

	if ( *fname == '~')
		fname++;
	if ( *fname == '/') {
		mystrncpy( path, this_rp->rootdir, MIDLEN);
		mystrncat( path, fname, MIDLEN);
	}
	else {
		mystrncpy( path, cachepath, MIDLEN);
		if ( (cp = strrchr( path, '/')) == NULL) {
			logerr( err_m[37], path);
			return FALSE;
		}
		else {
			*++cp = '\0';
			mystrncat( path, fname, MIDLEN);
		}
	}				
	if ( strstr( "../", path) != NULL) {
		logerr( err_m[21], path);
		return FALSE;
	}
	return TRUE;
}


/*
 * Return the maximum file modification time for the files in an
 * includes/wrappers style comma separated list. (Thanks to David Capshaw)
 */

static time_t
max_mtime_includes( inclptr, ip)
char * inclptr;
Request *ip;
{
	register char *cp;
	struct stat stat_buf;
	time_t  max_mtime;
	char inclname[MIDLEN];
	char fullpath[MIDLEN];

	max_mtime = 0;

	if (inclptr) {
		/* Extract, expand and stat each entry in the include list. */
		while (*inclptr) {
        		while ( *inclptr && *inclptr == ',')
				inclptr++;

			cp = inclname;
        		while ( *inclptr && (*inclptr != ',') && 
						(cp < &inclname[MIDLEN - 1]))
				*cp++ = *inclptr++;
			*cp++ = '\0';

			if (getfpath( fullpath, inclname, ip) &&
		    	    (stat(fullpath, &stat_buf) == 0) &&
		    	    stat_buf.st_mtime > max_mtime ) {
				max_mtime = stat_buf.st_mtime;
			}
		}
	}

	return max_mtime;
}




/*
 * Update mod_time considering the includes/wrappers files.
 * (Thanks to David Capshaw)
 */

void
update_mod_time(ip)
Request *ip;
{
	time_t  mtime, max_mtime;
	struct stat stat_buf;

	max_mtime = (time_t) 0;

	if ( ip->attrib2 & WN_WRAPPED) {
		if ( strchr( ip->wrappers, '!')) {
			ip->mod_time = (time_t) 0;
			return;
		}
		mtime = max_mtime_includes(ip->wrappers, ip);
		if (mtime > max_mtime) {
			max_mtime = mtime;
		}
	}

	if ( ip->attrib2 & WN_INCLUDE ) {
		if ( strchr( ip->includes, '!')) {
			ip->mod_time = (time_t) 0;
			return;
		}
		mtime = max_mtime_includes(ip->includes, ip);
		if (mtime > max_mtime) {
			max_mtime = mtime;
		}
	}

	if ( ip->attrib2 & WN_LIST_INCL ) {
		if ( strchr( ip->list_incl, '!')) {
			ip->mod_time = (time_t) 0;
			return;
		}
		mtime = max_mtime_includes(ip->list_incl, ip);
		if (mtime > max_mtime) {
			max_mtime = mtime;
		}
	}

	if (max_mtime) {
		/*
		 * There was a wrapper/include so restat base
		 * file and regenerate mod_time value.
		 */
		if ((stat(ip->filepath, &stat_buf) == 0) &&
		    stat_buf.st_mtime > max_mtime ) {
			max_mtime = stat_buf.st_mtime;
		}

		ip->mod_time = max_mtime;
	}
}



/*
 * set_interface_root() checks the hostname and IP address to which
 * the client has connected and sets our data root (this_rp->rootdir[]) to the
 * apprpropriate value.  The appropriate value is determined by consulting
 * the array vhostlist[][0] which is defined and initialized in vhost.c.
 * If inheadp->host_head contains something it is a hostname set from
 * either the Host: header or a full URL in the request.  If any hostname in
 * the vhostlist matches this then the root dir corresponding to the
 * first match is used.  If the Host: header or URL contains an IP address
 * then the first match to vhostlist[][1] is used.  If no hostname has been
 * set by Host: or URL or if no match as above was found then the IP 
 * addresses from vhostlist[][1] are searched for a match to the IP address
 * on which the request was received.  The root dir corresponding to the
 * first such match is used.  If there is still no match the default rootdir
 * set on the command line or in config.h is used.
 */

#if USE_VIRTUAL_HOSTS
void
set_interface_root( )
{
	static char local_ip[20] = "";
	int	size;
	unsigned ifn = 0;

	char	*cp,
		lhostname[MAXHOSTNAMELEN];

	static struct sockaddr_in      saddr;
        
	this_rp->vhost_user = NULL;
	this_rp->vhost_group = NULL;
	this_rp->vhost_flag = DEFAULT_VHOST_FLAG;
 
	if ( *(inheadp->host_head)) {
		mystrncpy( lhostname, inheadp->host_head, MAXHOSTNAMELEN);
		if ( (cp = strchr( lhostname, ':')) != NULL) 
			*cp = '\0';
		while ( vhostlist[ifn][2] != NULL) {
			if ( (strcasecmp( vhostlist[ifn][0], lhostname) == 0)
				|| streq( vhostlist[ifn][1] , lhostname))  {
				mystrncpy( this_rp->rootdir,
					vhostlist[ifn][2], SMALLLEN);
				mystrncpy( hostname, lhostname, SMALLLEN);
				this_rp->vhost_user = (char *) vhostlist[ifn][4];
				this_rp->vhost_group = (char *) vhostlist[ifn][5];
				if ( vhostlist[ifn][6] != NULL )
					this_rp->vhost_flag = (unsigned long) atol( vhostlist[ifn][6]);
				break;
			}
			ifn++;
		}
	}
	if ( !*(inheadp->host_head) || (vhostlist[ifn][2] == NULL)) {
	/* if no host header or no match for host header use IP# */
		if ( !*local_ip) {
			size = sizeof(saddr);
			if ( getsockname( fileno( stdin),
				(struct sockaddr *) &saddr, &size) < 0 ) {
				logerr( err_m[73], "");
				mystrncpy(local_ip, "127.0.0.1", 20);

			}
			else {
				mystrncpy(local_ip, 
					inet_ntoa(saddr.sin_addr), 20);
			}
		}
		for ( ifn = 0; vhostlist[ifn][2] != NULL; ifn++) {
			if ( streq( vhostlist[ifn][1] , local_ip)) {
				mystrncpy( this_rp->rootdir,
					vhostlist[ifn][2], SMALLLEN);
                  		this_rp->vhost_user = (char *) vhostlist[ifn][4];
                  		this_rp->vhost_group = (char *) vhostlist[ifn][5];
				if ( vhostlist[ifn][6] != NULL )
					this_rp->vhost_flag = (unsigned long) atol( vhostlist[ifn][6]);
				cp = vhostlist[ifn][0];
				if ( !*cp)
					cp = local_ip;
				mystrncpy( hostname, cp, SMALLLEN);
				break;
			}
		}
	}
	interface_num = ((vhostlist[ifn][2] == NULL) ? 0 : ++ifn);
	/* Set interface to zero if nothing matched, otherwise (ifn + 1) */
	if ( interface_num == 0)
		mystrncpy( this_rp->rootdir, rootdir, SMALLLEN);
	/* Use default rootdir if no matches */
}
#else
void
set_interface_root( )
{
		mystrncpy( this_rp->rootdir, rootdir, SMALLLEN);
}
#endif
