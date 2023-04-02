/*
    Wn: A Server for the HTTP
    File: wn/chkcntrl.c
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


#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "wn.h"
#include "chkcntrl.h"
#include "access.h"


extern int	chkauth();

extern long	atol();

static int	mask_match(),
		wild_match(),
		wild_match_rem(),
		get_def_cachepath( );

static void	setdirvalue(),
		setvalue(),
		handlers(),
		do_serveall();


/*

 * chk_cntrl( ip) checks to see that the URL sent by the client is a
 * valid one, i.e. that basename exists in a control file in the
 * designated directory.  It also enters some additional fields in the
 * Request struct pointed to by ip, namely "title", "content_type",
 * "encoding", "wrappers", "includes", etc.  It gets this information
 * from the cached control file.

 */

void
chk_cntrl( ip)
Request	*ip;
{
	struct stat stat_buf;

	FILE	*fp;

	char	*authmod,
		*authtype;

	int	i,
		access_status = ACCESS_DENIED;

	Cache_entry	*cep,
			entry;


	mystrncpy( dir_p->noaccess_url, ACCESS_DENIED_URL, MIDLEN/2);
	mystrncpy( dir_p->cantstat_url, NO_SUCH_FILE_URL, MIDLEN/2);
	mystrncpy( dir_p->authdenied_file, AUTH_DENIED_FILE, MIDLEN/2);

	if ( ip->type == RTYPE_DENIED )  /* done in parse_request */
		return;

	if ( lstat( ip->cachepath, &stat_buf) != 0 ) {
		if ( (get_def_cachepath( ip) == FALSE) || (lstat( ip->cachepath, &stat_buf) != 0 )) {
			writelog( ip,  err_m[2], ip->cachepath);
			ip->type = RTYPE_DENIED;
			ip->status |= WN_CANT_STAT;
			return;
		}
	}


#ifndef S_ISREG
#define	S_ISREG(m)	(((m)&S_IFMT) == S_IFREG)
#endif

	if ( !(S_ISREG(stat_buf.st_mode))) {
		senderr( SERV_ERR, err_m[13], ip->cachepath);
		return;
	}
	dir_p->cache_uid = (unsigned) stat_buf.st_uid;
	dir_p->cache_gid = (unsigned) stat_buf.st_gid;
	dir_p->cmod_time =  stat_buf.st_mtime;

	if ( (!WN_OPT_U) && (WN_OPT_T) && (!IS_TRUSTED) ) {
		logerr( err_m[7], ip->cachepath);
		ip->type = RTYPE_DENIED;
		return;
	}

	if ( stat_buf.st_uid == (uid_t) user_id) {
		logerr( err_m[8], ip->cachepath);
		ip->type = RTYPE_DENIED;
		return;
	}

	if ( stat_buf.st_mode & S_IWOTH) {
		logerr( err_m[8], ip->cachepath);
		ip->type = RTYPE_DENIED;
		return;
	}

	if ( (stat_buf.st_gid == (gid_t) group_id) && ( stat_buf.st_mode & S_IWGRP)) {
		logerr( err_m[8], ip->cachepath);
		ip->type = RTYPE_DENIED;
		return;
	}

	if ( WN_STRICT_SECURITY ) {
		if ( ip->filetype & WN_WORLD_WRITABLE) {
			logerr( err_m[134], ip->filepath);
			ip->type = RTYPE_DENIED;
			return;
		}

	}

	if ( (fp = fopen( ip->cachepath, "r")) == (FILE *) NULL ) {
		logerr( err_m[9], ip->cachepath);
		ip->type = RTYPE_DENIED;
		return;
	}

	read_cache_dirinfo( fp, dir_p);

	access_status = chkaccess( ip->cachepath,  dir_p->accessfile);

	switch( access_status) {
	case ACCESS_GRANTED:
	case ACCESS_PRIVILEGED:
		break;
	case ACCESS_DENIED:
		ip->type = RTYPE_NOACCESS;
		fclose( fp);
		return;
	default:
		ip->type = RTYPE_DENIED;
		fclose( fp);
		return;
	}

	if ( *(dir_p->defdoc) && ( ip->filetype & WN_DEFAULT_DOC)) {
		fclose( fp);
		dolocation( dir_p->defdoc, ip, 301);
		ip->type = RTYPE_FINISHED;
		return;
	}

	if ( (inheadp->method == PUT) || (inheadp->method == DELETE) ||
	     				(inheadp->method == MOVE)) {
		authmod = dir_p->pauthmod;
		authtype = dir_p->pauthtype;
	}
	else {
		authmod = dir_p->authmod;
		authtype = dir_p->authtype;
	}

	if ( (*authmod) && 
	((access_status != ACCESS_PRIVILEGED) || (inheadp->method == PUT) ||
			(inheadp->method == DELETE) || (inheadp->method == MOVE)) ) {

		char	tmp_auth_mod[MIDLEN];

		if ( !(IS_TRUSTED || IS_ATRUSTED) ) {
			senderr( DENYSTATUS, err_m[90], authmod);
			ip->type = RTYPE_FINISHED;
			fclose( fp);
			return;
		}

		exec_ok( ip);

		if ( WN_USE_PAM &&
				( strncasecmp( authmod, "pam", 3) == 0) &&
				( (!authmod[3]) || isspace(authmod[3]))) {
			mystrncpy( dir_p->authmodule, "pam", MIDLEN);
			mystrncat( dir_p->authmodule, authmod + 3, MIDLEN);
		}
		else {
			if ( !getfpath( tmp_auth_mod, authmod, ip)) {
				senderr( SERV_ERR, err_m[45], authmod);
				ip->type = RTYPE_FINISHED;
				return;
			}
			mystrncpy( dir_p->authmodule, tmp_auth_mod, MIDLEN);
		}

		/* anything requiring authentication should not be cached */
		if ( !(ip->attributes & WN_CACHEABLE))
			ip->attributes |= WN_NOCACHE;

		if ( (strcasecmp( authtype, "Digest") != 0) && (!chkauth( ip)) ) {
			/*
			 * chkauth must be delayed for Digest until we know the
			 * md5 digest.
			 */
			ip->type = RTYPE_NO_AUTH;
			fclose( fp);
			return;
		}
	}

	if ( *(dir_p->filemod)) {
		exec_ok( ip);
		if ( !getfpath( dir_p->filemodule, dir_p->filemod, ip)) {
			senderr( SERV_ERR, err_m[45], dir_p->filemod);
			return; /* to process_url */
		}
		dir_p->filemod = dir_p->filemodule;

		if ( WN_OPT_U )
			check_perm( ip, dir_p->filemodule);

		ip->attrib2 |= WN_FILEMOD;
	}

	if ( *(dir_p->cachemod)) {
		exec_ok( ip);
		if ( !getfpath( dir_p->cachemodule, dir_p->cachemod, ip)) {
			senderr( SERV_ERR, err_m[45], dir_p->cachemod);
			return; /* to process_url */
		}
		dir_p->cachemod = dir_p->cachemodule;
		if ( WN_OPT_U )
			check_perm( ip, dir_p->cachemodule);

		if ( (dir_p->defattributes) & WN_CGI)
			cgi_env( ip, WN_FULL_CGI_SET);
	}

	if ( *(dir_p->indexmod)) {
		exec_ok( ip);
		if ( !getfpath( dir_p->indexmodule, dir_p->indexmod, ip)) {
			senderr( SERV_ERR, err_m[45], dir_p->indexmod);
			return;
		}
		dir_p->indexmod = dir_p->indexmodule;
		if ( WN_OPT_U )
			check_perm( ip, dir_p->indexmodule);
	}

	if ( iswndir( ip)) {
		/* It's a title, keyword, grep, or index search of this dir */
		ip->allowed |= WN_M_GET + WN_M_TRACE;
		fclose( fp);
		ip->title = ip->encoding = ip->keywords = ip->cookie
			= ip->filter = ip->handler = ip->phandler = wn_empty;
		ip->content_type = BUILTIN_CONTENT_TYPE;
		return;  
	}

	cep = &entry;
	cep->line = ip->cacheline;  
	/* actual cache line goes in ip struct not cep struct */
	while ( read_cache_file( cep, fp, ip->basename)) {
		if ( !*cep->basename)
			continue;
		if ( streq( ip->basename, cep->basename)) {
			if ( ip->type == RTYPE_UNCHECKED)
				ip->type = RTYPE_FILE;

			ip->attributes |= 
				(entry.attributes ? entry.attributes :
						dir_p->defattributes);
			ip->allowed |= WN_M_GET + WN_M_HEAD
						+ WN_M_TRACE + WN_M_OPTIONS;

			ip->title = entry.title;
			ip->content_type = entry.content; 
			ip->encoding = entry.encoding; 
			ip->keywords = entry.keywords; 

			ip->includes = dir_p->defincludes;
			ip->wrappers = dir_p->defwrapper;
			ip->list_incl = dir_p->deflist;

			if ( *entry.includes)
				ip->includes = entry.includes;
			if ( (*ip->includes) &&
					!streq( ip->includes, "<none>")) {
				ip->attrib2 |= WN_INCLUDE;
				ip->attrib2 &= ~(WN_LIST_INCL);
			}
			else
				ip->includes = wn_empty;

			if ( *entry.wrappers)
				ip->wrappers = entry.wrappers; 
			if ( (*ip->wrappers) &&
					!streq( ip->wrappers, "<none>")) {
				ip->attrib2 |= WN_WRAPPED;
				ip->attrib2 &= ~(WN_LIST_INCL);
			}
			else
				ip->wrappers = wn_empty;

			ip->inclptr = ip->wrappers; 

			if ( *entry.list_incl)
				ip->list_incl = entry.list_incl;

			if ( (*ip->list_incl) &&
					!streq( ip->list_incl, "<none>")) {
				ip->attrib2 |= WN_LIST_INCL;
				/* shut off any includes */
				ip->attrib2 &= ~(WN_INCLUDE + WN_WRAPPED);
				ip->includes = ip->wrappers = wn_empty;
			}
			else
				ip->list_incl = wn_empty;

			ip->swrapper = entry.swrapper; 
			if ( (*ip->swrapper) &&
					!streq( ip->swrapper, "<none>")) {
				ip->attrib2 |= WN_SWRAPPED;
			}

			ip->nomatchsub = entry.nomatchsub; 
			ip->filter = entry.filter;

			ip->expires = entry.expires;
			ip->maxage = ((*entry.maxage) 
				? entry.maxage : dir_p->default_maxage);

			ip->cookie = ((*entry.cookie) 
				? entry.cookie : dir_p->def_cookie);

			ip->handler = ((*entry.handler) 
				? entry.handler : dir_p->def_handler);

			ip->phandler = ((*entry.phandler) 
				? entry.phandler : dir_p->def_phandler);

			/* By default CGI is dynamic non-cachable */
			/* It is always non-cachable */
			if ( (ip->type == RTYPE_CGI ) ||
						(ip->type == RTYPE_NPH_CGI ))
				ip->attributes |= 
					(WN_CGI + WN_DYNAMIC +
					 WN_NOCACHE + WN_NOSEARCH);

			handlers( ip);


			ip->filter = ((*entry.filter) 
				? entry.filter : dir_p->def_filter);

			if ( *ip->filter) {
				if ( streq( ip->filter, "<none>")) {
					ip->filter = wn_empty;
					ip->attributes &= ~WN_FILTERED;
				}
				else {
					ip->attributes |= WN_FILTERED;
				}
			}
			for ( i = 0; i < NUMFIELDS; i++) {
				ip->field[i] = entry.field[i];
			}

			ip->filetype |= entry.filetype;

			if ( ip->attrib2 & 
				(WN_INCLUDE + WN_WRAPPED + WN_LIST_INCL)) {
				update_mod_time( ip);
				ip->attributes |= WN_PARSE;
			}

			if ( (ip->filetype & WN_IMAGEMAP) ||
					(ip->attributes & WN_ISMAP)) {
				ip->type = RTYPE_IMAGEMAP;
			}

			if ( ip->attributes & WN_NOPARSE)
				ip->attributes &= ~(WN_PARSE);

			if ( strncasecmp( ip->content_type, "text", 4) == 0 )
				ip->filetype |= WN_TEXT;
			if ( strncmp( ip->content_type, "text/html", 9) == 0)
				ip->filetype |= WN_ISHTML;

			if ( *entry.headerlines)
				mystrncpy( outheadp->list, entry.headerlines,
					   			BIGLEN);

			if ( *entry.status)
				mystrncpy( outheadp->status, 
						entry.status, SMALLLEN);

			if ( *entry.md5) {
				mystrncpy( outheadp->md5, "Content-MD5: ", 20);
				mystrncat( outheadp->md5,
						entry.md5, 2*TINYLEN);
				mystrncat( outheadp->md5, "\r\n", 2*TINYLEN);
			}

			if ( *entry.redirect) {
				char 	*cp;

				ip->type = RTYPE_REDIRECT;
				mystrncpy( outheadp->location,
						entry.redirect, SMALLLEN);

				cp = strrchr( outheadp->location, '?');
				if ( (cp != NULL) && (*(cp+1) == '\0') ) {
					if  ( *ip->query )
						mystrncpy( ++cp, ip->query, 
							MIDLEN - SMALLLEN);
					else
						*cp = '\0';
				}
			}
			else if ( (ip->status & WN_CANT_STAT) ) {
				if (*dir_p->filemod != '\0')
					; /* filemod handles it */
				else if ( (ip->allowed & WN_M_PUT) &&
						(inheadp->method == PUT))
					; /* put file may not exist */
				else
					ip->type = RTYPE_DENIED;
			}
			if ( strcasecmp( authtype, "Digest") == 0 &&
							!chkauth( ip)) {
				ip->type = RTYPE_NO_AUTH;
			}
			fclose( fp);
			return;
		}
	}

	if ( NO_SERVEALL)
		ip->type = RTYPE_DENIED;
	else {
		if ( dir_p->attributes & WN_SERVEALL) {
			if ( strcasecmp( authtype, "Digest") == 0 && !chkauth( ip)) {
				ip->type = RTYPE_NO_AUTH;
				fclose( fp);
				return;
			}
			do_serveall( ip);
		}
		else
			ip->type = RTYPE_DENIED;
	}
	fclose( fp);
	return;
}


static void
handlers( ip)
Request	*ip;
{
	if ( *ip->handler) {
		if ( streq( ip->handler, "<none>")) {
			ip->handler = wn_empty;
			ip->attributes &= ~WN_CGI;
		}
		else {
			ip->attributes |= 
				(WN_CGI + WN_DYNAMIC +
				 WN_NOCACHE + WN_NOSEARCH);
			ip->type = RTYPE_CGI_HANDLER;
		}
	}
	if ( (*ip->phandler) &&
		((inheadp->method == PUT) ||
		 (inheadp->method == DELETE) ||
		 (inheadp->method == MOVE)) ) {
		if ( streq( ip->phandler, "<none>")) {
		 	ip->phandler = wn_empty;
			ip->allowed &= ~(WN_M_PUT + WN_M_MOVE + WN_M_DELETE); 
		}
		else {
			ip->type = RTYPE_PUT_HANDLER;
		}
	}
	if ( ip->attributes & WN_NONDYNAMIC)
		ip->attributes &= ~(WN_DYNAMIC);

	if ( (ip->attributes) & WN_NOKEEPALIVE)
		this_conp->keepalive = FALSE;

	if ( ip->attributes & WN_CACHEABLE)
		ip->attributes &= ~(WN_NOCACHE);

	if ( ip->attributes & WN_CGI ) {
		ip->allowed |= (WN_M_GET + WN_M_POST);
	}

	if ( ip->attributes & WN_POST_OK )
		ip->allowed |= WN_M_POST;

	if ( ip->attributes & WN_NO_POST)
		ip->allowed &= ~WN_M_POST;

	if ( ip->attributes & WN_NO_GET)
		ip->allowed &= ~WN_M_GET;

	if ( ip->attributes & WN_PUT_OK)
		ip->allowed |= WN_M_PUT + WN_M_MOVE + WN_M_DELETE;

}



/*
 * do_serveall( ip) The file ip->filename exists but is not in the index.cache
 * file.  This function sets ip->content (and ip->encoding if needed) based
 * on the filename suffix.
 */

static void
do_serveall( ip )
Request	*ip;
{
	register char	*cp,
			*cp2;

	char		suffix[10];


	ip->title = ip->basename;
	ip->allowed |= WN_M_GET + WN_M_HEAD + WN_M_TRACE + WN_M_OPTIONS;

	if ( !*(dir_p->default_content))
		dir_p->default_content = DEFAULT_CONTENT_TYPE;
	if ( !*(dir_p->default_charset))
		dir_p->default_charset = DEFAULT_CHARSET;

	if ( strstr( dir_p->default_content, "charset") == NULL) {
		fmt3( ip->contype, SMALLLEN, dir_p->default_content,
		      "; charset =", dir_p->default_charset); 
	}
	else
		mystrncpy( ip->contype, dir_p->default_content, SMALLLEN);

	ip->content_type = ip->contype;
	
	ip->maxage = dir_p->default_maxage;
	ip->cookie = dir_p->def_cookie;
	ip->handler = dir_p->def_handler;
	ip->phandler = dir_p->def_phandler;
	ip->attributes |= dir_p->defattributes;
	handlers( ip);
	ip->filter = dir_p->def_filter;
	if ( *ip->handler || *ip->filter)
		ip->attributes |= WN_NOSEARCH;

	if ( (*(dir_p->filemod)) || ( ip->type == RTYPE_PUT_HANDLER))
		/* skip check on file name */
		;
	else if ( (*(ip->title) == '.') || streq( ip->title, CACHEFNAME) ||
				(ip->status & WN_CANT_STAT) ||
				streq( ip->title, dir_p->accessfile)  ||
				streq( ip->title, CONTROLFILE_NAME)  ||
				streq( ip->title, CONTROLFILE2_NAME)) {
		ip->type = RTYPE_DENIED;
		return;
	}

	if ( ip->type == RTYPE_UNCHECKED)
		ip->type = RTYPE_FILE;

	if ( (ip->type == RTYPE_CGI ) || (ip->type == RTYPE_NPH_CGI ))
		ip->attributes |= (WN_DYNAMIC + WN_NOSEARCH);

	if ( (cp = strrchr( ip->basename, '.')) == NULL ) { /* no suffix */
		return;
	}
	mystrncpy( suffix, cp+1, 10);
	strlower( suffix);
	if ( streq( suffix, "gz") || streq( suffix, "z")) {
		ip->encoding = ( suffix[0] == 'g' ? "x-gzip" : "x-compress");
		*cp = '\0';
		if ( (cp2 = strrchr( ip->basename, '.')) == NULL ) {
			*cp = '.';
			return;
		}
		mystrncpy( suffix, cp2+1, 10);
		strlower( suffix);
		*cp = '.';
	}

	if ( (PARSE_EXT != "") && streq( suffix, PARSE_EXT) && !(ip->attributes  & WN_NOPARSE))
		ip->attributes |= WN_PARSE;

	if ( (cp = strstr( CGI_EXT_LIST, suffix)) != NULL ) {
		cp += strlen( suffix);
		if ( (!*cp) || (*cp == ','))
			ip->attributes |= WN_NOSEARCH;
	}

	get_mtype( suffix); /* Should have ip->content_type == ip->contype */
	if ( strncasecmp( ip->contype, "text", 4) == 0 ) {
		ip->filetype |= WN_TEXT;
		strlower (ip->contype);
		if ( strstr( ip->contype, "charset") == NULL)
			fmt3( ip->contype, SMALLLEN, ip->contype, "; charset=",
			      dir_p->default_charset); 
	}
	if ( strncmp( ip->content_type, "text/html", 9) == 0)
		ip->filetype |= WN_ISHTML;

	return;
}


/*
 * chkaccess( cachepath, accessfile) checks whether the client's IP address
 * is in the allowed list in accessfile.  Returns ACCESS_PRIVILEGED if 
 * access is unconditionally allowed, ACCESS_GRANTED if further
 * authentication (through an authentication module) may be required, 
 * ACCESS_DENIED if access is denied and ACCESS_ERR on error.
 */

int
chkaccess( cachepath, accessfile)
char	*cachepath,
	*accessfile;
{
	FILE	*fp;
	int	len,
		notflag,
		priv_flag,
		match = FALSE;

	char	*cp,
		*cp2,
		buf[MIDLEN],
		linebuf[SMALLLEN];

	if ( ! *accessfile)
		return ACCESS_GRANTED;	/* No access control */

	if ( getfpath2( buf, accessfile, cachepath) == FALSE)
		/* Error logged in getfpath2() */
		return ACCESS_ERR;

	if ( ! WN_IP_ONLY_ACCESS) {
		if ( !(dir_p->logtype & NO_DNS_LOG)) {
			if ( !dir_p->logtype)
				dir_p->logtype = default_logtype;
			dir_p->logtype |= REV_DNS_LOG;

		}
		/* force reverse DNS lookup for access control */
		get_remote_info( );
	}

	if ((fp = fopen( buf, "r")) == (FILE *)NULL ) {
		logerr( err_m[87], buf);
		return ACCESS_ERR;
	}

	while ( fgets( linebuf, SMALLLEN, fp)) {
		if ( !chop( linebuf)) {
			logerr( err_m[62], buf);
			return ACCESS_ERR;
		}
		if ( ( cp = strchr( linebuf, '#')) != NULL) {
			*cp = '\0';
		}

		cp = linebuf;

		while ( isspace( *cp ) )
			cp++;

		if ( strncasecmp( cp, "access-denied-url=", 18) == 0) {
			mystrncpy( dir_p->noaccess_url, cp + 18, MIDLEN/2);
			continue;
		}

		if ( (notflag = ( *cp == '!')))
			cp++;

		if ( (priv_flag = ( *cp == '+')))
			cp++;

		len = strlen( cp);

		if ( len == 0 )
			continue;

		strlower( cp);


		if ( streq(cp, this_conp->remaddr)) {
			match = TRUE;
		}

		else if ( (! WN_IP_ONLY_ACCESS)
				&& streq(cp, this_conp->remotehost)) {
			match = TRUE;
		}

		else if ( (cp2 = strchr( cp, '/')) != NULL) {
			*cp2++ = '\0';
			match = mask_match( cp, cp2);
		}
		else {
			char	*cp2;

			cp2 = cp + (len - 1);
			while ( isspace( *cp2 ) && ( cp2 > cp) ) {
				len--;
				cp2--;
			}
			if ( ( *cp2 == '.') && (len > 1) && 
				( strncmp( cp, this_conp->remaddr, len) == 0 ))
				match = TRUE;
		}

		if ( match || wild_match_rem( this_conp->remotehost, cp)) {
			if ( notflag)
				break;
			else {
				fclose( fp);
				if ( priv_flag)
					return  ACCESS_PRIVILEGED;
				else
					return  ACCESS_GRANTED;
			}
		}
	}
	fclose( fp);
	return ACCESS_DENIED;
}

/*
 * static int mask_match( net, mask)
 * net is "nnn.nnn.nnn.nnn", mask is "mmm.mmm.mmm.mmm" and remaddr
 * is "rrr.rrr.rrr.rrr".  Return true if nnn == mmm | rrr for each
 * of the four segments of net.  Else return false.
 */

static int
mask_match( net, mask)
char	*net,
	*mask;

{
	int	ipnet[4],
		ipmask[4],
		iprem[4];

	sscanf( net, "%d.%d.%d.%d", 
			&ipnet[0], &ipnet[1], &ipnet[2], &ipnet[3]);
	sscanf( mask, "%d.%d.%d.%d", 
			&ipmask[0], &ipmask[1], &ipmask[2], &ipmask[3]);
	sscanf( this_conp->remaddr, "%d.%d.%d.%d", 
			&iprem[0], &iprem[1], &iprem[2], &iprem[3]);

	return ( (ipnet[0] == (ipmask[0] & iprem[0]))
			&& ( ipnet[1] == (ipmask[1] & iprem[1]))
			&& ( ipnet[2] == (ipmask[2] & iprem[2]))
			&& ( ipnet[3] == (ipmask[3] & iprem[3])));
}


/*
 *  static int wild_match( char *l, char *p)
 *
 *  String equality routine, including matching the '*' and '?' characters.
 *  The string p contains the wildcards.  '?' matches any single character
 *  while '*' matches any string.
 *  
 */

/*
 *  Borrowed from the ANU News sources V6.1b3 newsrtl.c.  Original sources
 *  Copyright 1989 by Geoff Huston.   Modified by John Franks
 *
 */

static int
wild_match( l, p)
char	*l,
	*p;
{
	if ( !l || !p)
		return FALSE;

	while ( *l && *p && (*l == *p)) {
		p++;
		l++;
	}

	if (!*l) {
		if (!*p)
			return TRUE;
		else if (*p == '*') 
			return (wild_match( l, p+1));
		else
			return FALSE;
	}
	if (*p == '*') {
		while ( !wild_match( l, p+1)) {
			l++;
			if (!*l) {
				if (!*(p+1))
					return TRUE;
				else
					return FALSE;
				}
			}
		return TRUE;
	}
	if (*p == '?')
		return(wild_match( l+1, p+1));

	return ((*l == *p) && wild_match( l+1, p+1));
}


static int
wild_match_rem( l, p)
char	*l,
	*p;
{
	if ( WN_IP_ONLY_ACCESS)
		return FALSE;
	else
		return wild_match( l, p);
}

/*
 * Store the line from fp in dep->dirline.  This line consists of &
 * separated field value pairs (field=value).  Fields are access,
 * swrapper, nomatchsub, subdirs, and owner.
 * Change the &'s and ='s  to '\0' and  make dep->access, etc., point to
 * the right place in dep->dirline.  Return TRUE unless empty line then FALSE.
 */

void
read_cache_dirinfo( fp, dep)
FILE		*fp;
Dir_info	*dep;
{
	register char	*cp;
	int 	reading_value = FALSE;

	char		*field,
			*value = NULL;

	cp = dep->dirline;
	if ( fgets( cp, BIGLEN, fp) == NULL) {
		*cp++ = '\n';
		*cp = '\0';
	}

	if ( strrchr( dep->dirline, '\n') == NULL) {
		senderr( SERV_ERR, err_m[63], "");
		wn_exit( 2);  /* senderr: SERV_ERR */
	}

	dep->attributes = dep->defattributes = (unsigned long) 0;
	dep->logtype = 0;

	dep->accessfile = dep->swrapper = dep->defwrapper = dep->defincludes
	= dep->deflist = dep->subdirs = dep->nomatchsub = dep->dir_owner 
	= dep->cachemod = dep->filemod = dep->indexmod
	= dep->authmod = dep->authtype = dep->authrealm
	= dep->pauthmod = dep->pauthtype = dep->pauthrealm = wn_empty;

	dep->default_content = dep->defdoc = dep->default_maxage
	= dep->def_filter = dep->def_handler = dep->def_phandler
	= dep->default_charset = dep->def_cookie = wn_empty;

	*dep->authmodule = *dep->cachemodule
	 = *dep->filemodule = *dep->indexmodule = '\0';

	if ( this_rp->attrib2 & WN_USE_DEF_CACHEFILE)
			dep->attributes |= WN_DIRNOSEARCH;

	cp = dep->dirline;

	if ( !*cp )
		return;

	field = cp++;
	while ( *cp) {

		switch (*cp) {
		case '=':
			if ( reading_value) {
				cp++;
				break;
			}
			*cp++ = '\0';
			value = cp;
			reading_value = TRUE;
			break;

		case '&':
			if ( *(cp-1) == '\\') {	/* ignore escaped & */
				mystrncpy( cp-1, cp, MIDLEN/2);
				break;
			}
			*cp = '\0';
			setdirvalue( field, value, cp, dep);
			field = ++cp;
			reading_value = FALSE;
			break;

		case '\n':
			*cp = '\0';
			setdirvalue( field, value, cp, dep);
			return;

		default:
			cp++;
		}
	}
}


static void
setdirvalue( field, value, end, dep)
char		*field,
		*value,
		*end;
Dir_info	*dep;
{
	char	buf[TINYLEN];

	if ( !value || !*value) {
		mystrncpy( buf, field, TINYLEN);
		logerr( err_m[10], buf);
		return;
	}
	if ( (end - value) > MIDLEN/2) {
		mystrncpy( buf, field, TINYLEN);
		logerr( err_m[107], buf);
		value[MIDLEN/2] = '\0';
	}

	switch (*field) {
	case 'a':
		if ( strncmp( field, "auth", 4) == 0) {
			switch( field[4]) {
			case 'd':		/* authdenied_file */
				mystrncpy( dep->authdenied_file, 
							value, MIDLEN/2);
				break;
			case 'm':
				dep->authmod = value;
				break;
			case 'r':
				dep->authrealm = value;
				break;
			case 't':
				dep->authtype = value;
				break;
			}
		}
		else {
			dep->accessfile = value;
		}
		break;

	case 'c':
		if ( streq( field, "cachemod")) {
			dep->cachemod = value;
		}
		else if ( streq( field, "cntlfname")) {
			; /* ignore it */
		}
		break;

	case 'd':
		if ( streq( field, "dwrapper")) {
			dep->attributes |= WN_DIRWRAPPED;
			dep->swrapper = value;
		}

		else if ( streq( field, "defwrapper")) {
			dep->defwrapper = value;
		}

		else if ( streq( field, "defincludes")) {
			dep->defincludes = value;
		}

		else if ( streq( field, "default_filter")) {
			dep->def_filter = value;
		}

		else if ( streq( field, "default_handler")) {
			dep->def_handler = value;
			dep->attributes |= WN_CGI;
		}

		else if ( streq( field, "default_cookie")) {
			dep->def_cookie = value;
			dep->attributes |= WN_CGI;
		}

		else if ( streq( field, "default_phandler")) {
			dep->def_phandler = value;
		}

		else if ( streq( field, "deflist")) {
			dep->deflist = value;
		}

		else if ( streq( field, "defattributes"))
			dep->defattributes = (unsigned long) atol( value);

		else if ( streq(field, "default_content"))
			dep->default_content = value;

		else if ( streq(field, "default_charset"))
			dep->default_charset = value;

		else if ( streq(field, "default_document"))
				dep->defdoc = value;

		else if ( streq(field, "default_maxage"))
				dep->default_maxage = value;

		else
			logerr( err_m[11], field);
		break;

	case 'f':	/* file module */
		dep->filemod = value;
		break;

	case 'i':	/* index module */
		dep->indexmod = value;
		break;

	case 'l':	/* logtype */
		dep->logtype = (unsigned) atol( value);
		break;

	case 'n':
		switch ( *(field + 2)) {

		case 'a':		/* noaccess_url */
			mystrncpy( dep->noaccess_url, value, MIDLEN/2);
			break;

		case 'f':		/* nofile_url */
			mystrncpy( dep->cantstat_url, value, MIDLEN/2);
			break;

		case 'm':		/* nomatchsub */
			dep->nomatchsub = value;
			break;

		case 's':
			if ( streq( value, "true")) /* nosearch=true */
			dep->attributes |= WN_DIRNOSEARCH;
			break;

		default:
			logerr( err_m[11], field);
			break;
		}
		break;

	case 'o':	/* owner */
		dep->dir_owner = value;
		break;

	case 'p':	/* pauth */
		if ( strncmp( field, "pauth", 5) == 0) {
			switch( field[5]) {
			case 'm':
				dep->pauthmod = value;
				break;
			case 'r':
				dep->pauthrealm = value;
				break;
			case 't':
				dep->pauthtype = value;
				break;
			}
		}
		break;
	case 's':
		if ( streq( field, "subdirs"))		/* subdirs */
			dep->subdirs = value;
		else if ( streq( field, "serveall") && streq( value, "true")){
				dep->attributes |= WN_SERVEALL;
		}
		break;
		
	default:
		logerr( err_m[11], field);
	}
}

/*
 * Store the line from fp in cep->line.  This line consists of &
 * separated field value pairs (field=value).  Fields are basename,
 * title, keywords, content, maxage, encoding, type, includes, and wrappers.
 * Change the &'s and ='s  to '\0' and  make cep->basename, cep->title,
 * cep->keywords, cep->content, cep->encoding and cep->type point to
 * the right place in cep->line.  Return TRUE unless no more lines then FALSE.
 */

int
read_cache_file( cep, fp, key)
Cache_entry	*cep;
FILE		*fp;
char		*key;

{
	register char	*cp;
	char		*field,
			*value,
			envkey[SMALLLEN];
	int		c,
			i;

	static FILE	*lfp;

	cp = cep->line;

	if ( *dir_p->cachemod ) {  /* invoke cache module */
		if ( key != NULL ) {
			mystrncpy( envkey, "WN_KEY=", SMALLLEN);
			mystrncat( envkey, key, SMALLLEN );
			putenv( envkey);
		}

		if ((lfp = WN_popen( dir_p->cachemod, "r")) == (FILE *)NULL ) {
			senderr( SERV_ERR, err_m[40], dir_p->cachemod);
			wn_exit( 2);  /* senderr: SERV_ERR */
		}

		if ( (c = getc( lfp)) == EOF ) {
			senderr( SERV_ERR, err_m[43], dir_p->cachemod);
			pclose( lfp);
			wn_exit( 2);  /* senderr: SERV_ERR */
		}
		else
			ungetc( c, lfp);

		*dir_p->cachemod = '\0';  /* don't come back here again */
	}	
	else 
		lfp = fp;

	for (;;) {		/* read until non-empty line */
		if ( fgets( cp, CACHELINE_LEN, lfp) == NULL) {
			return FALSE;
		}
		if ( *cp != '\n')
			break;
	}

	if ( lfp != fp)    /* It's a cache module and we're done */
		pclose( lfp);

	if ( strrchr( cp, '\n') == NULL) {
		senderr( SERV_ERR, err_m[63], "");
		wn_exit( 2);  /* senderr: SERV_ERR */
	}

	cep->end = cep->basename = cep->title = cep->keywords 
	= cep->content = cep->encoding = cep->includes = cep->list_incl 
	= cep->wrappers = cep->swrapper = cep->nomatchsub
	= cep->filter = cep->expires = cep->maxage = cep->cookie
	= cep->status = cep->md5 = cep->url = cep->redirect 
	= cep->handler = cep->phandler = wn_empty;

	for ( i = 0; i < NUMFIELDS; i++) {
		cep->field[i] = wn_empty;
	}

	*cep->headerlines = '\0';
	cep->attributes = cep->filetype = 0;

	cp = cep->line;
	field = cp;

	if ( (value = strchr( cp, '=' )) == NULL )
		cp = value = cep->end;
	else {
		*value++ ='\0';
		cp = value;
	}
	while ( *cp) {
		switch (*cp) {
		case '&':
			if ( *(cp-1) == '\\') {	  /* handle escaped & */
				strcpy( cp-1, cp);
				break;
			}
			*cp = '\0';
			setvalue( field, value, cp, cep);
			field = ++cp;
			if ( (value = strchr( cp, '=' )) == NULL )
				cp = value = cep->end;
			else {
				*value++ ='\0';
				cp = value;
			}
			break;
		case '\n':
			*cp = '\0';
			setvalue( field, value, cp, cep);
			break;
		default:
			cp++;
		}
	}

	if ( this_rp->attrib2 & WN_ISACGIBIN ) {
		cep->attributes |= WN_NOSEARCH;
	}
	return TRUE;
}

static void
setvalue( field, value, end, cep)
char	*field,
	*value,
	*end;
Cache_entry	*cep;
{
	char	buf[SMALLLEN];
	int	i,
		errflg;

	errflg = 0;

	if ( !*value) {
		mystrncpy( buf, field, 28);
		mystrncat( buf, ":", SMALLLEN);
		mystrncat( buf, cep->basename, SMALLLEN);
		logerr( err_m[5], buf);
		return;
	}
	if ( (end - value) > MIDLEN/2) {
		mystrncpy( buf, field,  30);
		logerr( err_m[107], buf);
		value[MIDLEN/2] = '\0';
	}

	switch (*field) {
	case 'a':		/* attributes */
		cep->attributes |= (unsigned long) atol( value);
		if ( cep->attributes & (WN_DYNAMIC + WN_CGI)) {
			cep->attributes |= WN_NOSEARCH;
		}
		break;
	case 'c':
		switch( field[2]) {
		case 'o':
			cep->cookie = value;
			break;
		case 'n':
			cep->content = value;
			break;
		default:
			errflg++;
		}
		break;

	case 'e':
		switch( field[1]) {
		case 'n':
			cep->encoding = value;
			break;
		case 'x':
			cep->expires = value;
			break;
		default:
			errflg++;
		}
		break;
	case 'f':
		switch( field[3]) {
		case 'e':		/* file */
			cep->basename = value;
			*cep->url = '\0';  /* can't have url & basename */
			break;
		case 'l':		/* field */
			i = atoi( field + 5);
			if ( (i >= 0 ) && ( i < NUMFIELDS))
				cep->field[i] = value;
			break;
		case 't':		/* filter */
			cep->filter = value;
			break;
		default:
			errflg++;
		}
		break;
	case 'h':
		if ( streq( field, "handler")) {
			cep->handler = value;
			if ( !streq( value, "<none>")) {
				cep->attributes |= WN_NOSEARCH;
			}
		}
		else if ( streq( field, "header")) {
			if ( strlen( cep->headerlines) + 
						strlen( value) > BIGLEN ) {
				senderr( SERV_ERR, err_m[70], value);
				wn_exit( 2);  /* senderr: SERV_ERR */
			}
			mystrncat( cep->headerlines, value, BIGLEN);
			mystrncat( cep->headerlines, "\r\n", BIGLEN);
		}
		else
			errflg++;
		break;
	case 'i':
		cep->includes = value;
		break;
	case 'k':
		cep->keywords = value;
		break;
	case 'l':			/* list */
		cep->list_incl = value;
		break;
	case 'm':
		if ( streq( field, "md5"))
			cep->md5 =  value;
		else 	if ( streq( field, "maxage"))
			cep->maxage = value;
		else
			errflg++;
		break;
	case 'n':
		if ( *(field+2) == 'm')  /* nomatchsub */
			cep->nomatchsub = value;
		else if ( streq( value, "true")) /* nosearch=true */
			cep->attributes |= WN_NOSEARCH;
		else
			errflg++;
		break;
	case 'p':
		if ( streq( field, "phandler"))
			cep->phandler = value;
		else
			errflg++;
		break;
	case 'r':
		if ( streq( field, "redirect"))
			cep->redirect = value;
		else
			errflg++;
		break;
	case 's':
		if ( streq( field, "swrapper")) {
			cep->swrapper = value;
		}
		else if ( streq( field, "status")) {
			if ( strlen( value) > SMALLLEN ) {
				senderr( SERV_ERR, err_m[70], value);
				wn_exit( 2);  /* senderr: SERV_ERR */
			}
			cep->status = value;
		}
		else
			errflg++;
		break;
	case 't':		/* title */
		cep->title = value;
		break;
	case 'u':
		cep->url = value;
		*cep->basename = '\0';  /* can't have url & basename */
		break;
	case 'w':
		cep->wrappers = value;
		break;
	default:
		errflg++;
	}

	if ( errflg) 
		logerr( err_m[6], field);
}


/*
 * check_perm( ip, buf)
 * This stats the file named in buf, then checks if the index.cache is
 * owned by trusted user or group (options -t & -T) or if the index.cache
 * owner must own the file ( option -u). It sends an error and quits
 * if permssion is not allowed.
 */

void
check_perm( ip, buf)
Request	*ip;
char	*buf;
{
	register char	*cp;
	char		filebuf[MIDLEN];

	struct stat stat_buf;

	if ( (!WN_OPT_T) && (!WN_OPT_U) ) {
		if ( (ip->filetype & WN_NOT_WORLD_READ)
				&& (ip->filetype & WN_NOT_REG_FILE)) {
			senderr( SERV_ERR, err_m[44], buf);
			wn_exit( 2); /* senderr: SERV_ERR */
		}
		else
			return;
	}
	else if ( IS_TRUSTED )
		return;

	if ( WN_OPT_U ) {
		mystrncpy( filebuf, buf, MIDLEN);
		cp = filebuf;
		while ( *cp && !isspace( *cp))
			cp++;
		*cp = '\0';
		if ( stat( filebuf, &stat_buf) != 0 ) {
			logerr( err_m[12], buf);
			return;
		}

		if (( dir_p->cache_uid == stat_buf.st_uid )
				 || ( cache_id == stat_buf.st_uid )
				 || ( cache_id == stat_buf.st_gid ))
			return;
	}
		
	senderr( DENYSTATUS, err_m[3], filebuf);
	wn_exit( 2); /* senderr: DENYSTATUS */
}


void
exec_ok( ip)
Request	*ip;
{
	
	if ( FORBID_CGI) {
		ip->allowed &= ~(WN_M_POST + WN_M_PUT + WN_M_DELETE + WN_M_MOVE);
		senderr( DENYSTATUS, err_m[4], ip->cachepath);
		wn_exit( 2);  /* senderr: DENYSTATUS*/
	}
	else {
		if ((serv_perm & WN_FORBID_EXEC) ||
				((serv_perm & WN_RESTRICT_EXEC) && !IS_TRUSTED)) {
			senderr( DENYSTATUS, err_m[4], ip->cachepath);
			wn_exit( 2);  /* senderr: DENYSTATUS*/
		}
	}
}

/*
 *  static int get_def_cachepath( ip) opens the file DEFAULT_CACHEFILE_LIST
 * where it finds lines of the form 
 *         /full/path/2/dir/ <whitespace> /full/path_to/default_cache_file
 * It reads these lines looking for a first field which matches the beginning
 * of ip->cachepath.  If it finds a match it replaces ip->cachepath with 
 * /full/path_to/default_cache_file and returns TRUE.  Otherwise it returns FALSE.
 * Comments in DEFAULT_CACHEFILE_LIST are anything on a line after the first '#'
 */

static int
get_def_cachepath( ip)
Request *ip;
{
#if USE_DEF_CACHE_LIST
	char	*cp,
		*cp2,
		*cp3,
		cachedir[MIDLEN],
		linebuf[SMALLLEN];

	struct stat stat_buf;
	FILE	*fp = NULL;

	if ( (stat( DEFAULT_CACHEFILE_LIST, &stat_buf) != 0 ) ||
	       		((fp = fopen( DEFAULT_CACHEFILE_LIST, "r")) == (FILE *) NULL) ) {
		logerr( err_m[87], DEFAULT_CACHEFILE_LIST);
		return FALSE;
	}

	if ( (stat_buf.st_uid == (uid_t) user_id) || (stat_buf.st_mode & S_IWOTH)) {
		logerr( err_m[149], DEFAULT_CACHEFILE_LIST);
		return FALSE;
	}

	if ( (stat_buf.st_gid == (gid_t) group_id) && ( stat_buf.st_mode & S_IWGRP)) {
		logerr( err_m[149], DEFAULT_CACHEFILE_LIST);
		return FALSE;
	}


	while ( fgets( linebuf, SMALLLEN, fp)) {
		if ( !chop( linebuf)) {
			logerr( err_m[1], DEFAULT_CACHEFILE_LIST);
			return FALSE;
		}
		if ( ( cp = strchr( linebuf, '#')) != NULL) {
			*cp = '\0';
		}

		cp = linebuf;

		while ( *cp && isspace( *cp ) )
			cp++;
		cp2 = cp;

		while ( *cp2 && !isspace( *cp2 ) )
			cp2++;
		if ( *cp2)
			*cp2++ = '\0';

		mystrncpy( cachedir, ip->cachepath, MIDLEN);
		if ( (cp3 = strrchr( cachedir, '/')) != NULL)
			*++cp3 = '\0';

		if ( (strcmp( cachedir, cp ) != 0) ) {
			if  ( ! (strchr( cp, '*') || strchr( cp, '?')))
				continue;
			if ( ! wild_match( cachedir, cp) )
				continue;
		}

		/* It is a match; use value in cp2 */
		cp = cp2;
		while ( *cp && isspace( *cp ) )
			cp++;

		cp2 = cp;
		while ( *cp2 && !isspace( *cp2 ) )
			cp2++;

		if ( *cp2)
			*cp2++ = '\0';
		
		mystrncpy( ip->cachepath, cp, MIDLEN);
		ip->attrib2 |= WN_USE_DEF_CACHEFILE;
		return TRUE;
	}
#endif
	return FALSE;
}

