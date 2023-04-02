/*
    Wn: A Server for the HTTP
    File: wn/csearch.c
    Version 2.3.10
    
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


#include <sys/types.h>
#include <string.h>
#include "wn.h"
#include "parse.h"
#include "access.h"
#include "reg.h"
#include "regi.h"


#include "search.h"

static char	*get_next_dir();

typedef struct Link_entry {
	char	line[BIGLEN],
		*url,
		*title,
		*keywords;
} Link_entry;


static void	send_match_line();

static int	csearch(),
		do_list_search();

static struct regprog	*regp;

static Dir_info	*dirinfo_p;

/*
 * If ip->query is empty send a form to get it.  If there, strlower
 * it and do regcomp putting result in *rp.  Then, if needed do
 * an amperline and regcomp again with result in *rp2.  If rp == rp2
 * don't do the 2nd regcomp.  If it isn't done set *rp2 = *rp
 * If both rp and rp2 are NULL don't do any regcomp stuff.
 */

void
check_query( ip, rp, rp2)
Request	*ip;
struct regprog	**rp,
		**rp2;
{
	char	buf[BIGLEN],
		owner[SMALLLEN],
		*cp;

	if ( !*ip->query) {
		bzero( (char *) outheadp, sizeof( Outheader));
		ip->content_type = BUILTIN_CONTENT_TYPE;
		ip->status |= WN_HAS_BODY;
		http_prolog( );
		cp = ( *dir_p->dir_owner ? dir_p->dir_owner : MAINTAINER);
		mystrncpy( owner, "<link rev=\"made\" href=\"", SMALLLEN);
		mystrncat( owner, cp, SMALLLEN);
		mystrncat( owner, "\">\n", SMALLLEN);
		fmt3( buf, MIDLEN, "<html>\n<head>\n<title>", search_m[1],
		      "</title>\n");
		send_text_line( buf);
		fmt3( buf, MIDLEN, owner, "</head>\n<body>\n<h2>", 
			search_m[1]);
		mystrncat( buf, "</h2>\n", MIDLEN);
		send_text_line( buf);
		send_text_line( search_m[8]);
		send_text_line( search_m[7]);
		send_text_line( SERVER_LOGO);
		send_text_line( "</body>\n</html>\n" );
		writelog( ip, log_m[2], ip->relpath);
		ip->type = RTYPE_FINISHED;
		return;
	}

	www_unescape( ip->query, ' ');

	if ( rp && (*rp = regcomp( strlower( ip->query))) == NULL ) {
		senderr( SERV_ERR, err_m[81], ip->query);
		return;
	}

	if ( rp == rp2)
		return;
	if ( amperline( buf, ip->query, BIGLEN)) {
				/* amper escape '<', '>' and '&' */
		if ( (*rp2 = regcomp( strlower( buf))) == NULL ) {
			senderr( SERV_ERR, err_m[81], ip->query);
			return;
		}
	}
	else if ( rp) {
		*rp2 = *rp;
	}
}


void
cache_search( ip)
Request	*ip;
{
	char	*cp,
		cdirpath[BIGLEN];
	Dir_info	csearch_dir;

	if ( !iswndir( ip)) {
		senderr(CLIENT_ERR, err_m[59], ip->request);
		return;
	}
	
	dirinfo_p = &csearch_dir;
	check_query( ip, &regp, &regp);

	if ( ip->type == RTYPE_FINISHED)
		return;

	*ip->length = '\0';

	mystrncpy( cdirpath, ip->cachepath, MIDLEN);
	if ( (cp = strrchr( cdirpath, '/')) != NULL)
		*cp = '\0';
	else
		*cdirpath = '\0';

	search_prolog( ip, out_m[4]);

	if (!csearch( cdirpath, "", ip, MAXDEPTH)) {
		send_nomatch( ip, 'd');
		return;
	}

	send_text_line( "</ul>\n");
	if ( isdirwrapped( dir_p))
		do_swrap( ip);
	else
		search_epilog( );

	writelog( ip, log_m[3], ip->relpath);
}

void
send_nomatch( ip, type)
Request	*ip;
char	type;
{
	char	buf[BIGLEN],
		buf2[MIDLEN];

	if ( (type == 'd') && *(dir_p->nomatchsub)) {
		if ( isdirwrapped( dir_p)) {
			do_nomatchsub( ip, dir_p->nomatchsub);
			return; /* to cache_search, list_search etc.*/
		}
		else
			logerr( err_m[89], ip->relpath);
	}
	else if ( (type == 'f') && *(ip->nomatchsub)) {
		if ( *ip->swrapper) {
			do_nomatchsub( ip, ip->nomatchsub);
			return; /* to cache_search, list_search etc.*/
		}
		else
			logerr( err_m[89], ip->relpath);
	}

	send_text_line("<hr>\n<h2>Unsuccessful Search</h2>\n");
	sanitize( buf2, ip->query, MIDLEN);
	fmt3( buf, BIGLEN, search_m[3], buf2, "'</b>.\n");
	send_text_line( buf);
	send_text_line( search_m[4]);
	if ( type == 'd' ) {
		sanitize( buf2, ip->param_value, MIDLEN);
		buf2[6] = '\0'; /* truncate to 6 chars */
		fmt3( buf, MIDLEN, search_m[5], buf2, search_m[6]);
		send_text_line( buf);
	}
	else
		send_text_line( search_m[8]);
	send_text_line( search_m[7]);
	send_text_line( SERVER_LOGO);
	send_text_line( "</body>\n</html>\n" );

	writelog( ip, log_m[4], ip->relpath);
	return; /* to cache_search, list_search etc.*/
}


/*
 * search_prolog( ip, str) provides the response to a successful search.
 * If the file is wrapped don't do anything as the wrapper is
 * assumed to handle any messages.
 */

void
search_prolog(ip, str)
Request	*ip;
char	*str;
{

	char	*cp,
		owner[SMALLLEN],
		buf[BIGLEN];

	if ((iswndir( ip)) ?  isdirwrapped( dir_p) :
			( ip->attrib2 & WN_SWRAPPED))
		return;

	ip->status |= WN_HAS_BODY;
	http_prolog( );
		
	cp = ( *dir_p->dir_owner ? dir_p->dir_owner : MAINTAINER);
	fmt3( owner, SMALLLEN, "<link rev=\"made\" href=\"", cp, "\">\n");
	fmt3(buf, BIGLEN, "<html>\n<head>\n<title>", str, "</title>\n");
	send_text_line( buf);
	fmt3(buf, BIGLEN, owner, "</head>\n<body>\n<h2>", str);
	mystrncat( buf, "</h2>\n", BIGLEN);
	send_text_line( buf);
}	


void
search_epilog( )
{
	send_text_line( SERVER_LOGO);
	send_text_line( "</body>\n</html>\n" );
}


/*
 * csearch( cdir, srel, ip, depth) searches control cache in directory cdir for
 * lines which match the compiled regular expression pointed to by
 * static pointer regp.  When found call send_match_line.
 * For subdirs listed in the control cache
 * recursively call csearch.  Note: with symbolic links there could be
 * an infinite loop of "subdirectories" -- to handle this problem, go
 * only depth levels deep in the recursion.  This will still result in
 * many matches for the same item.
 */

static int
csearch( cdir, srel, ip, depth)
char	*cdir,
	*srel;
Request	*ip;
int	depth;
{
	int	ismatch = FALSE;
	FILE	*cfp;

	Cache_entry	entry,
			*cep;

	int	foundmatch = FALSE,
		access_status = ACCESS_DENIED,
		i;
		

	char	*endpath,
		*endrelpath,
		*dp,
		*dirp,
		entryline[CACHELINE_LEN],
		srelpath[MIDLEN],
		cdirbuf[MIDLEN],
		dirlist[MIDLEN],
		cfpath[MIDLEN + SMALLLEN],
		cbuf[MIDLEN];

	if ( depth <= 0 )
		return FALSE;

	mystrncpy( cdirbuf, cdir, MIDLEN);

	endpath = cdirbuf;
	while ( *endpath) /* endpath should point to / before cache name */
		endpath++;
	*endpath = '/';
	*(endpath + 1) = '\0';

	mystrncpy( srelpath, srel, MIDLEN);
	endrelpath = srelpath;
	while ( *endrelpath) 
		endrelpath++;
	if ( *srel) {
		*endrelpath++ = '/';
		*endrelpath = '\0';
	}
	/* endrelpath now points AFTER the '/' at the end */

	fmt2( cfpath, MIDLEN, cdirbuf, cfname);

	if ( (cfp = fopen( cfpath, "r")) == (FILE *) NULL ) {
		logerr( err_m[41], cfpath);
		return FALSE;
	}


	read_cache_dirinfo( cfp, dirinfo_p);

	if ( dirinfo_p->attributes & WN_DIRNOSEARCH) {
		fclose( cfp);
		return FALSE;
	}

	if ( *dirinfo_p->authmod
			&& !streq( dir_p->authrealm, dirinfo_p->authrealm)) {
		fclose( cfp);
		return FALSE;
	}

	access_status = chkaccess( cfpath,  dirinfo_p->accessfile);

	switch( access_status) {
	case ACCESS_GRANTED:
	case ACCESS_PRIVILEGED:
		break;
	default:
		fclose( cfp);
		return FALSE;
	}

	/* Get list of subdirs from dir record in first line of index.cache */
	mystrncpy( dirlist, dirinfo_p->subdirs, MIDLEN);

	dirp = dirlist;
	cep = &entry;
	cep->line = entryline;


	while ( read_cache_file( cep, cfp, (char *) NULL)) {
		/*
		if ( cep->attributes & WN_NOSEARCH)
			continue;
		*/
		if ( *(cep->redirect))
			continue;

		mystrncpy( cbuf, entry.title, MIDLEN);

		switch( ip->type) {
		case RTYPE_TSEARCH:
			ismatch = regfind( regp, strlower( cbuf));
			break;
		case RTYPE_KSEARCH:
			ismatch = regfind( regp, strlower(entry.keywords));
			break;
		case RTYPE_TKSEARCH:
			ismatch = regfind( regp, strlower( cbuf))
				|| regfind( regp, strlower( entry.keywords));
			break;
		case RTYPE_FIELDSEARCH:
			i = atoi( ip->param_value + 5);
			if ( (i < 0) || (i >= NUMFIELDS)) {
				senderr( SERV_ERR, err_m[58], "");
				return FALSE;
			}
			ismatch = regfind( regp, strlower(entry.field[i]));
			break;
		default:
			break;
		}
		if ( ismatch ) {
			foundmatch |= ismatch;
			send_match_line( ip, cep, srelpath);
		}
	}

	while ( (dp = get_next_dir(  &dirp)) ) {
		mystrncpy( endpath + 1, dp, SMALLLEN);
		mystrncpy( endrelpath, dp, SMALLLEN);
		foundmatch |= csearch( cdirbuf, srelpath, ip,  depth - 1);
	}

	fclose( cfp);
	return foundmatch;
}

static char *
get_next_dir( dpp)
char	**dpp;
{
	register char	*cp;

	char	*dp2;

	cp = *dpp;
	if ( !*cp)
		return NULL;
	while ( *cp && ( (*cp == ',')  || isspace( *cp)))
		cp++;	/* Skip leading space or commas */
	dp2 = cp;

	while ( *cp && (*cp != ',') && !(isspace( *cp)))  
		cp++;
	if ( *cp ) {
		*cp = '\0';
		*dpp = ++cp;
	}
	else
		*dpp = cp;

	return dp2;
}



static void
send_match_line( ip, cep, srelpath)
Request	*ip;
Cache_entry	*cep;
char		*srelpath;
{
	char		buf[MIDLEN],
			buf2[MIDLEN];

	if ( !(ip->status & WN_MATCH_SENT)) {  /* first matching line */
		ip->status |= WN_MATCH_SENT;
		if ( isdirwrapped( dir_p)) {
			do_swrap( ip);
			if ( ip->status & WN_ERROR)
				return;  /* abort this transaction */
			send_text_line( "<ul>\n");
		}
		else {
			send_text_line( search_m[4]);
			sanitize( buf2, ip->param_value, MIDLEN);
			buf2[6] = '\0'; /* truncate to 6 chars */
			fmt3( buf, MIDLEN, search_m[5], buf2, search_m[6]);
			send_text_line( buf);
			send_text_line( search_m[7]);
			sanitize( buf2, ip->query, MIDLEN);
			fmt3( buf, MIDLEN, search_m[2], buf2, "'</b>.\n");
			send_text_line( buf);
			send_text_line( "<ul>\n");
		}

	}
	if ( *cep->basename) {
		fmt3( buf, MIDLEN, "<li><a href=\"", srelpath, cep->basename);
		fmt3( buf, MIDLEN, buf, "\"> ", cep->title);
		mystrncat( buf, " </a>\n", MIDLEN);
		send_text_line( buf);
	}
	else {
		fmt3( buf, MIDLEN, "<li><a href=\"", cep->url, "\"> ");
		fmt3( buf, MIDLEN, buf, cep->title, " </a>\n");
		send_text_line( buf);
	}
}


void
list_search( ip)
Request	*ip;
{
	FILE	*gfp;

	int	found = FALSE;

	check_query( ip, &regp, &regp);
	if ( ip->type == RTYPE_FINISHED)
		return;

	if ( (ip->attributes & WN_NOSEARCH) || 
			!(ip->filetype & WN_TEXT)) {
		senderr( "403", err_m[51], ip->relpath);
		return;
	}

	*ip->length = '\0';

	search_prolog( ip, out_m[6]);

	check_perm( ip, ip->filepath);
        if ( (gfp = fopen( ip->filepath, "r")) == (FILE *) NULL ) {
		senderr( SERV_ERR, err_m[1], ip->relpath);
		return;
	}

	found = do_list_search( ip, regp, gfp);

	fclose( gfp);

	if ( !found) {
		send_nomatch( ip, 'f');
		return;
	}
	
	if ( ip->attrib2 & WN_SWRAPPED)
		do_swrap( ip);
	else
		search_epilog( );

	writelog(  ip, "Sent list search", "");
}

static int
do_list_search( ip, rp, fp)
Request		*ip;
struct regprog	*rp;
FILE	*fp;
{
	register char	*cp,
			*cp2;

	char	linebuf[BIGLEN],
		buf[BIGLEN];
	int	fnd = FALSE,
		first = TRUE;


	while ( fgets( linebuf, BIGLEN, fp)) {
		cp = linebuf;
		while ( isspace( *cp))
			cp++;
		if ( strncasecmp( cp, "<li>", 4))
			continue;
		mystrncpy( buf, cp + 4, BIGLEN);
		if ( (cp2 = strchr( buf, '>')) == NULL )
			continue;
		if ( (cp = strchr( ++cp2, '<')) == NULL )
			continue;
		*cp = '\0';
		strlower( cp2);
		if ( regfind( rp, cp2) ) {
			if ( first && ip->attrib2 & WN_SWRAPPED) {
				do_swrap( ip);
				if ( ip->status & WN_ERROR)
					return FALSE;
					/* abort this transaction */
				send_text_line( "<ul>\n");
			}
			else if ( first) {
				char	buf2[MIDLEN];

				send_text_line( search_m[4]);
				mystrncpy( buf2, search_m[8], MIDLEN);
				send_text_line( buf2);
				send_text_line( search_m[7]);
				sanitize( buf2, ip->query, MIDLEN);
				fmt3( buf, BIGLEN, search_m[2], buf2,
						"'</b>.\n");
				send_text_line( buf);
				send_text_line( "<ul>\n");
			}
			send_text_line( linebuf);
			first = FALSE;
			fnd =  TRUE;
		}
	}
	if ( fnd)
		send_text_line( "</ul>\n");
	return fnd;
}

