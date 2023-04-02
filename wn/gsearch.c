/*
    Wn: A Server for the HTTP
    File: wn/gsearch.c
    Version 2.3.13
    
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

#define	MAXMATCHES	(20)


#include <string.h>
#include "wn.h"
#include "parse.h"
#include "reg.h"
#include "regi.h"

static char	*curr_linep,
		*prev_filep,
		*remove_tags();

static int	gfound_match(),
		cfound_match(),
		file_grep(),
		in_tag(),
		ok2mark = FALSE,
		begin_offset,
		end_offset,
		wrapped,
		ishtml;

static unsigned	curr_line_num;

static void	format_markline(),
		send_dirgrep(),
		send_filegrep(),
		send_grep_line();


static struct regprog	*regp,
			*htmlregp;


void
sendgrep( ip)
Request	*ip;
{
	char	curr_line[MIDLEN],
		prev_filename[MIDLEN];

	curr_linep = curr_line;
	*curr_linep = '\0';
	prev_filep = prev_filename;
	*prev_filep = '\0';

	*ip->length = '\0';
	if ( iswndir( ip))
		send_dirgrep( ip);
	else
		send_filegrep(ip);
	return; /* to process_url */
}


/* Do regexp search of directory pointed to by ip->filepath */

static void
send_dirgrep( ip)
Request	*ip;
{
	FILE	*cfp,
		*gfp;

	register char	*cp;

	int	found = FALSE,
		max_matches = MAXMATCHES,
		num_matches;

	char	entryline[CACHELINE_LEN],
		commandbuf[2*MIDLEN],
		tmpbuf[2*MIDLEN];


	Parsedata	pdata;

	Cache_entry	*cep,
			entry;

	pdata.show = SHOW_IT;

	check_query( ip, &regp, &htmlregp);

	if ( ip->type == RTYPE_FINISHED)
		return;

	if ( ip->type == RTYPE_LINESSEARCH)
		max_matches = 4*MAXMATCHES;

	cep = &entry;
	cep->line = entryline;

	if ( dir_p->attributes & WN_DIRNOSEARCH) {
		senderr( "403", err_m[32], ip->relpath);
		return;
	}

	if ( (cfp = fopen( ip->cachepath, "r")) == (FILE *) NULL ) {
		senderr( SERV_ERR, err_m[1], ip->cachepath);
		return;
	}

	search_prolog( ip, out_m[1]);

	fgets( entryline, CACHELINE_LEN, cfp);  /* skip directory line */

	while ( read_cache_file( cep, cfp, (char *) NULL)) {
		if ( cep->attributes & WN_NOSEARCH)
			continue;
		if ( *(cep->redirect))
			continue;
		if ( strncmp( cep->content, "text", 4))
			continue;
		ishtml = ( strncmp( cep->content, "text/html", 9) == 0);
		wrapped = (int) *cep->wrappers;
		mystrncpy( tmpbuf, ip->cachepath, MIDLEN);
		cp = strrchr( tmpbuf, '/');
		mystrncpy( cp + 1, cep->basename, SMALLLEN);

		check_perm( ip, tmpbuf);
		if ( cep->attributes & WN_FILTERED) {
			if ( WN_SU_EXEC) {
				char	*cpx,
					xbuf[MIDLEN];
				
				mystrncpy( commandbuf, cep->filter, MIDLEN);
				fmt3( xbuf, MIDLEN, "WN_FILEPATH_INFO=", 
							tmpbuf, NULL);
				if ( (cpx = strdup( xbuf)) == NULL)
					logerr( err_m[64], "gsearch.send_dirgrep");
				else
					putenv( cpx);
			}
			else {
				fmt3( commandbuf, 2*MIDLEN, cep->filter, 
						" < ", tmpbuf);
			}

			if ((gfp = WN_popen( commandbuf, "r")) == (FILE *)NULL) {
				logerr( err_m[17], ip->filepath);
				logerr( err_m[18], ip->filter);
				continue;
			}
		}
                else if ( (gfp = fopen( tmpbuf, "r")) == (FILE *) NULL )
                        /* File may no longer be there, keep going */
                        continue;
		curr_line_num = num_matches = 0;
		if ( cep->attributes & WN_PARSE )
			reset_parse_err( tmpbuf, 0, &pdata);

		if ( (ip->type == RTYPE_CONTEXTSEARCH)
				|| (ip->type == RTYPE_LINESSEARCH)) {
						/* dir context search */
			while ( cfound_match( (ishtml ? htmlregp : regp),
							 gfp, &pdata) ) {
				num_matches++;
				found = TRUE;
				if ( num_matches <= max_matches)
					send_grep_line( ip, cep->basename,
							cep->title);
				else {
					send_text_line( search_m[0]);
					break;
				}
			}
			ok2mark = FALSE;
		}
		else if ( gfound_match( (ishtml ? htmlregp : regp),
							gfp, &pdata) ) { 
			 /* dir grep search */
			found = TRUE;
			send_grep_line( ip, cep->basename, cep->title);
		}
		if ( cep->attributes & WN_FILTERED)
			pclose( gfp);
		else
			fclose( gfp);
	}
	fclose( cfp);

	if ( !found) {
		send_nomatch( ip, 'd');
		return;
	}
	
	if ( ip->type == RTYPE_CONTEXTSEARCH)
		send_text_line( "\t</ul>\n");
	send_text_line( "</ul>\n");

	if ( dir_p->attributes & WN_DIRWRAPPED) {
		do_swrap( ip);
	}
	else
		search_epilog( );

	writelog(  ip, log_m[10], "");
}

/*
 * Context search find match 
 */

static int
cfound_match( rp, fp, pdp)
struct regprog	*rp;
FILE	*fp;
Parsedata	*pdp;
{
	unsigned	searchoff;
	int		token;

	char	linebuf[MIDLEN],
		svbuf[MIDLEN],
		dummy,
		*cp,
		*startmatch,
		*endmatch,
		*line;


	searchoff = FALSE;
	pdp->show = SHOW_MSK + IN_SECT_MSK;

	if ( wrapped)
		ok2mark = TRUE;
	svbuf[0] = '\0';
	while ( TRUE) {
		if ( ishtml )
			line = get_parse_line( linebuf, svbuf, MIDLEN, fp);
		else
			line = fgets( linebuf,  MIDLEN, fp);

		if ( !line)
			break;
		curr_line_num++;
		pdp->currline++;
		if ( ishtml ) {
			token = get_parse_token( linebuf, &dummy, pdp);
			if ( token != TEXT_TOKEN) {
				switch ( token) {
				case SEARCH_ON:
					searchoff = FALSE;
					break;
				case SEARCH_OFF:
					searchoff = TRUE;
					break;
				default:
					set_show( token, pdp);
				}
				continue;
			}
			if ( searchoff || !( pdp->show & SHOW_MSK))
				continue;
		}
		mystrncpy( curr_linep, linebuf, MIDLEN);
		strlower( linebuf);
		if ( !ok2mark) {
			if ( strstr( linebuf, "</head>"))
				ok2mark = TRUE;
			if ( curr_line_num > 12 )
				ok2mark = TRUE;
		}
		cp = linebuf;
		regfind( rp, cp);
		while ( regfind( rp, cp) ) {
			startmatch = reglp(0);
			endmatch = regrp(0);
			if ( in_tag( linebuf, startmatch, endmatch)) {
				cp = startmatch + 1;
				continue;
			}
			begin_offset = (int) ( startmatch - linebuf);
			end_offset = (int) ( endmatch - linebuf);
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * in_tag( line, point, end) returns TRUE or FALSE depending on whether 
 * anything between point and end is inside of < and >.  The opening < 
 * may be in a  previous (unseen) line and the closing > may be in a
 * subsequent line.
 */

static int
in_tag( line, point, end)
char	*line,
	*point,
	*end;
{
	char		lastseen = '\0';

	while ( line < point ) {
		switch ( *line) {
		case '<':
		case '>':
			lastseen = *line++;
			break;
		default:
			line++;
		}
	}
	switch ( lastseen) {
	case '<':
		return TRUE;
	case '>':
		return FALSE;
	default:
		for (;;) {
			switch ( *line) {
			case '<':
				if ( line < end)
					return TRUE;
				else
					return FALSE;
			case '>':
				return TRUE;
			case '\0':
				return FALSE;
			default:
				line++;
			}
		}
	}
}


static int
gfound_match( rp, fp, pdp)
struct regprog	*rp;
FILE	*fp;
Parsedata	*pdp;
{
	char		dummy,
			linebuf[MIDLEN];
	unsigned	searchoff;
	int		token;

	searchoff = FALSE;
	pdp->show = SHOW_MSK + IN_SECT_MSK;

	while ( fgets( linebuf, MIDLEN, fp)) {
		pdp->currline++;
		if ( ishtml) {
			token = get_parse_token( linebuf, &dummy, pdp);
			if ( token != TEXT_TOKEN) {
				switch ( token) {
				case SEARCH_ON:
					searchoff = FALSE;
					break;
				case SEARCH_OFF:
					searchoff = TRUE;
					break;
				default:
					set_show( token, pdp);
				}
				continue;
			}
			if ( searchoff || !( pdp->show & SHOW_MSK))
				continue;
		}
		mystrncpy( curr_linep, linebuf, MIDLEN);
		strlower( linebuf);
		if ( regfind( rp, linebuf) )
			return TRUE;
	}
	return FALSE;
}


static void
send_grep_line( ip, name, title)
Request	*ip;
char	*name,
	*title;
{
	char		buf[BIGLEN];

	if ( !(ip->status & WN_MATCH_SENT)) {  /* first matching line */
		ip->status |= WN_MATCH_SENT;
		if ( iswndir( ip) && dir_p->attributes & WN_DIRWRAPPED)
			do_swrap( ip);
		else if ( ip->attrib2 & WN_SWRAPPED)
			do_swrap( ip);
		else {
			char buf2[MIDLEN];

			send_text_line( search_m[4]);
			sanitize( buf2, ip->param_value, MIDLEN);
			buf2[6] = '\0'; /* truncate to 6 chars */
			fmt3( buf, MIDLEN, search_m[5], buf2, search_m[6]);
			send_text_line( buf);
			send_text_line( search_m[7]);
			sanitize( buf2, ip->query, MIDLEN);
			fmt3( buf, MIDLEN, search_m[2], buf2, "'</b>.\n");
			send_text_line( buf);
		}
		if ( ip->status & WN_ERROR)
			return;  /* abort this transaction */
		send_text_line( "<ul>\n");
	}
	if ( ip->type == RTYPE_LINESSEARCH)
			format_markline( name);
	else if ( ip->type == RTYPE_CONTEXTSEARCH) {
		if ( streq( name, prev_filep) )
			format_markline( name);
		else {
			if ( *prev_filep)
				send_text_line("\t</ul>\n");
			mystrncpy( prev_filep, name, MIDLEN);
			fmt3( buf, MIDLEN, "<li><b>Title:</b> <a href=\"",
					name, "\">");
			fmt3( buf, MIDLEN, buf, title, "</a>\n");
			send_text_line( buf);
			send_text_line(
				"\t<br><b>Matching lines:</b>\n\t<ul>\n");
			format_markline( name);
		}
	}
	else {
		fmt3( buf, MIDLEN, "<li><a href=\"", name, "\">");
		fmt3( buf, MIDLEN, buf, title, "</a>\n");
		send_text_line( buf);
	}
}

static void
format_markline( base)
char	*base;
{
	register char	*cp;

	char	*beginmatch,
		*endmatch,
		buf[MIDLEN],
		mline[SMALLLEN];


	cp = buf;

	beginmatch = curr_linep + begin_offset;
	endmatch = curr_linep + end_offset;
	*mline = '\0';
	mystrncpy( buf, "\t<li> ", 10);
	cp += 6;
	if ( ok2mark && ishtml)
		Snprintf4( mline, SMALLLEN, ";mark=%d,%d,%d#%.32s", 
			curr_line_num, begin_offset, end_offset, WN_HTML_MARK);

	cp = remove_tags( cp, curr_linep, beginmatch, &buf[MIDLEN - 1]);

	fmt3( buf, MIDLEN, buf, "<a href=\"", base);
	fmt3( buf, MIDLEN, buf, mline, "\">");

	while ( *cp)
		cp++;

	cp = remove_tags( cp, beginmatch, endmatch, &buf[MIDLEN - 1]);

	if ( cp < &buf[MIDLEN - 5]) {
		mystrncpy( cp, "</a>", 10);
		cp +=4;
	}
	cp = remove_tags( cp, endmatch, (char *) NULL, &buf[MIDLEN - 1]);
	*cp = '\0';	
	send_text_line( buf);
}

/*
 * char *remove_tags( p1, p2, end, p1_end)  Copy p2 to p1 until end is reached
 * or p2 is exhausted.  If doc is not HTML URL encode '<', '>', and & and 
 * if it is remove tags.
 * Use end = NULL to use all of p2. 
 * Return pointer to EOS at end of copied p1.
 */

static char
*remove_tags ( p1, p2, end, p1_end)
char	*p1,
	*p2,
	*end,
	*p1_end;
{
	int	intag = FALSE;
	char	*start;

	start = p1;
	if ( end == NULL)
		end = p2 + strlen( p2);
	if ( ishtml) {
		while ( *p2 && p2 < end) {
			switch( *p2) {
			case '<':
				intag = TRUE;
				p2++;
				break;
			case '>':
				if ( !intag)
					p1 = start;
				p2++;
				intag = FALSE;
				break;
			default:
				if ( intag)
					p2++;
				else
					*p1++ = *p2++;
			}
		}
	}
	else { /* not in HTML amperfy stuff */
		while ( *p2 && p2 < end && (p1 < p1_end - 5)) {
			switch( *p2) {
			case '<':
				strcpy( p1, "&lt;");
				p1 += 4;
				p2++;
				break;
			case '>':
				strcpy( p1, "&gt;");
				p1 += 4;
				p2++;
				break;
			case '&':
				strcpy( p1, "&amp;");
				p1 += 5;
				p2++;
				break;
			default:
				*p1++ = *p2++;
			}
		}
	}
	*p1 = 0;
	return p1;
}

/* Do regexp search of file pointed to by ip->filepath */

static void
send_filegrep( ip)
Request	*ip;
{
	FILE	*gfp;
	int	found = FALSE;
	Parsedata	pdata;

	pdata.show = SHOW_IT;
	ip->content_type = BUILTIN_CONTENT_TYPE;
	*ip->length = '\0';
	check_query( ip, &regp, &htmlregp);

	if ( (ip->attributes & WN_NOSEARCH) || 
			!(ip->filetype & WN_TEXT)) {
		senderr( "403", err_m[51], ip->relpath);
		return;
	}

	search_prolog( ip, out_m[3] ); /* does http_prolog */

	ishtml = (ip->filetype & WN_ISHTML);

	check_perm( ip, ip->filepath);

	if ( ip->attributes & WN_FILTERED) {
		char commandbuf[MIDLEN];

		fmt3( commandbuf, MIDLEN, ip->filter, " < ", ip->filepath);
		if ((gfp = WN_popen( commandbuf, "r")) == (FILE *)NULL) {
			senderr( SERV_ERR, err_m[1], ip->relpath);
			return;
		}
	}
        else if ( (gfp = fopen( ip->filepath, "r")) == (FILE *) NULL ) {
		senderr( SERV_ERR, err_m[1], ip->relpath);
		return;
	}
	curr_line_num = 0;
	if ( ip->attributes & WN_PARSE )
		reset_parse_err( ip->filepath, 0, &pdata);

	if ( ip->type == RTYPE_CONTEXTSEARCH) {
		while ( cfound_match( (ishtml ? htmlregp : regp), gfp,
							&pdata )) {
			found = TRUE;
			send_grep_line( ip, ip->basename, ip->title);
		}
		ok2mark = FALSE;
	}
	else
		found = file_grep( ip, (ishtml ? htmlregp : regp), gfp);

	if ( ip->attributes & WN_FILTERED)
		pclose( gfp);
	else
		fclose( gfp);

	if ( !found) {
		send_nomatch( ip, 'f');
		return;
	}
	
	if ( ip->type == RTYPE_CONTEXTSEARCH)
		send_text_line( "\t</ul>\n</ul>\n");

	if ( ip->attrib2 & WN_SWRAPPED)
		do_swrap( ip);
	else
		search_epilog( );

	writelog(  ip, log_m[10], "");
}

static int
file_grep( ip, rp, fp)
Request		*ip;
struct regprog	*rp;
FILE	*fp;
{
	char	linebuf[MIDLEN],
		buf[BIGLEN];
	int	fnd = FALSE,
		first = TRUE;


	while ( fgets( linebuf, MIDLEN, fp)) {
		mystrncpy( curr_linep, linebuf, MIDLEN);
		strlower( linebuf);
		if ( regfind( rp, linebuf) ) {
			if ( first && ip->attrib2 & WN_SWRAPPED) {
				do_swrap( ip);
				if ( ip->status & WN_ERROR)
					return FALSE;
					/* abort this transaction */
				send_text_line( "<pre>\n");
			}
			else if ( first) {
				char buf2[MIDLEN];

				send_text_line( search_m[4]);
				sanitize( buf2, ip->param_value, MIDLEN);
				buf2[6] = '\0'; /* truncate to 6 chars */
				fmt3( buf, MIDLEN, search_m[5], buf2,
					search_m[6]);
				send_text_line( buf);
				sanitize( buf2, ip->query, MIDLEN);
				fmt3( buf, MIDLEN, search_m[2], buf2,
					"'</b>.\n");
				send_text_line( buf);
				send_text_line( "<pre>\n");
			}
			amperline( linebuf, curr_linep, MIDLEN);
			send_text_line( linebuf);
			first = FALSE;
			fnd =  TRUE;
		}
	}
	if ( fnd)
		send_text_line( "</pre>\n");
	return fnd;
}


