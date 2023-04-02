/*
    Wn: A Server for the HTTP
    File: wn/parse.c
    Version 2.4.0
    
    Copyright (C) 1996-2001  <by John Franks>

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
#include <string.h>
#include <time.h>
#include "wn.h"
#include "parse.h"
#include "reg.h"


#define MAX_REDIRECT	(10)

extern long	atol();

extern char	*getenv();

static void	send_fp(),
		send_include(),
		out_markline(),
		doc_parse();

static char	*in_anchor();

static FILE	*openfp();


static int	isinlist(),
		scnt = 0;

static Parsedata	swpdata;


typedef struct File_or_Pipe {
	FILE	*fp;
	int	type;
} File_or_Pipe;

static File_or_Pipe	swrapfp_st = { NULL, FRP_FILE};


WN_CONST 
char * WN_CONST parserr_m[] = {
	/* 0 */ "",
	/* 1 */ "Parse error: 'else' or 'elif' with no 'if'",
	/* 2 */ "Parse error: 'endif' with no 'if'",
	/* 3 */ "Parse error: 'start' inside 'if' construct or multiple starts with no 'end'",
	/* 4 */ "Parse error: 'end' inside 'if' construct or multiple ends with no 'start'",
	/* 5 */ "Parse line not understood",
	/* 6 */ "Parse error: Bad if accessfile format",
	/* 7 */ "Parse error: Bad if - regexp format",
	/* 8 */ "Conditional text file line overflow",
	/* 9 */ "Can't open Conditional text file",
	/* 10 */ "Redirect attempted after text sent",
	/* 11 */ "Missing quote mark in redirect URL",
	/* 12 */ "If-Elif-Else nested too deeply",
	/* 13 */ "If-Elif condition syntax error",
	/* 14 */ "Parse construct too long",
	/* 15 */ "Unexpected end of file",
	/* 16 */ "No such environment variable"
};

/*
 * do_wrap( ip, show)
 * Handle inserted files or files with wrappers.  
 */

void
do_wrap( ip, show)
Request		*ip;
unsigned	show;
{
	static enum { 	before_file,
			in_file,
			after_file } wrap_place;

	int		toplevel = FALSE;
	register char	*cp;
	File_or_Pipe	frp_st;

	Parsedata	pdata;

	if ( (ip->type != RTYPE_FILE) && (ip->type != RTYPE_MARKLINE))
			/* only do wrapping for files */
		return;

	pdata.show = show;
	pdata.currline = 0;

	/*
	 * ip->do_wrap_1st_time gets reinitialized
	 * in keepalive loop in wn.c.
	 */
	if ( ip->do_wrap_1st_time) {
		wrap_place = before_file;
		toplevel = TRUE;
		ip->do_wrap_1st_time = FALSE;
		scnt = 0;
	}


	cp = ip->inclptr;

	if ( !*cp ) {
		pdata.currfile = ip->basename;
		switch ( wrap_place) {
		case before_file:
			/* end of wrappers send the file */
			if ( !(ip->filetype & WN_TEXT)) {
				senderr( DENYSTATUS, err_m[34],
					ip->relpath);
				wn_exit( 0); /* senderr: DENYSTATUS */
			}

			wrap_place = in_file;

			ip->inclptr = ip->includes;
			/* this will be overridden for list include */

			send_fp( ip, &pdata);
			wrap_place = after_file;
			/* If some includes are left, tack them on the end */
			while ( toplevel && (*ip->inclptr))
				do_wrap( ip, pdata.show);
			return;

		case in_file:
		case after_file:
			if ( !*cp ) {
				logerr( err_m[35], "");
				return;
			}
		}
	}

	while ( *cp && *cp != ',')
		cp++;

	if ( *cp )
		*cp++ = '\0';
	pdata.currfile = ip->inclptr;
	if ( (openfp( ip->inclptr, ip, &frp_st)) == (FILE *) NULL ) {
		/* Error logged in openfp */

		if ( ip->attrib2 & WN_LIST_INCL)
			ip->inclptr = wn_empty; /* safe empty spot */
		else
			ip->inclptr = cp;
		return;
	}
	else {
		if ( ip->attrib2 & WN_LIST_INCL)
			ip->inclptr = wn_empty; /* safe empty spot */
		else
			ip->inclptr = cp;

		send_include( ip, frp_st, &pdata);

		if ( wrap_place == after_file ) {
			 /* file done but but still some includes */
			while ( toplevel && (*ip->inclptr))
				do_wrap( ip, pdata.show);

		}
		return;
	}
}


/*
 * static void send_include( ip, frp_st, pdp)
 * Actually send the include or wrapper file. 
 */

static void
send_include( ip, frp_st, pdp)
Request	*ip;
File_or_Pipe	frp_st;
Parsedata	*pdp;
{
	char	linebuf[BIGLEN],
		svbuf[BIGLEN],
		insert_param[SMALLLEN];

	int	token;

	pdp->currline = 0;
	svbuf[0] = '\0';
	while ( get_parse_line( linebuf, svbuf, BIGLEN, frp_st.fp)) {
		pdp->currline++;
		token = get_parse_token( linebuf, insert_param, pdp);

		if ( token == EMPTY_TOKEN ) {
			if ( !(ip->status & WN_PROLOGSENT) )
				continue;
			else
				token = TEXT_TOKEN;
		}

		/* ignore if using section but not between start and end */
		if ( (pdp->show & (SECT_MSK)) && !(pdp->show & (IN_SECT_MSK))
						&& ( token != START))
			continue;

		if ( ( token == TEXT_TOKEN) || (token == COMMENT)) {
			if ( (pdp->show & SHOW_IT) == SHOW_IT)
				send_text_line( linebuf);
			continue;
		}
		else {
			if ( set_show( token, pdp))
				continue;
			else
				doc_parse( ip, token, pdp, insert_param);
		}
	}
	if ( frp_st.type == FRP_PIPE)
		pclose( frp_st.fp);
	else
		fclose( frp_st.fp);
}

/*
 * send_fp( ip, pdp) Actually send the main file.
 */

static void
send_fp( ip, pdp)
Request	*ip;
Parsedata	*pdp;
{

	char		linebuf[BIGLEN],
			svbuf[BIGLEN],
			insert_param[SMALLLEN];

	int		token;

	if ( ip->type == RTYPE_MARKLINE ) {
		send_markline_doc( ip, pdp->show);
		return;
	}

	pdp->currline = 0;
	svbuf[0] = '\0';
	while ( get_parse_line( linebuf, svbuf, BIGLEN, ip->fp)) {
		pdp->currline++;
		token = get_parse_token( linebuf, insert_param, pdp);

		if ( token == EMPTY_TOKEN ) {
			if ( !(ip->status & WN_PROLOGSENT) )
				continue;
			else
				token = TEXT_TOKEN;
		}

		/* ignore if using section but not between start and end */
		if ( (pdp->show & (SECT_MSK)) && !(pdp->show & (IN_SECT_MSK))
						&& ( token != START))
			continue;

		if ( ( token == TEXT_TOKEN) || (token == COMMENT)) {
			if ( (pdp->show & SHOW_IT) == SHOW_IT)
				send_text_line( linebuf);
			continue;
		}
		else {
			if ( set_show( token, pdp))
				continue;
			else
				doc_parse( ip, token, pdp, insert_param);
		}
	}

	if ( ip->fptype == FRP_PIPE)
		pclose( ip->fp);
	else
		fclose( ip->fp);
}


static void
doc_parse( ip, token, pdp, insert_ptr)
Request 	*ip;
int		token;
Parsedata	*pdp;
char		*insert_ptr;
{
	char		*cp,
			buf[MIDLEN + 1];

	unsigned	show2;

	switch ( token) {
	case FIELD:				/* field# */
		if ( (pdp->show & SHOW_IT) == SHOW_IT ) {
			mystrncpy( buf, ip->field[atoi(insert_ptr)], MIDLEN);
			send_text_line( buf);
		}
		break;

	case ENVIRON:				/* environ variable */
		if ( (pdp->show & SHOW_IT) == SHOW_IT ) {
			if ( (cp = getenv(insert_ptr)) == NULL) {
				logerr( parserr_m[16], insert_ptr);
				break;
			}
			mystrncpy( buf, cp, MIDLEN);
			send_text_line( buf);
		}
		break;

	case INCLUDE:				/* include */
		do_wrap( ip, pdp->show);
		break;

	case LIST_INCLUDE:			/* list include */
		if ( isinlist( insert_ptr, ip->list_incl)) {
			ip->inclptr = insert_ptr;
			do_wrap( ip, pdp->show);
		}
		else
			logerr( err_m[111], insert_ptr);

		break;
		
	case LAST_MOD_DATE:
		if ( (pdp->show & SHOW_IT) == SHOW_IT ) {
		     strftime(buf, 12, "%d-%b-%Y", localtime(&ip->mod_time)); 
                     send_text_line(buf);
                }
		break;

	case REDIRECT:
		if ( (pdp->show & SHOW_IT) == SHOW_IT ) {
			if ( ip->status & WN_PROLOGSENT ) {
				logerr( parserr_m[10], pdp->currfile);
				break;
			}
			this_conp->keepalive = FALSE;
			dolocation( outheadp->location, ip, 301);
			wn_exit( 0);  /* after redirect dolocation; UGLY */
		}
		break;

	case SECTION:
		show2 = pdp->show;
		if ( !(show2 & SECT_MSK)) {
			show2 |= SECT_MSK;
			show2 &= ~IN_SECT_MSK;
		}
		do_wrap( ip, show2);
		break;
	case LIST_SECTION:
		if ( !isinlist( insert_ptr, ip->list_incl)) {
			logerr( err_m[111], insert_ptr);
			break;
		}
		show2 = pdp->show;
		if ( !(show2 & SECT_MSK)) {
			show2 |= SECT_MSK;
			show2 &= ~IN_SECT_MSK;
		}
		ip->inclptr = insert_ptr;
		do_wrap( ip, show2);
		break;

	case QUERY:
		if ( (pdp->show & SHOW_IT) == SHOW_IT ) {
			sanitize( buf, ip->query, MIDLEN);
			send_text_line( buf);
		}
		break;
	case TITLE:
		if ( (pdp->show & SHOW_IT) == SHOW_IT ) {
			mystrncpy( buf, ip->title, MIDLEN);
			send_text_line( buf);
		}
		break;
	case KEYWORDS:
		if ( (pdp->show & SHOW_IT) == SHOW_IT ) {
			mystrncpy( buf, ip->keywords, MIDLEN);
			send_text_line( buf);
		}
		break;
	}
}


/*
 * static int isinlist( item, list)
 * If "item" is in a comma separated list "list" then return TRUE
 * else return FALSE.
 */

static int
isinlist( item, list)
char	*item,
	*list;
{
	char	c,
		*cp;

	if ( (cp = strstr( list, item)) == NULL)
		return FALSE;
	c = *(cp + strlen( item));
	if ( ( c == ',') || (c == '\0') )
		return TRUE;
	return FALSE;
}


/*
 * static void openfp( name, ip, frp)
 * If name starts with '/' assume it is relative to system root,
 * if it starts with ~/ it is relative to WN root  otherwise
 * assume relative to current directory.  If name starts with '!'
 * it is a command to execute, so use popen( ).  If open fails log error
 * and return NULL.  Check UID and GID on file to see if they are
 * compatible with current security options in force.
 */

static FILE
*openfp( name, ip, frp)
char	*name;
Request	*ip;
File_or_Pipe	*frp;
{
	FILE	*ofp;
	char	buf[MIDLEN];

	if ( *name == '!' ) {
		name++;
		exec_ok( ip);
		if ( getfpath( buf, name, ip) == FALSE) {
			logerr( err_m[36], name);
			return NULL;
		}
		check_perm( ip, buf);
		if ( (ofp = WN_popen( buf, "r")) == (FILE *) NULL ) {
			logerr( err_m[36], name);
			return NULL;
		}
		frp->fp = ofp;
		frp->type = FRP_PIPE;
		return ofp;
	}
		
	if ( getfpath( buf, name, ip) == FALSE) {
		logerr( err_m[1], buf);
		return NULL;
	}
	check_perm( ip, buf);
	if ( (ofp = fopen( buf, "r")) == (FILE *) NULL ) {
		logerr( err_m[1], buf);
		return NULL;
	}
	frp->fp = ofp;
	frp->type = FRP_FILE;
	return ofp;
}

/*
 * void do_nomatchsub( ip, location)
 * If the return is empty (e.g. a search with no matches) substitute 
 * another local file.   If location
 * has no '/' then assume it is a file in the same directory and
 * process it as a URL immediately.  Error otherwise.  We can't
 * use a redirect because header (http_prolog) has already been
 * sent (via search_prolog) before we get here.
 */

void
do_nomatchsub( ip, location)
Request	*ip;
char	*location;
{
	Parsedata	pdata;
	File_or_Pipe	frp_st;

	if ( strchr( location, '/') != NULL ) {
		logerr( err_m[108], location);
		return;
	}

	if ( openfp( location, ip, &frp_st) == (FILE *) NULL ) {
		logerr( err_m[83], location);
		return;
	}

	pdata.currline = 0;
	pdata.currfile = location;
	pdata.show = SHOW_IT;

	ip->fp = frp_st.fp;
	ip->fptype = frp_st.type;

	ip->filetype |= WN_ISHTML;
	ip->attributes |= WN_PARSE;
	send_fp( ip, &pdata);

	writelog( ip, log_m[2], location);
	return;		/* to send_nomatchsub */
}



/*
 * send_markline_doc( ip, show) Send the main file when 
 * ip->type = RTYPE_MARKLINE.
 *
 */

void
send_markline_doc( ip, show)
Request		*ip;
unsigned	show;
{

	register char	*cp,
			*cp2;

	unsigned	markline,
			off1,
			off2,
			i = 0;


	char	linebuf[MIDLEN],
		svbuf[MIDLEN],
		bigbuf[3*MIDLEN],
		insert_param[SMALLLEN],
		*astart,
		*s3,
		*begin = NULL,
		*end = NULL;

	int	token;

	Parsedata	pdata;

	pdata.show = show;
	pdata.currline = 0;
	pdata.currfile = ip->basename;

	cp = cp2 = ip->param_value;
	while ( *cp && (*cp != ','))
		cp++;
	if ( *cp)
		*cp++ = '\0';
	markline = (unsigned) atol( cp2);

	cp2 = cp;
	while ( *cp && (*cp != ','))
		cp++;
	if ( *cp)
		*cp++ = '\0';
	off1 = (unsigned) atol( cp2);
	off2 = (unsigned) atol( cp);

	if ( off1 > off2) {
			senderr( CLIENT_ERR, err_m[38], "");
			wn_exit( 2); /* senderr: CLIENT_ERR */
	}

	svbuf[0] = bigbuf[0] = '\0';
	
	while ( get_parse_line( linebuf, svbuf, MIDLEN, ip->fp)) {
		pdata.currline++;
		i++;

		token = get_parse_token( linebuf, insert_param, &pdata);

		if ( token == EMPTY_TOKEN ) {
			if ( !(ip->status & WN_PROLOGSENT) )
				continue;
			else
				token = TEXT_TOKEN;
		}

		if ( ( token == TEXT_TOKEN) || (token == COMMENT)) {
			if ( !((pdata.show & SHOW_IT) == SHOW_IT) )
				continue;
		}
		else {
			if ( set_show( token, &pdata))
				continue;
			else
				doc_parse( ip, token, &pdata, insert_param);
		}

		if ( (i == markline - 1) || (i == markline - 2)){
			mystrncat( bigbuf, linebuf, MIDLEN);
			continue;
		}
		if ( i == markline) {
			s3 = bigbuf + strlen(bigbuf);
			mystrncpy( s3, linebuf, MIDLEN);
			if ( off2 <= strlen( s3) ) {
				begin = s3 + off1;
				end = s3 + off2;
			}
			else {
				senderr( CLIENT_ERR, err_m[38], "");
				wn_exit( 2); /* senderr: CLIENT_ERR */
			}



			if ( (astart = in_anchor( bigbuf, begin))) {
				*astart = '\0';
				send_text_line( bigbuf);
				Snprintf1( linebuf, SMALLLEN, 
					"<a name=\"%.32s\">&#160;</a>", WN_HTML_MARK);
				send_text_line( linebuf);
					
				*astart = '<';

			}
			out_markline( (astart ? astart : bigbuf),
					begin, end, in_anchor( bigbuf, begin));

			continue;
		}
		send_text_line( linebuf);
	}
	if ( ip->fptype == FRP_PIPE)
		pclose( ip->fp);
	else
		fclose( ip->fp);
}

/*
 * char *in_anchor( buf, point) returns a pointer to the start of the
 * anchor ( <a href=...) containing point.  Returns NULL if point is 
 * not in an anchor.
 */

static char
*in_anchor( buf, point)
char	*buf,
	*point;
{
	register char	*cp;

	char	*start = NULL;
	int	in = FALSE;

	cp = buf;
	while ( cp < point) {
		if ( *cp == '<' ) {
			if ( strncasecmp( cp, "</a>", 4 ) == 0 ) {
				in = FALSE;
				cp += 4;
				continue;
			}
			if ( (strncasecmp( cp, "<a", 2) == 0)
				&& isspace( *(cp + 2)) ) {
				start = cp;
				in = TRUE;
				cp += 3;
				continue;
			}
		}
		cp++;
	}
	return ( in ? start : NULL);
}



/*
 * set_show( token, pdp)  See if token corresponds to 
 * "if", "else", "endif", "start" or "end".  If it does adjust
 * the variable "show" appropriately and return TRUE.  Else return
 * FALSE. 
 * The "if-elif-else-endif" constructs are parsed on the char
 * array stack[].  The lower four bits of a value represent the
 * language token (PS_IF, PS_ELIF, etc) and are obtained by masking
 * with PARSE_MASK.  The upper four bits (mask with STATE_MASK)
 * represent the current state, e.g. SS_SHOW = showing text,
 * SS_HIDDEN = not showing because of enclosing if construct, etc.
 */

int
set_show( token, pdp)
int		token;
Parsedata	*pdp;
{
	static unsigned char	stack[STACKSIZE] = { SS_SHOW };
	unsigned char		parse;

	if ( scnt >= STACKSIZE -1 ) {
		parse_html_err( PARSE_TOO_DEEP, pdp);
		scnt = 0;
	}

	switch ( token) {
	case IF_ERR:
		parse_html_err( IF_ERR, pdp);
		pdp->show |= ERR_MSK;
		pdp->show &= ~SHOW_MSK;
		break;

	case IF_TRUE:
	case IF_FALSE:
		scnt++;
		stack[scnt] = PS_IF;

		switch (STATE_MASK & stack[scnt-1]) {

		case SS_HIDDEN:
		case SS_NOSHOW:
		case SS_SEEN:
			stack[scnt] |= SS_HIDDEN;
			pdp->show &= ~SHOW_MSK;
			break;

		case SS_SHOW:
			if ( token == IF_TRUE) {
				stack[scnt] |= SS_SHOW;
				pdp->show |= SHOW_MSK;
			}
			else {
				stack[scnt] |= SS_NOSHOW;
				pdp->show &= ~SHOW_MSK;
			}
			break;
		}
		break;

	case ELSE:
	case ELIF_TRUE:
	case ELIF_FALSE:
		parse = (PARSE_MASK & stack[scnt]);
		if ( (parse != PS_IF) && (parse != PS_ELIF)) {
			parse_html_err( token, pdp);
			break;
		}
		scnt++;
		stack[scnt] = (token == ELSE ? PS_ELSE : PS_ELIF);

		switch (STATE_MASK & stack[scnt-1]) {

		case SS_HIDDEN:
			stack[scnt] |= SS_HIDDEN;
			break;

		case SS_SHOW:
		case SS_SEEN:
			stack[scnt] |= SS_SEEN;
			break;

		case SS_NOSHOW:
			if ( (token == ELIF_TRUE ) || (token == ELSE ))
				stack[scnt] |= SS_SHOW;
			else
				stack[scnt] |= SS_NOSHOW;
		}

		if ( (stack[scnt] & STATE_MASK) == SS_SHOW )
			pdp->show |= SHOW_MSK;
		else
			pdp->show &= ~SHOW_MSK;
		break;

	case ENDIF:
		if ( (stack[scnt] & PARSE_MASK) == PS_ELSE )
			scnt--;

		while ( (stack[scnt] & PARSE_MASK) == PS_ELIF ) 
			scnt--;

		if ( (stack[scnt] & PARSE_MASK) == PS_IF ) {
			scnt--;
			if ( (scnt < 0) ||
					(stack[scnt] & STATE_MASK) == SS_SHOW )
				pdp->show |= SHOW_MSK;
			else
				pdp->show &= ~SHOW_MSK;

			break;
		}
		else
			parse_html_err( token, pdp);

		break;


	case START:
		if ( !(pdp->show & SECT_MSK))
			break;
		pdp->show |= IN_SECT_MSK;
		break;

	case END:
		if ( !(pdp->show & SECT_MSK))
			break;
		pdp->show &= ~IN_SECT_MSK;
		break;

	default:
		return (FALSE);
	}


	return (TRUE);
}

void
parse_html_err( token, pdp)
int	token;
Parsedata	*pdp;
{
	char	buf[SMALLLEN];

	if ( pdp->currfile == NULL)
		pdp->currfile = "unknown";
	Snprintf2( buf, SMALLLEN, "file=%.100s, line=%d", pdp->currfile, pdp->currline);

	switch ( token) {
		case IF_ERR:
			logerr( parserr_m[13], buf);
			break;
		case ELSE:
		case ELIF_TRUE:
		case ELIF_FALSE:
			logerr( parserr_m[1], buf);
			break;
		case ENDIF:
			logerr( parserr_m[2], buf);
			break;

		case START:
			logerr( parserr_m[3], buf);
			break;
		case END:
			logerr( parserr_m[4], buf);
			break;
		case PARSE_TOO_DEEP:
			logerr( parserr_m[12], buf);
			break;
		case TEXT_TOKEN:
			logerr( parserr_m[5], buf);
			break;
	}
}

int
get_parse_token( s, param_ptr, pdp)
char		*s,
		*param_ptr;
Parsedata	*pdp;
{
	char		*if_exprp,
			buf[SMALLLEN];
	int		sgmlprocess,
			oldprocess;

	register char	*cp;

	cp = s;

	while ( isspace( *cp))
		cp++;

	if ( !*cp)
		return EMPTY_TOKEN;

	sgmlprocess = (strncasecmp( cp, "<?wn", 4) == 0);
	oldprocess = (strncmp( cp, "<!--", 4) == 0 );

	if ( !( (this_rp->filetype & WN_ISHTML) 
				&& (sgmlprocess || oldprocess) )) {
		if ( (pdp->show & SHOW_IT) == SHOW_IT) {
			if ( !(this_rp->status & WN_PROLOGSENT) )
				http_prolog();
		}
		return (TEXT_TOKEN);
	}

	cp += 4;
	while ( *cp && isspace( *cp))
		cp++;

	if ( oldprocess) {
		if ( *cp != '#' ) {
			if ( (pdp->show & SHOW_IT) == SHOW_IT) {
				if ( !(this_rp->status & WN_PROLOGSENT) )
					http_prolog();
			}
			return (COMMENT);
		}
	}
	if ( *cp == '#' )
		cp++;	/* skip the '#' */

	if ( strncasecmp( cp, "wn_", 3) == 0 )
		cp += 3;

	if ( strncasecmp( cp, "else", 4) == 0 ) {
		return (ELSE);
	}

	/* Careful here (endif vs end) */
	if ( strncasecmp( cp, "endif", 5) == 0 ) {
		return (ENDIF);
	}
	if ( strncasecmp( cp, "end", 3) == 0 ) {
		return (END);
	}

	if ( strncasecmp( cp, "field", 5) == 0 ) {
		cp += 5;

		while ( isspace( *cp) || (*cp == '#'))
			cp++;
		mystrncpy( param_ptr, cp, SMALLLEN);
		cp = param_ptr;
		while ( isdigit( *cp))
			cp++;
		*cp = '\0';
		return (FIELD);
	}

	if ( strncasecmp( cp, "environ", 7) == 0 ) {
		cp += 7;

		while ( isspace( *cp) || (*cp == '=') || (*cp == '"'))
			cp++;
		mystrncpy( param_ptr, cp, SMALLLEN);
		cp = param_ptr;
		while ( *cp && !isspace( *cp) && (*cp != '"'))
			cp++;
		*cp = '\0';
		return (ENVIRON);
	}

	if ( strncasecmp( cp, "if ", 3) == 0 ) {
		if_exprp = cp + 3;
		return (do_ifexpr( &if_exprp, pdp));

	}

	if ( strncasecmp( cp, "elif ", 5) == 0 ) {
		int	val;

		if_exprp = cp + 5;
		val = do_ifexpr( &if_exprp, pdp);
		switch (val) {
		case IF_TRUE:
			return	ELIF_TRUE;
		case IF_FALSE:
			return	ELIF_FALSE;
		default:
			return val;
		}
	}

	if ( strncasecmp( cp, "include", 7) == 0 ) {
		if (this_rp->attrib2 & (WN_WRAPPED + WN_INCLUDE + WN_ISSEARCH))
			return (INCLUDE);

		cp += 7;

		while ( isspace( *cp) || (*cp == '=') || (*cp == '"'))
			cp++;
		mystrncpy( param_ptr, cp, SMALLLEN);
		cp = param_ptr;
		while ( *cp && !isspace( *cp) && (*cp != '"'))
			cp++;
		*cp = '\0';
		return (LIST_INCLUDE);
	}
	
	if ( strncasecmp( cp, "last_mod_date", 13) == 0 ) {
		return (LAST_MOD_DATE);
	}

	if ( strncasecmp( cp, "query", 5) == 0 ) {
		return (QUERY);
	}

	if ( strncasecmp( cp, "redirect", 8) == 0 ) {
		cp += 8;
		if ( (pdp->show & SHOW_IT) != SHOW_IT)
			return (REDIRECT);

		if ( (cp = strchr( cp, '"')) == NULL) {
			logerr( parserr_m[11], s);
			return (COMMENT);
		}
		mystrncpy( outheadp->location, ++cp, MIDLEN);
		if ( (cp = strchr( outheadp->location, '"')) == NULL) {
			logerr( parserr_m[11], s);
			return (COMMENT);
		}
		*cp = '\0';
		return (REDIRECT);
	}

	if ( strncasecmp( cp, "section", 7) == 0 ) {
		if (this_rp->attrib2 & (WN_WRAPPED + WN_INCLUDE + WN_ISSEARCH))
			return (SECTION);

		cp += 7;
		while ( isspace( *cp) || (*cp == '=') || (*cp == '"'))
			cp++;
		mystrncpy( param_ptr, cp, SMALLLEN);
		cp = param_ptr;
		while ( *cp && !isspace( *cp) && (*cp != '"'))
			cp++;
		*cp = '\0';
		return (LIST_SECTION);
	}

	if ( strncasecmp( cp, "search_on", 9) == 0 ) {
		return (SEARCH_ON);
	}

	if ( strncasecmp( cp, "search_off", 10) == 0 ) {
		return (SEARCH_OFF);
	}

	if ( strncasecmp( cp, "start", 5) == 0 ) {
		return (START);
	}

	if ( strncasecmp( cp, "title", 5) == 0 ) {
		return (TITLE);
	}

	if ( strncasecmp( cp, "keywords", 8) == 0 ) {
		return (KEYWORDS);
	}

	mystrncpy( buf, s, SMALLLEN);
	chop( buf);
	logerr( parserr_m[5], buf);
	return (TEXT_TOKEN);
}

void
reset_parse_err( file, line, pdp)
char		*file;
int		line;
Parsedata	*pdp;

{
	pdp->currfile = file;
	pdp->currline = line;
}



/*
 * do_swrap( ip)
 * Handle search wrapper start and end
 */

void
do_swrap( ip)
Request	*ip;

{
	char	linebuf[BIGLEN],
		svbuf[BIGLEN],
		insert_param[SMALLLEN],
		*wrapfile = NULL;
	int	token;

	Parsedata	*pdp;
	static int	sw_status = SWSTAT_NO_INCL;

	pdp = &swpdata;

	if (sw_status == SWSTAT_ERROR)
		return;

	ip->filetype |= WN_ISHTML;
	if ( swrapfp_st.fp == NULL) {  /* It's the first time so initialize */
		pdp->currline = 0;
		pdp->show = SHOW_IT;
		sw_status = SWSTAT_NO_INCL;
		scnt = 0;
		wrapfile = ( (iswndir( ip)) ? dir_p->swrapper :	ip->swrapper);
		pdp->currfile = wrapfile;

		if ( openfp( wrapfile, ip, &swrapfp_st) == NULL ) {
			senderr( SERV_ERR, err_m[46], wrapfile);
			return;
		}
	}

	svbuf[0] = '\0';
	while ( get_parse_line( linebuf, svbuf, BIGLEN, swrapfp_st.fp)) {
		pdp->currline++;
		token = get_parse_token( linebuf, insert_param, pdp);

		if ( token == EMPTY_TOKEN ) {
			if ( !(ip->status & WN_PROLOGSENT) )
				continue;
			else
				token = TEXT_TOKEN;
		}

		if ( token == INCLUDE) {
			if (sw_status == SWSTAT_NO_INCL ) {
				sw_status = SWSTAT_INCL;
				return;
			}
			else {
				logerr( err_m[84], wrapfile);
			}
		}

		if ( ( token == TEXT_TOKEN) || (token == COMMENT)) {
			if ( (pdp->show & SHOW_IT) == SHOW_IT)
				send_text_line( linebuf);
			continue;
		}
		else {
			if ( set_show( token, pdp))
				continue;
			else
				doc_parse( ip, token, pdp, insert_param);
		}
	}
	if ( swrapfp_st.type == FRP_PIPE)
		pclose( swrapfp_st.fp);
	else
		fclose( swrapfp_st.fp);

	if (sw_status == SWSTAT_NO_INCL) {
		sw_status = SWSTAT_ERROR;
		logerr( err_m[109], wrapfile);
	}

	/* re-initialize for persistent connections */
	sw_status = SWSTAT_NO_INCL;
	swrapfp_st.fp = NULL;
	swrapfp_st.type = FRP_FILE;
}


/*  
 * If path  contains ":/" then assume that it is the full URL
 * to which we are redirecting.  Otherwise, if it starts with
 * '/' consider it relative to wn root, otherwise consider it relative
 * to current url.  If path is "<null>" send 204.  If path ends 
 * with '?' then append ip->query to it so that url query data will pass
 * to the new url.  
 */

void
dolocation( path, ip, status)
char	*path;
Request	*ip;
int	status;
{
	char	*cp,
		*lhost,
		*stat_msg,
		loc[MIDLEN],
		buf[MIDLEN];

	int	full_url = FALSE;

	if ( strncasecmp( path, "<null>", 6) == 0) {
		send204( ip);
		return;
	}

	lhost = ( *(inheadp->host_head) ? (inheadp->host_head) : hostname );

	mystrncpy( buf, path, MIDLEN);

	if ( (cp = strchr( buf, ':')) != NULL) {
		/* URL rediretion: it has "http://" or equivalent  */
		full_url = TRUE;
	}

	if ( *(ip->query) 
		&& ((cp = strrchr( buf, '?')) != NULL) && (*(cp+1) == '\0'))
		mystrncat( buf, ip->query, MIDLEN);
	/* ends with '?' so add the ip->query to it */

	switch ( status) {
	case 301:
		stat_msg = "301 Moved Permanently";
		break;
	case 303:
		stat_msg = "303 See Other";
		break;
	case 302:
	default:
		stat_msg = "302 Found";
	}

	if ( full_url ) {
		sendredirect( ip, stat_msg, buf);
		return;
	}

	if ( (port == STANDARD_PORT) || ( strchr( lhost, ':') != NULL) )
		Snprintf2( loc, SMALLLEN, "%.32s://%.200s", this_conp->scheme, lhost);
	else
		Snprintf3( loc, SMALLLEN, "%.32s://%.200s:%d", this_conp->scheme, lhost, port);

	if ( *buf == '/') {
		mystrncat( loc, buf, MIDLEN);
		sendredirect( ip, stat_msg, loc);
		return;
	}

	mystrncat( loc, inheadp->url_path, MIDLEN);
	if ( (cp = strrchr( loc, '/')) != NULL)
		*++cp = '\0';
	mystrncat( loc, buf, MIDLEN );
	sendredirect( ip, stat_msg, loc);
	return;

}


static void
out_markline( line, begin, end, inanch)
char	*line,
	*begin,
	*end,
	*inanch;

{
	register char	*cp;

	char	buf[BIGLEN];

	cp = buf;

	while ( (line < begin) && (cp < &buf[BIGLEN - SMALLLEN]) )
		*cp++ = *line++;
	if (! inanch)
		Snprintf1( cp, SMALLLEN, "<b><a name=\"%.32s\">", WN_HTML_MARK);
	else
		mystrncat( cp, "<b>", BIGLEN );

	while ( *cp)
		cp++;

	while ( (line < end) && (cp < &buf[BIGLEN - SMALLLEN]))
		*cp++ = *line++;

	if (! inanch) {
		mystrncpy( cp, "</a></b>", 10);
		cp +=8;
	}
	else {
		mystrncpy( cp, "</b>", 10);
		cp +=4;
	}

	while ( *line && (cp < &buf[BIGLEN - 1]))
		*cp++ = *line++;
	*cp = '\0';	
	send_text_line( buf);
}

char *
get_parse_line( linebuf, savebuf, size, fp)
char	*linebuf,
	*savebuf;
int	size;
FILE	*fp;
{
	char		save;
	int		isstart = FALSE,
			len;

	register char	*cp;

	if ( !*savebuf) {
		if ( ! fgets( savebuf, size, fp))
			return NULL;
	}
	cp = savebuf;
	while ( *cp) {
		if ( (cp = strchr( cp, '<')) == NULL) {
			mystrncpy( linebuf, savebuf, size);
			*savebuf = '\0';
			return linebuf;
		}
		if (strncmp( cp, "<!--", 4) == 0 ) {
			char	*cp2;

			cp2 = cp + 4;
			while ( *cp2 && isspace( *cp2))
				cp2++;
			if ( *cp2 == '#')
				isstart = TRUE;
		}
				
		
		if ( isstart || (strncasecmp( cp, "<?wn", 4) == 0) )
			break;
		else
			cp++;
	}

	/* found start of token in savebuf; cp points to it */

	if ( cp != savebuf ) {  /* token not at start of savebuf */
		*cp = '\0';
		mystrncpy( linebuf, savebuf, size);
		*cp = '<';
		mystrncpy( savebuf, cp, size);
		return linebuf;
	}

	else {     /* token starts at start of savebuf */
		cp = savebuf;
		while ( *cp ) {
			if ( (cp = strchr( cp, '>')) != NULL) {
				if ( *(cp - 1) == '\\') {
					mystrncpy( cp - 1, cp, size);
					continue;
				}
				cp++;
				save = *cp;
				*cp = '\0';
				mystrncpy( linebuf, savebuf, size);
				*cp = save;
				mystrncpy( savebuf, cp, size);
				return linebuf;
			}
			else {
				len = strlen( savebuf);
				if ( len > size - 5 ) {
					logerr( parserr_m[14], savebuf);
					mystrncpy( linebuf, savebuf, size);
					*savebuf = '\0';
					return linebuf;
				}			
				if ( !fgets( savebuf + len, size - len, fp)) {
					logerr( parserr_m[15], savebuf);
					mystrncpy( linebuf, savebuf, size);
					*savebuf = '\0';
					return linebuf;
				}
				cp = savebuf;
			}
		}
		return NULL;  /* not reached ? */
	}
}
