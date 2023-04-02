/*

    Wn: A Server for the HTTP
    File: wn/evalif.c
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


#include <string.h>
#include "wn.h"
#include "access.h"
#include "parse.h"
#include "reg.h"
#include "regi.h"

static int	fieldnum = 0,
		eval_ifterm(),
		if_op(),
		gettoken(),
		chk_accessfile( ),
		chk_file_match(),
		chk_match();

int
do_ifexpr(  exprp,  pdp)
char		**exprp;
Parsedata	*pdp;
{

	char	token[SMALLLEN];
	int	value,
		val2,
		notflg,
		ttype;


	value = IF_ERR;

	ttype = gettoken( exprp, token, pdp, &notflg);

	if ( ttype == IFCLAUSE_TERM) {
		value = eval_ifterm ( token, exprp, pdp);
		if ( notflg) {
			if ( value == IF_TRUE)
				value = IF_FALSE;
			else if ( value == IF_FALSE)
				value = IF_TRUE;
		}
		ttype = gettoken( exprp, token, pdp, &notflg);
		if ( notflg)
			return IF_ERR;
	}

	switch ( ttype) {
	case IFCLAUSE_ERR:
		return IF_ERR;

	case IFCLAUSE_TERM:
	case IFCLAUSE_END:
		return value;

	case IFCLAUSE_AND:
		val2 = do_ifexpr( exprp, pdp);
		return (if_op( value, val2, IFCLAUSE_AND));

	case IFCLAUSE_OR:
		val2 = do_ifexpr( exprp, pdp);
		return (if_op( value, val2, IFCLAUSE_OR));
		
	}
	return 	IF_ERR;
}

/*
 * static int if_op( val1, val2, op)
 * op must be IFCLAUSE_AND or IFCLAUSE_OR.  val1 and val2 must
 * be IF_TRUE, IF_FALSE, or IF_ERR.
 */

static int
if_op( val1, val2, op)
int	val1,
	val2,
	op;
{

	switch (val1) {
	case IF_TRUE:
		val1 = TRUE;
		break;
	case IF_FALSE:
		val1 = FALSE;
		break;
	default:
		return IF_ERR;
	}

	switch (val2) {
	case IF_TRUE:
		val2 = TRUE;
		break;
	case IF_FALSE:
		val2 = FALSE;
		break;
	default:
		return IF_ERR;
	}

	switch ( op) {
	case IFCLAUSE_AND:
		return ( (val1 & val2) ? IF_TRUE : IF_FALSE);
	case IFCLAUSE_OR:
		return ( (val1 | val2) ? IF_TRUE : IF_FALSE);
	}
	return IF_ERR;
}
		
static int
gettoken( exprp, tokstart, pdp, flg)
char	**exprp,
	*tokstart;
Parsedata	*pdp;
int	*flg;
{
	char	*tok,
		*cp;
	int	val,
		type;

	tok = tokstart;
	*flg = FALSE;
	cp = *exprp;

	while ( isspace( *cp))
		cp++;

	if ( strncmp( cp , "-->", 3) == 0 ) {	/* <!-- something --> */
		mymemcpy( tokstart, cp, 3);
		*(tokstart + 3) = '\0';
		*exprp = cp + 3;
		return IFCLAUSE_END;
	}

	if ( *cp == '>' ) {	/* <?WN something > */
		*tokstart = *cp;
		*(tokstart + 1) = '\0';
		*exprp = ++cp;
		return IFCLAUSE_END;
	}

	if ( strncmp( cp , "&&", 2) == 0 ) {
		mymemcpy( tokstart, cp, 2);
		*(tokstart + 2) = '\0';
		*exprp = cp + 2;
		return IFCLAUSE_AND;
	}

	if ( strncmp( cp , "||", 2) == 0 ) {
		mymemcpy( tokstart, cp, 2);
		*(tokstart + 2) = '\0';
		*exprp = cp + 2;
		return IFCLAUSE_OR;
	}

	type = IFCLAUSE_TERM;

	if ( *cp == '!' ) {
		*exprp = ++cp;
		while ( isspace( *cp))
			cp++;
		*flg = TRUE;
	}

	if ( *cp == '(' ) {
		*exprp = ++cp;
		val = do_ifexpr( exprp, pdp);

		switch ( val) {
		case IF_TRUE:
			strcpy( tokstart, "true");
			break;
		case IF_FALSE:
			strcpy( tokstart, "false");
			break;
		case IF_ERR:
			return IFCLAUSE_ERR;
		}

		cp = *exprp;
		while ( isspace( *cp))
			cp++;
		if ( *cp++ == ')' ) {
			*exprp = cp;
			return IFCLAUSE_TERM;
		}
		else
			return IFCLAUSE_ERR;
	}

	while ( *cp && ( tok - tokstart < SMALLLEN) ) {
		int	end = FALSE;
		switch ( *cp) {
		case '&':
			if ( *(cp+1) == '&') {
				*exprp = cp;
				end = TRUE;
			}
			else
				*tok++ = *cp++;
			break;
		case '|':
			if ( *(cp+1) == '|') {
				*exprp = cp;
				end = TRUE;
			}
			else
				*tok++ = *cp++;
			break;

		case '-':
			if ( ( *(cp+1) == '-') && (*(cp+2) == '>') ) {
				*exprp = cp;
				end = TRUE;
			}
			else
				*tok++ = *cp++;
			break;

		case ')':
		case '>':
			*exprp = cp;
			end = TRUE;
			break;
		default:
			*tok++ = *cp++;
			break;
		}

		if ( end == TRUE )
			break;
	}

	*tok-- = '\0';
	while (  (tok >= tokstart) && isspace( *tok) )
		tok--; /* eliminate trailing whitespace */
	*++tok = '\0';

	if ( !*cp)
		return IFCLAUSE_ERR;
	return (type);
}




/*
 * static int eval_ifterm( token, exprp, pdp)
 *  returns IF_TRUE, IF_FALSE, or IF_ERR 
 */

static int
eval_ifterm( token, exprp, pdp)
char   *token,
       **exprp;
Parsedata *pdp;
{
	if ( strncasecmp( token, "true", 4) == 0 )
		return (IF_TRUE);
	if ( strncasecmp( token, "false", 6) == 0 )
		return (IF_FALSE);
	if ( strncasecmp( token, "accessfile", 10) == 0 )
		return (chk_accessfile( this_rp, token));

	if ( strncasecmp( token, "cookie", 6) == 0 )
		return (chk_match( token + 6, MATCH_COOKIE, pdp));

	if ( strncasecmp( token, "ua", 2) == 0 )
		return (chk_match( token + 2, MATCH_UA, pdp));

	if ( strncasecmp( token, "refer", 5) == 0 ) {
		while ( isalpha( *token)) /* get referer, and referrer */
			token++;
		return (chk_match( token, MATCH_REFERRER, pdp));
	}

	if ( strncasecmp( token, "host_header", 11) == 0 )
		return (chk_match( token + 11, MATCH_HOST_HEAD, pdp));

	if ( strncasecmp( token, "query", 5) == 0 )
		return (chk_match( token + 5, MATCH_QUERY, pdp));

	if ( strncasecmp( token, "param_field", 11) == 0 )
		return (chk_match( token + 11, MATCH_PARAM_FIELD, pdp));

	if ( strncasecmp( token, "param_value", 11) == 0 )
		return (chk_match( token + 11, MATCH_PARAM_VALUE, pdp));

	if ( strncasecmp( token, "request", 7) == 0 )
		return (chk_match( token + 7, MATCH_REQUEST, pdp));

	if ( strncasecmp( token, "hostname", 8) == 0 )
		return (chk_match( token + 8, MATCH_HOST, pdp));

	if ( strncasecmp( token, "ip", 2) == 0 )
		return (chk_match( token + 2, MATCH_IP, pdp));
	
	if ( strncasecmp( token, "accept_language", 15) == 0 )
		return (chk_match( token + 15, MATCH_LANGUAGE, pdp));

	if ( strncasecmp( token, "language", 8) == 0 )
		return (chk_match( token + 8, MATCH_LANGUAGE, pdp));

	if ( strncasecmp( token, "accept_charset", 14) == 0 )
		return (chk_match( token + 14, MATCH_CHARSET, pdp));

	if ( strncasecmp( token, "accept_encoding", 15) == 0 )
		return (chk_match( token + 15, MATCH_A_ENCODING, pdp));

	if ( strncasecmp( token, "te_header", 9) == 0 )
		return (chk_match( token + 9, MATCH_TE, pdp));

	if ( strncasecmp( token, "accept", 6) == 0 )
		return (chk_match( token + 6, MATCH_ACCEPT, pdp));

	if ( strncasecmp( token, "environ", 7) == 0 )
		return (chk_match( token + 7, MATCH_ENVIRON, pdp));

	if ( strncasecmp( token, "remote_user", 11) == 0 )
		return (chk_match( token + 11, MATCH_REM_USER, pdp));

	if ( strncasecmp( token, "before", 6) == 0 )
		return ( date_cmp( this_rp, token + 6, FALSE) ? 
				IF_FALSE : IF_TRUE);

	if ( strncasecmp( token, "after", 5) == 0 )
		return ( date_cmp( this_rp, token + 5, FALSE) ? 
				IF_TRUE : IF_FALSE);

	if ( strncasecmp( token, "field", 5) == 0 )  {
		/* Get the field number */
                token += 5;
                while ( isspace( *token) || (*token == '#'))
                        token++;

		fieldnum = 0;
		while ( isdigit( *token))  {
			fieldnum = fieldnum * 10 + (*token - '0');
			token++;
		}

		return (chk_match( token, MATCH_FIELD, pdp));
	}

	parse_html_err( TEXT_TOKEN, pdp);
	return (TEXT_TOKEN);
}



static int
chk_accessfile( ip, s)
Request	*ip;
char	*s;
{
	register char	*cp;
	int val;

	char	buf[SMALLLEN];

	if ( (cp = strchr( s, '"')) == NULL ) {
		logerr( parserr_m[6], s);
		return IF_ERR;
	}
	mystrncpy( buf, ++cp, SMALLLEN);	

	if ( (cp = strchr( buf, '"')) == NULL ) {
		logerr( parserr_m[6], s);
		return IF_ERR;
	}
	*cp = '\0';

	val = chkaccess( ip->cachepath, buf);

	if ( (val == ACCESS_GRANTED) || (val == ACCESS_PRIVILEGED))
		return IF_TRUE;
	else if ( val == ACCESS_DENIED )
		return IF_FALSE;
	else
		return IF_ERR;

}



static int
chk_match( s, type, pdp)
char		*s;
int		type;
Parsedata	*pdp;
{
	struct regprog	*rp;
	register char	*cp;

	char	*item,
		buf[SMALLLEN],
		ebuf[MIDLEN/2];
	int	val,
		notflg = FALSE;

	item = NULL;
	cp = s;

	while ( *cp && isspace( *cp))
		cp++;

	if ( type == MATCH_ENVIRON ) {
		char  *cp2, *cp3;

		cp2 = cp;

		while ( *cp && !isspace( *cp))
			cp++;

		if ( *cp )
			*cp++ = '\0';

		if ( (cp3 = getenv( cp2)) == NULL) {
			logerr( parserr_m[16], cp2);
			return IF_ERR;
		}

		mystrncpy( ebuf, cp3, MIDLEN/2 );

		while ( *cp && isspace( *cp))
			cp++;
		
	}

	if ( strncasecmp( cp, "file", 4) == 0) {
		item = ebuf;
		return( chk_file_match( cp + 4, item, type, pdp));
	}

	if ( (*cp == '=') && (*(cp+1) == '~'))
		cp += 2;
	else if ( (*cp == '!') && (*(cp+1) == '~')) {
		cp += 2;
		notflg = TRUE;
	}
	else if ( *cp != '~') {
		logerr( parserr_m[5], s);
		return IF_ERR;
	}
	else 
		cp++;

	if ( (cp = strchr( cp, '"')) == NULL ) {
		logerr( parserr_m[7], s);
		return IF_ERR;
	}
	mystrncpy( buf, ++cp, SMALLLEN);	

	if ( (cp = strchr( buf, '"')) == NULL ) {
		logerr( parserr_m[7], s);
		return IF_ERR;
	}
	*cp = '\0';

	if ( (!*buf) || ((rp = regcomp( buf)) == NULL )) {
		logerr( parserr_m[7], s);
		return IF_ERR;
	}

	switch ( type) {
	case MATCH_ACCEPT:
		val = regfind( rp, inheadp->accept);
		break;
	case MATCH_COOKIE:
		val = regfind( rp, inheadp->cookie);
		break;
	case MATCH_UA:
		val = regfind( rp, inheadp->ua);
		break;
	case MATCH_REFERRER:
		val = regfind( rp, inheadp->referrer);
		break;
	case MATCH_HOST_HEAD:
		val = regfind( rp, inheadp->host_head);
		break;
	case MATCH_REM_USER:
		val = regfind( rp, this_rp->authuser);
		break;
	case MATCH_REQUEST:
		val = regfind( rp, this_rp->request);
		break;
	case MATCH_IP:
		val = regfind( rp, this_conp->remaddr);
		break;
	case MATCH_HOST:
		get_remote_info();
		val = regfind( rp, this_conp->remotehost);
		break;
	case MATCH_QUERY:
		val = regfind( rp, this_rp->query);
		break;
	case MATCH_PARAM_FIELD:
		val = regfind( rp, this_rp->param_field);
		break;
	case MATCH_PARAM_VALUE:
		val = regfind( rp, this_rp->param_value);
		break;
	case MATCH_FIELD:
		val = regfind( rp, this_rp->field[fieldnum]);
		break;
	case MATCH_LANGUAGE:
		val = regfind( rp, inheadp->lang);
		break;		
	case MATCH_CHARSET:
		val = regfind( rp, inheadp->charset);
		break;		
	case MATCH_A_ENCODING:
		val = regfind( rp, inheadp->a_encoding);
		break;		
	case MATCH_TE:
		val = regfind( rp, inheadp->te);
		break;		
	case MATCH_ENVIRON:
		val = regfind( rp, ebuf);
		break;		
	default:
		parse_html_err( TEXT_TOKEN, pdp);
		return (IF_FALSE);
	}
	if ( notflg )
		return ( val ? IF_FALSE : IF_TRUE);
	else
		return ( val ? IF_TRUE : IF_FALSE);
}

/*
 * static int
 * chk_file_match( s, item, type, pdp)
 *
 * s points to after "file" in #if line.
 * item is set only when type=MATCH_ENVIRON, otherwise item == NULL.
 */

static int
chk_file_match( s, item, type, pdp)
char		*s,
		*item;
int		type;
Parsedata 	*pdp;
{
	FILE	*fp;
	int	notflg,
		val;

	struct regprog	*rp;

	char	*cp,
		buf[MIDLEN],
		file[MIDLEN],
		linebuf[SMALLLEN];


	switch ( type) {
	case MATCH_ACCEPT:
		item = inheadp->accept;
		break;
	case MATCH_COOKIE:
		item = inheadp->cookie;
		break;
	case MATCH_UA:
		item = inheadp->ua;
		break;
	case MATCH_REFERRER:
		item = inheadp->referrer;
		break;
	case MATCH_IP:
		item = this_conp->remaddr;
		break;
	case MATCH_QUERY:
		item = this_rp->query;
		break;
	case MATCH_REQUEST:
		item = this_rp->request;
		break;
	case MATCH_PARAM_FIELD:
		item = this_rp->param_field;
		break;
	case MATCH_PARAM_VALUE:
		item = this_rp->param_value;
		break;
	case MATCH_HOST:
		get_remote_info();
		item = this_conp->remotehost;
		break;
	case MATCH_FIELD:
		item = this_rp->field[fieldnum];
		break;
	case MATCH_LANGUAGE:
		item = inheadp->lang;
		break;
	case MATCH_CHARSET:
		item = inheadp->charset;
		break;		
	case MATCH_A_ENCODING:
		item = inheadp->a_encoding;
		break;		
	case MATCH_REM_USER:
		item = this_rp->authuser;
		break;
	case MATCH_ENVIRON:
		/* item already set */
		break;
	default:
		parse_html_err( TEXT_TOKEN, pdp);
		return (IF_ERR);
	}


	if ( (cp = strchr( s, '"')) == NULL ) {
		logerr( parserr_m[6], s);
		return IF_ERR;
	}

	if ( !item || !*item ) {
		return IF_FALSE;
		/* empty item matches nothing */
	}

	mystrncpy( file, ++cp, MIDLEN);	

	if ( (cp = strchr( file, '"')) == NULL ) {
		logerr( parserr_m[6], s);
		return IF_ERR;
	}
	*cp = '\0';

	if ( getfpath2( buf, file, this_rp->cachepath) == FALSE) {
		logerr( parserr_m[6], s);
		return IF_ERR;
	}
	if ( serv_perm & WN_COMP_UID )
		check_perm( this_rp, buf);

	if ((fp = fopen( buf, "r")) == (FILE *)NULL ) {
		logerr( parserr_m[9], buf);
		return IF_ERR;
	}

	while ( fgets( linebuf, SMALLLEN, fp)) {
		if ( !chop( linebuf)) {
			logerr( parserr_m[8], buf);
			return IF_ERR;
		}

		cp = linebuf;
		if ( (notflg = ( *cp == '!')) )
			cp++;

		if ( !*cp || (*cp == '#') )
			continue;

		if ( (rp = regcomp( cp)) == NULL ) {
			logerr( parserr_m[7], s);
			return IF_ERR;
		}

		val = regfind( rp, item);

		if ( val) {
			fclose( fp);
			return ( notflg ? IF_FALSE : IF_TRUE);
		}
	}
	fclose( fp);
	return IF_FALSE;
}


